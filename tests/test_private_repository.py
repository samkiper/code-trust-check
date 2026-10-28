import base64
import io
import json
import unittest
import urllib.error
import warnings
import zipfile
from unittest.mock import patch
from fastapi import HTTPException
from starlette.requests import Request
import main


class PrivateRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.access={'authenticated':True,'user_id':'user-a','plan':'pro','limits':main.get_plan_limits('pro')}
        self.entry={'github_id':101,'token':'github-user-token'}

    def test_only_owned_live_authorization_can_download(self):
        replies=[{'full_name':'owner/private','default_branch':'main'},{'id':123},{'sha':'a'*40}]
        with patch.object(main.GITHUB_USER_AUTHORIZATIONS,'get',return_value=self.entry), \
                patch.object(main,'github_api_request',side_effect=replies) as github, \
                patch.object(main,'github_app_jwt',return_value='app-jwt'), \
                patch.object(main,'supabase_rest_request',return_value=[{'installation_id':123}]), \
                patch.object(main,'github_installation_still_authorized',return_value=True), \
                patch.object(main,'github_installation_token',return_value='installation-token'), \
                patch.object(main,'download_github_archive',return_value=b'archive') as archive:
            self.assertEqual(main.download_private_repository(self.access,'https://github.com/owner/private'),b'archive')
        self.assertEqual(github.call_args_list[0].args[2],'github-user-token')
        self.assertEqual(github.call_args_list[1].args[2],'app-jwt')
        archive.assert_called_once_with('owner/private','a'*40,'installation-token')

    def test_http_diagnostic_reports_only_stage_and_status(self):
        error=urllib.error.HTTPError('https://private.invalid/secret',404,'sensitive-token',{},None)
        with patch.object(main.GITHUB_USER_AUTHORIZATIONS,'get',return_value=self.entry), \
                patch.object(main,'github_api_request',side_effect=error), \
                patch.object(main,'log_server_issue') as log:
            with self.assertRaises(HTTPException) as caught:
                main.download_private_repository(self.access,'https://github.com/owner/private')
        self.assertEqual(caught.exception.status_code,403)
        self.assertEqual(log.call_args.args,('Private repository HTTP failure stage=user_repository status=404',))

    def test_cross_account_removed_permission_and_free_plan_fail_before_download(self):
        with patch.object(main.GITHUB_USER_AUTHORIZATIONS,'get',return_value=None), patch.object(main,'download_github_archive') as archive:
            with self.assertRaises(HTTPException):main.download_private_repository(self.access,'https://github.com/owner/private')
            archive.assert_not_called()
        with patch.object(main.GITHUB_USER_AUTHORIZATIONS,'get',return_value=self.entry), \
                patch.object(main,'github_api_request',side_effect=[{'full_name':'owner/private','default_branch':'main'},{'id':123}]), \
                patch.object(main,'github_app_jwt',return_value='app-jwt'), \
                patch.object(main,'supabase_rest_request',return_value=[]), patch.object(main,'download_github_archive') as archive:
            with self.assertRaises(HTTPException):main.download_private_repository(self.access,'https://github.com/owner/private')
            archive.assert_not_called()
        with patch.object(main,'github_api_request') as github:
            with self.assertRaises(HTTPException):main.download_private_repository({**self.access,'plan':'free'},'https://github.com/owner/private')
            github.assert_not_called()

    def test_revocation_between_checks_and_download_fails_closed(self):
        replies=[{'full_name':'owner/private','default_branch':'main'},{'id':123},{'sha':'a'*40}]
        with patch.object(main.GITHUB_USER_AUTHORIZATIONS,'get',side_effect=[self.entry,None]), \
                patch.object(main,'github_api_request',side_effect=replies),patch.object(main,'github_app_jwt',return_value='app-jwt'), \
                patch.object(main,'supabase_rest_request',return_value=[{'installation_id':123}]), \
                patch.object(main,'github_installation_still_authorized',return_value=True),patch.object(main,'github_installation_token') as token:
            with self.assertRaises(HTTPException):main.download_private_repository(self.access,'https://github.com/owner/private')
            token.assert_not_called()

    def test_archive_limit_is_explained_without_charging(self):
        replies=[{'full_name':'owner/private','default_branch':'main'},{'id':123},{'sha':'a'*40}]
        with patch.object(main.GITHUB_USER_AUTHORIZATIONS,'get',return_value=self.entry), \
                patch.object(main,'github_api_request',side_effect=replies),patch.object(main,'github_app_jwt',return_value='app-jwt'), \
                patch.object(main,'supabase_rest_request',return_value=[{'installation_id':123}]), \
                patch.object(main,'github_installation_still_authorized',return_value=True), \
                patch.object(main,'github_installation_token',return_value='installation-token'), \
                patch.object(main,'download_github_archive',side_effect=ValueError('Repository archive exceeds the 25 MB safety limit.')):
            with self.assertRaises(HTTPException) as caught:main.download_private_repository(self.access,'https://github.com/owner/private')
        self.assertEqual(caught.exception.status_code,413)
        self.assertIn('No audit allowance was used',caught.exception.detail)

    def test_private_archive_is_scanned_in_real_secret_minimized_worker(self):
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:z.writestr('owner-repo/app.py','x=input()\neval(x)\n')
        payload={'intent':'Review this code','repo_url':'https://github.com/owner/private','private_repo':True,'_private_archive':base64.b64encode(archive.getvalue()).decode()}
        response=main.run_audit_process('repo',payload,self.access)
        result=json.loads(response.body)
        self.assertEqual(response.status_code,200)
        self.assertEqual(result['coverage']['scope'],'private_repository')
        self.assertIsNone(result['readme_badge'])
        self.assertTrue(result['coverage']['files_analyzed']>=1)
        self.assertTrue(any(f.get('severity',0)>=18 for item in result['files'] for f in item['flags']))

    def test_private_worker_cannot_fetch_without_server_supplied_archive(self):
        request=Request({'type':'http','method':'POST','path':'/scan-repo','headers':[]})
        with patch.object(main,'download_repo_zip') as public_download:
            response=main.scan_repo_work(main.RepoScanRequest(intent='Review',repo_url='https://github.com/owner/private',private_repo=True),self.access,request)
        self.assertEqual(response.status_code,400)
        public_download.assert_not_called()

    def test_repository_url_requires_exact_https_root(self):
        for invalid in ['http://github.com/a/b','https://github.com/a/b/tree/main','https://github.com/a/b?x=1','https://github.com/../b','https://github.com/a/%2e%2e','https://evil.example/a/b']:
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):main.parse_github_repo(invalid)
        self.assertEqual(main.parse_github_repo('https://github.com/owner/repo.git'),('owner','repo'))

    def test_failed_private_authorization_refunds_the_reserved_audit(self):
        request=Request({'type':'http','method':'POST','path':'/scan-repo','headers':[],'client':('127.0.0.1',1)})
        req=main.RepoScanRequest(intent='Review',repo_url='https://github.com/owner/private',private_repo=True)
        with patch.object(main,'get_request_access_context',return_value=self.access), \
                patch.object(main,'enrich_access_with_admin_metadata',side_effect=lambda value:value), \
                patch.object(main,'enforce_rate_limit'), \
                patch.object(main,'monthly_usage',return_value={'allowed':True}) as usage, \
                patch.object(main,'download_private_repository',side_effect=HTTPException(403,'not authorized')):
            with self.assertRaises(HTTPException):main.scan_repo(req,request)
        self.assertEqual(usage.call_args_list[0].args[1],'reserve')
        self.assertEqual(usage.call_args_list[1].args[1],'settle')
        self.assertFalse(usage.call_args_list[1].args[4])

    def test_authorized_private_audit_reserves_and_settles_after_real_worker(self):
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:z.writestr('owner-repo/app.py','x=input()\neval(x)\n')
        request=Request({'type':'http','method':'POST','path':'/scan-repo','headers':[],'client':('127.0.0.1',1),'scheme':'https','server':('localhost',443)})
        req=main.RepoScanRequest(intent='Review',repo_url='https://github.com/owner/private',private_repo=True)
        with patch.object(main,'get_request_access_context',return_value=self.access), \
                patch.object(main,'enrich_access_with_admin_metadata',side_effect=lambda value:value), \
                patch.object(main,'enforce_rate_limit'), \
                patch.object(main,'monthly_usage',return_value={'allowed':True}) as usage, \
                patch.object(main,'download_private_repository',return_value=archive.getvalue()):
            response=main.scan_repo(req,request)
        self.assertEqual(response.status_code,200)
        self.assertEqual(usage.call_args_list[0].args[1],'reserve')
        self.assertEqual(usage.call_args_list[1].args[1],'settle')
        self.assertTrue(usage.call_args_list[1].args[4])
        self.assertNotIn('github-user-token',response.body.decode())

    def test_duplicate_private_archive_returns_allowance(self):
        archive=io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',UserWarning)
            with zipfile.ZipFile(archive,'w') as z:
                z.writestr('owner-repo/app.py','eval(input())')
                z.writestr('owner-repo/app.py','x=1')
        request=Request({'type':'http','method':'POST','path':'/scan-repo','headers':[],'client':('127.0.0.1',1),'scheme':'https','server':('localhost',443)})
        req=main.RepoScanRequest(intent='Review',repo_url='https://github.com/owner/private',private_repo=True)
        with patch.object(main,'get_request_access_context',return_value=self.access), \
                patch.object(main,'enrich_access_with_admin_metadata',side_effect=lambda value:value), \
                patch.object(main,'enforce_rate_limit'), \
                patch.object(main,'monthly_usage',return_value={'allowed':True}) as usage, \
                patch.object(main,'download_private_repository',return_value=archive.getvalue()):
            response=main.scan_repo(req,request)
        self.assertEqual(response.status_code,422)
        self.assertFalse(usage.call_args_list[-1].args[4])

    def test_api_token_cannot_be_sent_to_an_untrusted_origin(self):
        for url in ['http://api.github.com/user','https://api.github.com.attacker.example/user','https://user@api.github.com/user','https://api.github.com:444/user']:
            with self.subTest(url=url),self.assertRaises(ValueError):main.github_api_request('GET',url,'synthetic-token')
