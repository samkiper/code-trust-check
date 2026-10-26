"""Actual local worker plus coverage checks; no GitHub service or customer data."""
import io
import unittest
import zipfile
import urllib.request
import urllib.error
from unittest.mock import patch
from fastapi import HTTPException
import main


class GitHubWorkerTests(unittest.TestCase):
    def test_real_worker_scans_only_changed_file(self):
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:
            z.writestr('repo/changed.py','value = input()\neval(value)')
            z.writestr('repo/unchanged.py','print("not scanned")')
        findings,scanned,skipped=main.scan_github_changed_files_isolated(archive.getvalue(),[{'filename':'changed.py'}])
        self.assertEqual((scanned,skipped),(1,0))
        self.assertTrue(any(path=='changed.py' and f.get('severity',0)>=18 for path,f in findings))

    def test_invalid_utf8_and_line_limit_are_skipped(self):
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:
            z.writestr('repo/bad.py',b'\xff')
            z.writestr('repo/too_long.py','x=1\n'*20001)
        findings,scanned,skipped=main.scan_github_changed_files(archive.getvalue(),[{'filename':'bad.py'},{'filename':'too_long.py'}])
        self.assertEqual((findings,scanned,skipped),([],0,2))
        self.assertIn('Coverage is incomplete',main.build_github_check_output([],scanned,skipped)['summary'])

    def test_timeout_propagates_as_failed_worker(self):
        with patch('audit_runtime.run_process',side_effect=HTTPException(504,'timeout')):
            with self.assertRaises(HTTPException) as e:
                main.scan_github_changed_files_isolated(b'',[])
        self.assertEqual(e.exception.status_code,504)

    def test_bounded_changed_file_list_discloses_possible_omissions(self):
        page=[{'filename':f'src/file-{n}.py','status':'modified'} for n in range(main.PRO_REPO_FILE_LIMIT)]
        with patch.object(main,'github_api_request',return_value=page):
            files=main.list_github_pull_request_files('owner/repo',7,'token')
        self.assertEqual(len(files),main.PRO_REPO_FILE_LIMIT+1)
        self.assertEqual(files[-1]['coverage_gap'],'listing_limit')
        self.assertIn('skipped at least 1',main.build_github_check_output([],1,1)['summary'])

    def test_archive_redirect_cannot_send_credentials_to_other_hosts(self):
        handler=main.GitHubArchiveRedirectHandler()
        request=urllib.request.Request('https://api.github.com/repos/owner/repo/zipball/sha',headers={'Authorization':'Bearer test-token'})
        for url in ['https://attacker.example/archive','http://codeload.github.com/archive','https://codeload.github.com.attacker.example/archive','https://user@codeload.github.com/archive','https://codeload.github.com:444/archive']:
            with self.subTest(url=url), self.assertRaises(urllib.error.HTTPError):
                handler.redirect_request(request,None,302,'Found',{},url)
        redirected=handler.redirect_request(request,None,302,'Found',{},'https://codeload.github.com/owner/repo/legacy.zip/sha')
        self.assertEqual(redirected.full_url,'https://codeload.github.com/owner/repo/legacy.zip/sha')
