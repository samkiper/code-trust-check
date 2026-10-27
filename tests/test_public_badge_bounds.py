import io
import unittest
import zipfile
from unittest.mock import patch
import main


def archive(entries):
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w',zipfile.ZIP_DEFLATED) as z:
        for name, content in entries:
            z.writestr('repo/'+name,content)
    return data.getvalue()

class PublicBadgeBoundsTests(unittest.TestCase):
    def badge(self, entries, dependency_error=None):
        dependencies={'dependency_risk_points':0,'dependency_findings':[], 'dependencies_skipped':[], 'dependency_scan_error':dependency_error}
        main.BADGE_CACHE.clear()
        with patch.object(main,'download_repo_zip',return_value=archive(entries)), patch.object(main,'analyze_dependency_manifests',return_value=dependencies):
            return main.github_repo_badge_svg('example','test').body.decode()

    def test_complete_small_supported_code_can_be_rated(self):
        self.assertIn('/100',self.badge([('app.py','print("ready")\n')]))

    def test_oversized_or_excess_files_are_not_rated(self):
        self.assertIn('not rated',self.badge([('app.py','x='+('1'*main.FREE_REPO_SIZE_LIMIT_BYTES))]))
        self.assertIn('not rated',self.badge([(f'{i}.py','print(1)') for i in range(main.FREE_REPO_FILE_LIMIT+1)]))

    def test_invalid_source_and_dependency_error_are_not_rated(self):
        self.assertIn('not rated',self.badge([('bad.py',b'\xff')]))
        self.assertIn('not rated',self.badge([('bad.py','def broken(:\n')]))
        self.assertIn('not rated',self.badge([('app.py','print(1)')],dependency_error='unavailable'))

    def test_no_source_is_not_rated(self):
        self.assertIn('not rated',self.badge([('readme.md','hello')]))
