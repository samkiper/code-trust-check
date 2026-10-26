import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from scanner_process import run_scanner
import main

class ProcessTimeoutTests(unittest.TestCase):
    def test_real_timeout_kills_descendant_before_it_can_write(self):
        with tempfile.TemporaryDirectory() as folder:
            marker=Path(folder)/'orphan.txt'
            child=f"import time; from pathlib import Path; time.sleep(.6); Path({str(marker)!r}).write_text('orphan')"
            parent=f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); print('ready',flush=True); time.sleep(10)"
            started=time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                run_scanner([sys.executable,'-c',parent],timeout=.2)
            self.assertLess(time.monotonic()-started,2)
            time.sleep(.7)
            self.assertFalse(marker.exists())
            self.assertEqual(run_scanner([sys.executable,'-c','print(42)'],timeout=2).stdout.strip(),'42')

    def test_validation_is_exact_expiring_and_disabled_by_default(self):
        import hashlib
        code='print("synthetic timeout validation")'
        with patch.dict(os.environ,{},clear=True):
            self.assertFalse(main.validation_timeout_enabled(code))
            os.environ['SCAN_TIMEOUT_VALIDATION_SHA256']=hashlib.sha256(code.encode()).hexdigest()
            for expiry,expected in [(time.time()+60,True),(time.time()-1,False),(time.time()+1000,False),('bad',False)]:
                os.environ['SCAN_TIMEOUT_VALIDATION_EXPIRES']=str(expiry)
                self.assertEqual(main.validation_timeout_enabled(code),expected)
                self.assertFalse(main.validation_timeout_enabled(code+'\n'))
