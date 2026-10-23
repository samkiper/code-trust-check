import unittest
from main import analyze_code

class RandomnessDataflowTests(unittest.TestCase):
    def test_encoded_predictable_value_reaches_session(self):
        result = analyze_code("Review this code before production", "import random, base64\nvalue = str(base64.b64encode(random.randbytes(32)))\nsession['remember_me'] = value")
        self.assertNotEqual(result['risk'], 'green')
        self.assertTrue(any(f.get('type') == 'weak_randomness' and f.get('line') == 3 for f in result['flags']))

    def test_harmless_and_secure_values_remain_green(self):
        for code in [
            "import random, base64\nprint(base64.b64encode(random.randbytes(32)))",
            "import secrets, base64\nsession['remember_me'] = base64.b64encode(secrets.token_bytes(32))",
            "import random, secrets, base64\nvalue = base64.b64encode(random.randbytes(32))\nvalue = secrets.token_hex(32)\nsession['remember_me'] = value",
        ]:
            with self.subTest(code=code):
                self.assertEqual(analyze_code("Review this code before production", code)['risk'], 'green')
