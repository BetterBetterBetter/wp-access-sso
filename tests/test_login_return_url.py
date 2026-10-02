import subprocess
import unittest
from pathlib import Path


class LoginReturnUrlTests(unittest.TestCase):
    def test_nested_authorization_url_round_trips(self):
        result = subprocess.run(
            ["php", str(Path(__file__).with_name("login-return-url-test.php"))],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
