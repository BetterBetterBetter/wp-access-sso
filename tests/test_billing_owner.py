import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("php"), "php CLI not installed")
class BillingOwnerBehaviorTests(unittest.TestCase):
    def test_billing_owner_classification(self):
        result = subprocess.run(
            ["php", str(ROOT / "tests" / "billing-owner-test.php")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
