import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SSO_REDIRECT = ROOT / "assets" / "js" / "sso-redirect.js"
FORM_DETECTOR = ROOT / "assets" / "js" / "login-form-detector.js"


def read(path):
    return path.read_text(encoding="utf-8")


class BrowserStorageSafetyTests(unittest.TestCase):
    def test_session_storage_calls_are_inside_guarded_helpers(self):
        source = read(SSO_REDIRECT)

        direct_calls = re.findall(r"window\.sessionStorage\.(getItem|setItem|removeItem)\(", source)
        self.assertEqual(5, len(direct_calls))
        self.assertIn("function isSessionStorageAvailable()", source)
        self.assertIn("function safeSessionStorageGetItem(key)", source)
        self.assertIn("function safeSessionStorageSetItem(key, value)", source)
        self.assertIn("function safeSessionStorageRemoveItem(key)", source)
        self.assertNotRegex(source, r"(?<!window\.)sessionStorage\.")

    def test_cookie_check_is_guarded_and_runs_before_sso_initialization(self):
        source = read(SSO_REDIRECT)

        check_position = source.index("browserSupport.cookiesAvailable = areCookiesAvailable()")
        ready_position = source.index("$(document).ready(function()")
        self.assertLess(check_position, ready_position)
        self.assertIn("browserSupport.storageAvailable && browserSupport.cookiesAvailable", source)
        self.assertRegex(
            source,
            r"function areCookiesAvailable\(\) \{\s+try \{[\s\S]+?document\.cookie",
        )

    def test_blocked_browser_gets_guidance_and_reload_action(self):
        source = read(SSO_REDIRECT)

        self.assertIn("Browser privacy settings are preventing sign-in", source)
        self.assertIn("Block all cookies", source)
        self.assertIn("Block third-party cookies", source)
        self.assertIn("You can continue blocking third-party cookies, ads, and trackers.", source)
        self.assertIn("window.location.reload()", source)
        self.assertRegex(
            source,
            r"if \(!browserSupport\.available\) \{\s+blockSSOForUnsupportedBrowser\(\);\s+return;",
        )

    def test_dynamic_form_detector_respects_browser_preflight(self):
        source = read(FORM_DETECTOR)

        self.assertIn("function isBrowserSupported()", source)
        self.assertRegex(
            source,
            r"function detectAndEnhanceForms\(\) \{\s+if \(!isBrowserSupported\(\)\) return 0;",
        )


if __name__ == "__main__":
    unittest.main()
