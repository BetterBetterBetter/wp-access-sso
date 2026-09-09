import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN_PLUGIN = ROOT / "access-platform-sso.php"
ADMIN_SETTINGS = ROOT / "includes" / "class-admin-settings.php"
DETECTOR_JS = ROOT / "assets" / "js" / "account-manage-detector.js"
LOGIN_CSS = ROOT / "assets" / "css" / "login.css"


def read(path):
    return path.read_text(encoding="utf-8")


class AccountManageButtonTests(unittest.TestCase):
    """
    Access-billed members have no MemberPress subscription to cancel, so the
    plugin adds a manage/cancel button on the MemberPress account page that
    sends them to Access. These checks pin the contract.
    """

    def test_button_is_gated_to_access_billed_members(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("public function is_access_managed_user(", source)
        self.assertIn("get_user_meta($user_id, 'access_platform_id', true) !== ''", source)
        self.assertIn("return is_user_logged_in() && $this->is_access_managed_user();", source)

    def test_button_can_be_disabled_per_site_and_requires_platform_url(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("$this->get_option('manage_billing_disabled', '0') === '1'", source)
        self.assertIn("if (empty($this->get_option('platform_url', '')))", source)

    def test_button_links_to_access_not_memberpress_api(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("$this->get_option('manage_billing_path', '/subscriptions')", source)
        self.assertIn("return $platform_url . $path;", source)
        # Cancellation must stay in Access; never call MemberPress to cancel.
        self.assertNotIn("mepr/v1/subscriptions", source)
        self.assertNotRegex(source, r"cancel_subscription\s*\(")

    def test_detector_script_is_enqueued_for_access_users_only(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("'access-sso-account-manage'", source)
        self.assertIn("assets/js/account-manage-detector.js", source)
        self.assertIn("wp_localize_script('access-sso-account-manage', 'accessSSOAccountManage'", source)
        # No server-rendered nav tab: it broke the MemberPress nav row.
        self.assertNotIn("mepr_account_nav", source)
        self.assertNotIn("render_account_manage_nav", source)

    def test_banner_is_placed_outside_the_memberpress_nav(self):
        js = read(DETECTOR_JS)

        self.assertIn("window.accessSSOAccountManage", js)
        self.assertIn("var NAV_SELECTOR = '#mepr-account-nav", js)
        self.assertIn("nav.insertAdjacentElement('afterend', notice)", js)
        self.assertIn("closest(NAV_SELECTOR)", js)
        self.assertIn("document.querySelector('.access-manage-billing-notice')", js)
        self.assertIn("MutationObserver", js)
        # Never create nav tabs or insert before a nav tab.
        self.assertNotIn("mepr-nav-item access-manage-billing-nav", js)
        self.assertNotIn(".mepr-account-subscriptions", js)

    def test_settings_are_registered(self):
        source = read(ADMIN_SETTINGS)

        for option in (
            "manage_billing_disabled",
            "manage_billing_text",
            "manage_billing_help_text",
            "manage_billing_path",
        ):
            self.assertIn(f"'{option}'", source, f"{option} must be registered as a setting")
            self.assertIn(f"public function {option}_callback()", source)
        self.assertIn("'access_sso_account'", source)

    def test_styles_exist(self):
        css = read(LOGIN_CSS)

        self.assertIn(".access-manage-billing-notice", css)
        self.assertIn(".access-manage-billing-button", css)


if __name__ == "__main__":
    unittest.main()
