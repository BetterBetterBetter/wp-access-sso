import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN_PLUGIN = ROOT / "access-platform-sso.php"
ADMIN_SETTINGS = ROOT / "includes" / "class-admin-settings.php"
SIMPLE_CONFIG = ROOT / "simple-config.php"
DEBUG_ADMIN = ROOT / "debug-sso-admin.php"


def read(path):
    return path.read_text(encoding="utf-8")


class SiteIdSafetyTests(unittest.TestCase):
    def test_site_id_is_never_generated_with_uuid(self):
        combined = "\n".join(
            read(path) for path in (MAIN_PLUGIN, ADMIN_SETTINGS, SIMPLE_CONFIG, DEBUG_ADMIN)
        )

        self.assertNotRegex(
            combined,
            r"site_id[^\n]{0,120}wp_generate_uuid4\(",
            "access_sso_site_id must not be initialized from a locally generated UUID",
        )
        self.assertNotRegex(
            combined,
            r"access_sso_site_id[^\n]{0,120}wp_generate_uuid4\(",
            "the WordPress access_sso_site_id option must not be silently generated",
        )

    def test_activation_preserves_existing_site_id_and_marks_missing_unverified(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("'site_id' => ''", source)
        self.assertIn("'site_id_verified' => '0'", source)
        self.assertIn("if (false === get_option('access_sso_' . $key))", source)
        self.assertIn("add_option('access_sso_' . $key, $value)", source)

    def test_blank_settings_save_preserves_existing_site_id(self):
        source = read(ADMIN_SETTINGS)

        self.assertIn("public function sanitize_site_id($value)", source)
        self.assertIn("if (empty($value) && !empty($existing))", source)
        self.assertIn("return $existing", source)

    def test_missing_site_id_is_reported_not_trusted(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("'missing_site_id'", source)
        self.assertIn("Canonical Access site ID is not configured", source)
        self.assertIn("Access Platform SSO is not connected", source)

    def test_connection_test_fails_for_unrecognized_site_id(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("access_sso_validate_configured_site", source)
        self.assertIn("'site_not_found'", source)
        self.assertIn("Access does not recognize the configured site ID", source)
        self.assertRegex(
            source,
            r"access_sso_test_connection[\s\S]+access_sso_validate_configured_site",
            "manual connection test must verify the configured site ID with Access",
        )

    def test_connection_test_fails_for_host_mismatch(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("'site_host_mismatch'", source)
        self.assertIn("WordPress home URL host", source)
        self.assertIn("Access site URL host", source)
        self.assertIn("$wordpress_host !== $access_host", source)

    def test_settings_page_distinguishes_canonical_and_local_ids(self):
        source = read(ADMIN_SETTINGS)

        self.assertIn("Canonical Access site ID", source)
        self.assertIn("Local plugin-stored ID, not verified as canonical in Access", source)
        self.assertIn("Verified canonical Access site ID", source)

    def test_legacy_simple_config_uses_shared_connection_validation(self):
        source = read(SIMPLE_CONFIG)

        self.assertIn("access_sso_test_connection", source)
        self.assertIn("canonical Access site ID", source)

    def test_site_validation_failures_notify_access_admins_centrally(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("function access_sso_notify_access_admins", source)
        self.assertIn("api/sso/plugin-alerts", source)
        self.assertIn("wordpress_sso_site_id_validation_failed", source)
        self.assertIn("access_sso_access_admin_alert_throttle_seconds", source)
        self.assertRegex(
            source,
            r"function access_sso_store_site_validation_result[\s\S]+access_sso_notify_access_admins",
            "failed site validation should report centrally to Access",
        )
        self.assertRegex(
            source,
            r"function access_sso_test_connection[\s\S]+source' => 'connection_test'",
            "manual connection test failures should identify their alert source",
        )

    def test_admin_notice_reports_unverified_sites_to_access(self):
        source = read(MAIN_PLUGIN)

        self.assertIn("access_sso_maybe_notify_stored_site_validation_issue", source)
        self.assertIn("source' => 'admin_notice'", source)
        self.assertIn("Access admins will be notified centrally", source)


if __name__ == "__main__":
    unittest.main()
