import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "access-platform-sso.php").read_text(encoding="utf-8")
JWT = (ROOT / "includes" / "class-jwt-validator.php").read_text(encoding="utf-8")
PROVISIONER = (ROOT / "includes" / "class-user-provisioner.php").read_text(encoding="utf-8")
SESSIONS = (ROOT / "includes" / "class-session-manager.php").read_text(encoding="utf-8")
ADMIN_SETTINGS = (ROOT / "includes" / "class-admin-settings.php").read_text(encoding="utf-8")
ADMIN_JS = (ROOT / "assets" / "js" / "admin.js").read_text(encoding="utf-8")
DETECTOR_JS = (ROOT / "assets" / "js" / "login-form-detector.js").read_text(encoding="utf-8")
FRONTEND_JS = (ROOT / "assets" / "js" / "sso-redirect.js").read_text(encoding="utf-8")
SIMPLE_CONFIG = (ROOT / "simple-config.php").read_text(encoding="utf-8")
DEBUG_ADMIN = (ROOT / "debug-sso-admin.php").read_text(encoding="utf-8")


class SecurityHardeningTests(unittest.TestCase):
    def test_login_is_started_on_uncached_wordpress_endpoint(self):
        self.assertIn("admin_post_nopriv_access_sso_start", MAIN)
        self.assertIn("admin_post_access_sso_start", MAIN)
        self.assertIn("function handle_sso_start", MAIN)
        self.assertIn("'login_url' => $this->get_login_url()", MAIN)
        self.assertIn("config.login_url", DETECTOR_JS)

    def test_injected_login_button_preserves_wordpress_redirect_to(self):
        self.assertIn("pageUrl.searchParams.get('redirect_to')", DETECTOR_JS)
        self.assertIn("form.querySelector('input[name=\"redirect_to\"]')", DETECTOR_JS)
        self.assertIn("getReturnUrl(form)", DETECTOR_JS)

    def test_browser_bound_state_is_created_and_consumed(self):
        self.assertIn("STATE_COOKIE", MAIN)
        self.assertIn("STATE_TRANSIENT_PREFIX", MAIN)
        self.assertIn("create_login_state", MAIN)
        self.assertIn("consume_login_state", MAIN)
        self.assertNotIn("Nonce is best-effort", MAIN)

    def test_callback_tokens_are_single_use_and_time_bounded(self):
        self.assertIn("consume_token_once", JWT)
        self.assertIn("Token issued-at missing", JWT)
        self.assertIn("Token lifetime exceeds limit", JWT)
        self.assertIn("$user_data['verified']['replay'] = true", MAIN)
        self.assertIn("array('response' => 401)", MAIN)

    def test_access_claims_never_grant_wordpress_admin(self):
        self.assertNotIn("set_role('administrator')", PROVISIONER)
        self.assertNotIn("should_promote_to_administrator", PROVISIONER)
        self.assertIn("get_safe_default_role", PROVISIONER)
        self.assertIn("'edit_posts'", PROVISIONER)
        self.assertIn("'manage_woocommerce'", PROVISIONER)

    def test_admin_ajax_uses_request_specific_nonce(self):
        self.assertIn("access_sso_test_connection_nonce", MAIN)
        self.assertIn("access_sso_health_check_nonce", MAIN)
        self.assertNotIn("Fallback: allow logged-in admins", MAIN)
        self.assertIn("test_connection_nonce", ADMIN_JS)
        self.assertIn("health_check_nonce", ADMIN_JS)

    def test_session_tokens_and_network_fingerprints_are_hashed_at_rest(self):
        self.assertIn("hash_session_token", SESSIONS)
        self.assertIn("privacy_hash", SESSIONS)
        self.assertIn("migrate_legacy_storage", SESSIONS)
        self.assertNotIn("'session_token' => $session_token,", SESSIONS)

    def test_sensitive_diagnostics_and_processing_splash_are_removed(self):
        self.assertNotIn("secret_sha256_12", JWT)
        self.assertNotIn("provided_sig", JWT)
        self.assertNotIn("'email' => isset($user_data['email'])", PROVISIONER)
        self.assertNotIn("showProcessingMessage", FRONTEND_JS)
        self.assertNotIn("console.log", FRONTEND_JS)
        self.assertNotIn("console.log", DETECTOR_JS)
        self.assertNotIn("access_sso_track_event", FRONTEND_JS)
        self.assertNotIn("access_sso_track_click", DETECTOR_JS)

    def test_admin_secret_generator_uses_browser_csprng(self):
        self.assertIn("window.crypto.getRandomValues", ADMIN_JS)
        self.assertNotIn("Math.random", ADMIN_JS)
        self.assertIn("window.crypto.getRandomValues", SIMPLE_CONFIG)
        self.assertNotIn("Math.random", SIMPLE_CONFIG)

    def test_admin_pages_do_not_render_or_overwrite_existing_secret(self):
        self.assertIn("value=\"\"", SIMPLE_CONFIG)
        self.assertNotIn("esc_html($jwt_secret)", SIMPLE_CONFIG)
        self.assertIn("if ('' !== $submitted_jwt_secret)", SIMPLE_CONFIG)
        self.assertIn("sanitize_jwt_secret", ADMIN_SETTINGS)
        self.assertIn("value=\"\"", ADMIN_SETTINGS)
        self.assertNotIn("esc_attr($value)", ADMIN_SETTINGS[ADMIN_SETTINGS.index("public function jwt_secret_callback"):ADMIN_SETTINGS.index("public function callback_path_callback")])
        self.assertNotIn("console.log", DEBUG_ADMIN)
        self.assertNotIn("regenerate_options", DEBUG_ADMIN)
        self.assertNotIn("esc_html($value)", DEBUG_ADMIN)

    def test_authentication_routes_are_explicitly_uncacheable(self):
        self.assertIn("mark_auth_request_uncacheable", MAIN)
        self.assertIn("DONOTCACHEPAGE", MAIN)
        self.assertIn("rocket_cache_reject_uri", MAIN)
        self.assertIn("rocket_cache_reject_cookies", MAIN)
        self.assertIn("self::STATE_COOKIE", MAIN)

    def test_blank_success_redirect_falls_back_to_wordpress_home(self):
        compact = " ".join(MAIN.split())
        self.assertIn("if (empty($requested_url)) { return $fallback; }", compact)


if __name__ == "__main__":
    unittest.main()
