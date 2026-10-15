import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "access-platform-sso.php").read_text(encoding="utf-8")
MCP = (ROOT / "includes" / "class-readonly-mcp.php").read_text(encoding="utf-8")


class ReadonlyMcpTests(unittest.TestCase):
    def test_plugin_loads_private_mcp_bridge(self):
        self.assertIn("class-readonly-mcp.php", MAIN)
        self.assertIn("AccessSSO_Readonly_MCP::get_instance();", MAIN)
        self.assertIn("Version: 1.4.0", MAIN)

    def test_endpoint_is_signed_site_bound_and_replay_protected(self):
        self.assertIn("register_rest_route(self::ROUTE_NAMESPACE, self::ROUTE", MCP)
        self.assertIn("x-access-site-id", MCP)
        self.assertIn("x-access-mcp-timestamp", MCP)
        self.assertIn("x-access-mcp-nonce", MCP)
        self.assertIn("x-access-mcp-signature", MCP)
        self.assertIn("hash_hmac('sha256'", MCP)
        self.assertIn("hash_equals($expected, $signature)", MCP)
        self.assertIn("get_transient($nonce_key)", MCP)
        self.assertIn("set_transient($nonce_key", MCP)
        self.assertIn("access_sso_site_id_verified", MCP)

    def test_tools_are_bounded_and_read_only(self):
        expected = (
            "access_sso_get_member",
            "access_sso_get_memberships",
            "access_sso_get_transactions",
            "access_sso_list_products",
            "access_sso_get_site",
            "access_sso_get_inventory",
            "access_sso_list_plugins",
            "access_sso_list_themes",
            "access_sso_search_content",
            "access_sso_get_health",
            "access_sso_get_logs",
            "access_sso_get_database_schema",
        )
        for name in expected:
            self.assertIn("'name' => '" + name + "'", MCP)
        self.assertIn("'readOnlyHint' => true", MCP)
        self.assertIn("'destructiveHint' => false", MCP)
        self.assertIn("LIMIT %d", MCP)
        self.assertNotIn("wp_remote_post", MCP)
        self.assertNotIn("wp_remote_request", MCP)
        self.assertNotIn("->delete(", MCP)
        self.assertNotIn("INSERT ", MCP)
        self.assertNotIn("UPDATE ", MCP)
        self.assertNotIn("DELETE FROM", MCP)
        self.assertIn("SHOW TABLE STATUS", MCP)
        self.assertIn("DESCRIBE `{$name}`", MCP)
        self.assertNotIn("$wpdb->query(", MCP)

    def test_diagnostic_data_is_bounded_and_logs_are_redacted(self):
        self.assertIn("posts_per_page' => $per_page", MCP)
        self.assertIn("'content' => $this->truncate_text", MCP)
        self.assertIn("redact_log_line", MCP)
        self.assertIn("REDACTED_JWT", MCP)
        self.assertIn("min(200", MCP)

    def test_adapter_integration_is_optional_and_uses_custom_server(self):
        self.assertIn("function_exists('wp_register_ability')", MCP)
        self.assertIn("add_action('mcp_adapter_init'", MCP)
        self.assertIn("access-sso-readonly", MCP)
        self.assertIn("WP\\\\MCP\\\\Transport\\\\HttpTransport", MCP)
        self.assertIn("'access-sso/get-member'", MCP)
        self.assertIn("'access-sso/get-inventory'", MCP)
        self.assertIn("'access-sso/get-database-schema'", MCP)
        self.assertIn("'public' => false", MCP)


if __name__ == "__main__":
    unittest.main()
