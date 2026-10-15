<?php
/**
 * Private, read-only MCP bridge for the Access platform.
 *
 * The public agent-facing MCP lives in Access. This endpoint is a site-local
 * transport used only by Access to read bounded WordPress diagnostics and
 * MemberPress data. It deliberately excludes writes, arbitrary SQL, and
 * credential-bearing settings.
 */

if (!defined('ABSPATH')) {
    exit;
}

class AccessSSO_Readonly_MCP {
    const ROUTE_NAMESPACE = 'access-sso/v1';
    const ROUTE = '/mcp';
    const REQUEST_TTL = 300;
    const NONCE_TTL = 600;
    const MAX_BODY_BYTES = 65536;
    const NONCE_PREFIX = 'access_sso_mcp_nonce_';

    private static $instance = null;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct() {
        add_action('rest_api_init', array($this, 'register_route'));

        // WordPress 6.9+ exposes the Abilities API. The checks keep this
        // plugin compatible with older sites while allowing the official MCP
        // Adapter to expose the same bounded tools when installed.
        add_action('wp_abilities_api_init', array($this, 'register_abilities'));
        add_action('mcp_adapter_init', array($this, 'register_adapter_server'));
    }

    public function register_route() {
        register_rest_route(self::ROUTE_NAMESPACE, self::ROUTE, array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'handle_request'),
            'permission_callback' => '__return_true',
        ));
    }

    public function handle_request(WP_REST_Request $request) {
        $body = $request->get_body();
        $authorization = $this->authenticate_request($request, $body);
        if (is_wp_error($authorization)) {
            return $this->json_error($authorization->get_error_code(), $authorization->get_error_message(), $authorization->get_error_data());
        }

        if (strlen($body) > self::MAX_BODY_BYTES) {
            return $this->json_error('request_too_large', 'MCP request exceeds the maximum size.', array('status' => 413));
        }

        $message = json_decode($body, true);
        if (!is_array($message) || isset($message[0])) {
            return $this->json_rpc_error(null, -32600, 'Invalid JSON-RPC request.', 400);
        }

        $id = array_key_exists('id', $message) ? $message['id'] : null;
        if (isset($message['jsonrpc']) && $message['jsonrpc'] !== '2.0') {
            return $this->json_rpc_error($id, -32600, 'Invalid JSON-RPC version.', 400);
        }

        $method = isset($message['method']) && is_string($message['method']) ? $message['method'] : '';
        $params = isset($message['params']) && is_array($message['params']) ? $message['params'] : array();

        if ('initialize' === $method) {
            return $this->json_result($id, array(
                'protocolVersion' => '2025-06-18',
                'capabilities' => array('tools' => array()),
                'serverInfo' => array(
                    'name' => 'access-sso-readonly',
                    'version' => defined('ACCESS_SSO_VERSION') ? ACCESS_SSO_VERSION : '1.0.0',
                ),
            ));
        }

        if ('notifications/initialized' === $method) {
            return new WP_REST_Response(null, 202);
        }

        if ('tools/list' === $method) {
            return $this->json_result($id, array('tools' => $this->get_tools()));
        }

        if ('tools/call' === $method) {
            return $this->handle_tool_call($id, $params);
        }

        return $this->json_rpc_error($id, -32601, 'MCP method not found.', 404);
    }

    /**
     * Authenticate an Access request with a domain-separated HMAC signature.
     * The existing site-bound SSO secret is never returned or logged.
     */
    public function authenticate_request($request, $body = null) {
        if (!$request || !method_exists($request, 'get_header')) {
            return new WP_Error('invalid_request', 'Invalid request.', array('status' => 400));
        }

        if (null === $body && method_exists($request, 'get_body')) {
            $body = $request->get_body();
        }
        $body = is_string($body) ? $body : '';

        $secret = (string) get_option('access_sso_jwt_secret', '');
        $site_id = (string) get_option('access_sso_site_id', '');
        $provided_site_id = trim((string) $request->get_header('x-access-site-id'));
        $timestamp = trim((string) $request->get_header('x-access-mcp-timestamp'));
        $nonce = trim((string) $request->get_header('x-access-mcp-nonce'));
        $signature = strtolower(trim((string) $request->get_header('x-access-mcp-signature')));

        if ('' === $secret || '' === $site_id || '1' !== (string) get_option('access_sso_site_id_verified', '0')) {
            return new WP_Error('mcp_not_configured', 'Access read-only MCP is not configured.', array('status' => 503));
        }

        if ($provided_site_id !== $site_id) {
            return new WP_Error('site_mismatch', 'Site identity does not match the configured Access site.', array('status' => 403));
        }

        if (!preg_match('/^[0-9]{10}$/', $timestamp)) {
            return new WP_Error('invalid_timestamp', 'Invalid MCP request timestamp.', array('status' => 401));
        }

        $now = time();
        if (abs($now - (int) $timestamp) > self::REQUEST_TTL) {
            return new WP_Error('expired_request', 'MCP request has expired.', array('status' => 401));
        }

        if (!preg_match('/^[A-Za-z0-9_-]{32,128}$/', $nonce)) {
            return new WP_Error('invalid_nonce', 'Invalid MCP request nonce.', array('status' => 401));
        }

        if (!preg_match('/^[a-f0-9]{64}$/', $signature)) {
            return new WP_Error('invalid_signature', 'Invalid MCP request signature.', array('status' => 401));
        }

        $signed_message = "access-sso-readonly-mcp-v1\n" . $timestamp . "\n" . $nonce . "\n" . $site_id . "\n" . $body;
        $expected = hash_hmac('sha256', $signed_message, $secret);
        if (!hash_equals($expected, $signature)) {
            return new WP_Error('invalid_signature', 'Invalid MCP request signature.', array('status' => 401));
        }

        $nonce_key = self::NONCE_PREFIX . hash('sha256', $nonce);
        if (false !== get_transient($nonce_key)) {
            return new WP_Error('replayed_request', 'MCP request nonce has already been used.', array('status' => 401));
        }

        set_transient($nonce_key, '1', self::NONCE_TTL);
        return true;
    }

    private function get_tools() {
        return array(
            array(
                'name' => 'access_sso_get_member',
                'description' => 'Read one MemberPress member by exact email.',
                'inputSchema' => array(
                    'type' => 'object',
                    'properties' => array('email' => array('type' => 'string', 'format' => 'email')),
                    'required' => array('email'),
                    'additionalProperties' => false,
                ),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_get_memberships',
                'description' => 'Read up to 100 MemberPress memberships for one exact email.',
                'inputSchema' => array(
                    'type' => 'object',
                    'properties' => array('email' => array('type' => 'string', 'format' => 'email')),
                    'required' => array('email'),
                    'additionalProperties' => false,
                ),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_get_transactions',
                'description' => 'Read up to 100 MemberPress transactions for one exact email.',
                'inputSchema' => array(
                    'type' => 'object',
                    'properties' => array('email' => array('type' => 'string', 'format' => 'email')),
                    'required' => array('email'),
                    'additionalProperties' => false,
                ),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_list_products',
                'description' => 'Read up to 100 published MemberPress products.',
                'inputSchema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_get_site',
                'description' => 'Read non-sensitive WordPress and Access site metadata.',
                'inputSchema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_get_inventory',
                'description' => 'Read bounded WordPress core, runtime, theme, and content inventory metadata.',
                'inputSchema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_list_plugins',
                'description' => 'List installed WordPress plugins and their versions without settings or credentials.',
                'inputSchema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_list_themes',
                'description' => 'List installed WordPress themes and their versions without theme secrets.',
                'inputSchema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_search_content',
                'description' => 'Read a bounded page of WordPress post or page content for debugging.',
                'inputSchema' => array(
                    'type' => 'object',
                    'properties' => array(
                        'postType' => array('type' => 'string', 'maxLength' => 80),
                        'status' => array('type' => 'string', 'enum' => array('publish', 'draft', 'pending', 'private', 'any')),
                        'search' => array('type' => 'string', 'maxLength' => 200),
                        'page' => array('type' => 'integer', 'minimum' => 1, 'maximum' => 1000),
                        'perPage' => array('type' => 'integer', 'minimum' => 1, 'maximum' => 100),
                    ),
                    'additionalProperties' => false,
                ),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_get_health',
                'description' => 'Read bounded WordPress health, cron, debug, and filesystem checks.',
                'inputSchema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_get_logs',
                'description' => 'Read a redacted tail of the WordPress debug log, limited to recent lines.',
                'inputSchema' => array(
                    'type' => 'object',
                    'properties' => array('maxLines' => array('type' => 'integer', 'minimum' => 1, 'maximum' => 200)),
                    'additionalProperties' => false,
                ),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
            array(
                'name' => 'access_sso_get_database_schema',
                'description' => 'Read database table metadata and optionally columns without reading arbitrary rows or secrets.',
                'inputSchema' => array(
                    'type' => 'object',
                    'properties' => array(
                        'table' => array('type' => 'string', 'pattern' => '^[A-Za-z0-9_]+$', 'maxLength' => 128),
                        'includeColumns' => array('type' => 'boolean'),
                    ),
                    'additionalProperties' => false,
                ),
                'annotations' => array('readOnlyHint' => true, 'destructiveHint' => false, 'idempotentHint' => true),
            ),
        );
    }

    private function handle_tool_call($id, $params) {
        $name = isset($params['name']) && is_string($params['name']) ? $params['name'] : '';
        $arguments = isset($params['arguments']) && is_array($params['arguments']) ? $params['arguments'] : array();
        $email = isset($arguments['email']) && is_string($arguments['email']) ? strtolower(trim($arguments['email'])) : '';

        if (in_array($name, array('access_sso_get_member', 'access_sso_get_memberships', 'access_sso_get_transactions'), true)) {
            if (!is_email($email)) {
                return $this->json_rpc_error($id, -32602, 'A valid exact email is required.', 400);
            }
        }

        switch ($name) {
            case 'access_sso_get_member':
                $value = $this->get_member($email);
                break;
            case 'access_sso_get_memberships':
                $value = $this->get_memberships($email);
                break;
            case 'access_sso_get_transactions':
                $value = $this->get_transactions($email);
                break;
            case 'access_sso_list_products':
                $value = $this->get_products();
                break;
            case 'access_sso_get_site':
                $value = $this->get_site_metadata();
                break;
            case 'access_sso_get_inventory':
                $value = $this->get_inventory();
                break;
            case 'access_sso_list_plugins':
                $value = $this->get_plugins();
                break;
            case 'access_sso_list_themes':
                $value = $this->get_themes();
                break;
            case 'access_sso_search_content':
                $value = $this->get_content($arguments);
                break;
            case 'access_sso_get_health':
                $value = $this->get_health();
                break;
            case 'access_sso_get_logs':
                $value = $this->get_logs($arguments);
                break;
            case 'access_sso_get_database_schema':
                $value = $this->get_database_schema($arguments);
                break;
            default:
                return $this->json_rpc_error($id, -32602, 'Unknown read-only MCP tool.', 400);
        }

        if (is_wp_error($value)) {
            $input_error = in_array($value->get_error_code(), array('invalid_table'), true);
            return $this->json_rpc_error(
                $id,
                $input_error ? -32602 : -32000,
                $value->get_error_message(),
                $input_error ? 400 : 500
            );
        }

        return $this->json_result($id, array(
            'content' => array(array('type' => 'text', 'text' => wp_json_encode($value))),
        ));
    }

    private function get_member($email) {
        $user = $this->find_user_by_email($email);
        if (!$user) {
            return null;
        }

        $registered_at = strtotime((string) $user->user_registered);
        return array(
            'id' => (int) $user->ID,
            'email' => strtolower((string) $user->user_email),
            'firstName' => (string) get_user_meta((int) $user->ID, 'first_name', true),
            'lastName' => (string) get_user_meta((int) $user->ID, 'last_name', true),
            'registeredAt' => $registered_at ? gmdate('c', $registered_at) : null,
            'memberships' => $this->get_memberships_for_user((int) $user->ID),
        );
    }

    private function get_memberships($email) {
        $user = $this->find_user_by_email($email);
        return $user ? $this->get_memberships_for_user((int) $user->ID) : array();
    }

    private function get_transactions($email) {
        $user = $this->find_user_by_email($email);
        if (!$user) {
            return array();
        }

        global $wpdb;
        $table = $wpdb->prefix . 'mepr_transactions';
        $suppressed = $wpdb->suppress_errors(true);
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT id, product_id, subscription_id, status, amount, total, created_at, expires_at, trans_num FROM {$table} WHERE user_id = %d ORDER BY id DESC LIMIT %d",
            (int) $user->ID,
            100
        ), ARRAY_A);
        $wpdb->suppress_errors($suppressed);

        return is_array($rows) ? array_map(array($this, 'sanitize_transaction'), $rows) : array();
    }

    private function get_products() {
        $posts = get_posts(array(
            'post_type' => 'memberpressproduct',
            'post_status' => 'publish',
            'posts_per_page' => 100,
            'orderby' => 'ID',
            'order' => 'ASC',
        ));

        return array_map(function ($post) {
            return array(
                'id' => (int) $post->ID,
                'name' => (string) $post->post_title,
                'status' => (string) $post->post_status,
            );
        }, is_array($posts) ? $posts : array());
    }

    private function get_site_metadata() {
        return array(
            'siteId' => (string) get_option('access_sso_site_id', ''),
            'url' => esc_url_raw(home_url('/')),
            'wordpressVersion' => function_exists('get_bloginfo') ? (string) get_bloginfo('version') : '',
            'accessSsoVersion' => defined('ACCESS_SSO_VERSION') ? ACCESS_SSO_VERSION : '',
            'memberPressAvailable' => class_exists('MeprUser') || post_type_exists('memberpressproduct'),
        );
    }

    private function get_inventory() {
        global $wp_version;

        $post_counts = function_exists('wp_count_posts') ? wp_count_posts() : null;
        $page_counts = function_exists('wp_count_posts') ? wp_count_posts('page') : null;
        $theme = function_exists('wp_get_theme') ? wp_get_theme() : null;

        return array(
            'site' => $this->get_site_metadata(),
            'siteName' => function_exists('get_bloginfo') ? (string) get_bloginfo('name') : '',
            'description' => function_exists('get_bloginfo') ? (string) get_bloginfo('description') : '',
            'locale' => function_exists('get_locale') ? (string) get_locale() : '',
            'timezone' => function_exists('wp_timezone_string') ? (string) wp_timezone_string() : '',
            'wordpressVersion' => isset($wp_version) ? (string) $wp_version : '',
            'phpVersion' => PHP_VERSION,
            'environmentType' => function_exists('wp_get_environment_type') ? (string) wp_get_environment_type() : 'production',
            'multisite' => function_exists('is_multisite') && is_multisite(),
            'ssl' => function_exists('is_ssl') && is_ssl(),
            'permalinkStructure' => (string) get_option('permalink_structure', ''),
            'activeTheme' => $theme ? array(
                'name' => (string) $theme->get('Name'),
                'version' => (string) $theme->get('Version'),
                'stylesheet' => (string) $theme->get_stylesheet(),
                'template' => (string) $theme->get_template(),
            ) : null,
            'counts' => array(
                'posts' => $post_counts && isset($post_counts->publish) ? (int) $post_counts->publish : null,
                'pages' => $page_counts && isset($page_counts->publish) ? (int) $page_counts->publish : null,
                'users' => function_exists('count_users') ? (int) count_users()['total_users'] : null,
            ),
            'capabilities' => array(
                'abilitiesApi' => function_exists('wp_register_ability'),
                'mcpAdapter' => class_exists('WP\\MCP\\Transport\\HttpTransport'),
                'memberPress' => class_exists('MeprUser') || post_type_exists('memberpressproduct'),
            ),
        );
    }

    private function get_plugins() {
        if (!function_exists('get_plugins') && defined('ABSPATH')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins = function_exists('get_plugins') ? get_plugins() : array();
        $active = (array) get_option('active_plugins', array());
        $result = array();

        foreach ($plugins as $file => $plugin) {
            if (count($result) >= 500) {
                break;
            }
            $result[] = array(
                'file' => (string) $file,
                'name' => isset($plugin['Name']) ? (string) $plugin['Name'] : '',
                'version' => isset($plugin['Version']) ? (string) $plugin['Version'] : '',
                'author' => isset($plugin['Author']) ? wp_strip_all_tags((string) $plugin['Author']) : '',
                'pluginUri' => isset($plugin['PluginURI']) ? esc_url_raw((string) $plugin['PluginURI']) : '',
                'active' => in_array($file, $active, true),
                'networkOnly' => !empty($plugin['Network']),
            );
        }

        return $result;
    }

    private function get_themes() {
        $themes = function_exists('wp_get_themes') ? wp_get_themes() : array();
        $active_stylesheet = function_exists('get_stylesheet') ? get_stylesheet() : '';
        $result = array();

        foreach ($themes as $stylesheet => $theme) {
            if (count($result) >= 100) {
                break;
            }
            $result[] = array(
                'stylesheet' => (string) $stylesheet,
                'template' => (string) $theme->get_template(),
                'name' => (string) $theme->get('Name'),
                'version' => (string) $theme->get('Version'),
                'author' => wp_strip_all_tags((string) $theme->get('Author')),
                'themeUri' => esc_url_raw((string) $theme->get('ThemeURI')),
                'active' => $stylesheet === $active_stylesheet,
            );
        }

        return $result;
    }

    private function get_content($arguments) {
        $post_type = isset($arguments['postType']) && is_string($arguments['postType']) ? sanitize_key($arguments['postType']) : 'page';
        $status = isset($arguments['status']) && is_string($arguments['status']) ? $arguments['status'] : 'publish';
        $search = isset($arguments['search']) && is_string($arguments['search']) ? sanitize_text_field($arguments['search']) : '';
        $page = isset($arguments['page']) ? max(1, min(1000, (int) $arguments['page'])) : 1;
        $per_page = isset($arguments['perPage']) ? max(1, min(100, (int) $arguments['perPage'])) : 50;
        $allowed_statuses = array('publish', 'draft', 'pending', 'private', 'any');

        if (!post_type_exists($post_type) || !in_array($status, $allowed_statuses, true)) {
            return new WP_Error('invalid_content_query', 'The requested content type or status is not allowed.');
        }

        $posts = get_posts(array(
            'post_type' => $post_type,
            'post_status' => $status,
            'posts_per_page' => $per_page,
            'paged' => $page,
            's' => $search,
            'orderby' => 'modified',
            'order' => 'DESC',
            'suppress_filters' => false,
        ));

        $items = array();
        foreach (is_array($posts) ? $posts : array() as $post) {
            $items[] = array(
                'id' => (int) $post->ID,
                'type' => (string) $post->post_type,
                'status' => (string) $post->post_status,
                'slug' => (string) $post->post_name,
                'title' => wp_strip_all_tags((string) $post->post_title),
                'authorId' => (int) $post->post_author,
                'createdAt' => (string) $post->post_date_gmt,
                'modifiedAt' => (string) $post->post_modified_gmt,
                'url' => function_exists('get_permalink') ? esc_url_raw(get_permalink($post)) : '',
                'excerpt' => $this->truncate_text(wp_strip_all_tags((string) $post->post_excerpt), 4000),
                'content' => $this->truncate_text((string) $post->post_content, 20000),
            );
        }

        return array(
            'postType' => $post_type,
            'status' => $status,
            'search' => $search,
            'page' => $page,
            'perPage' => $per_page,
            'count' => count($items),
            'items' => $items,
        );
    }

    private function get_health() {
        $cron = function_exists('_get_cron_array') ? _get_cron_array() : array();
        $cron_events = array();
        $now = time();

        foreach (is_array($cron) ? $cron : array() as $timestamp => $hooks) {
            foreach (is_array($hooks) ? $hooks : array() as $hook => $events) {
                foreach (is_array($events) ? $events : array() as $event) {
                    if (count($cron_events) >= 100) {
                        break 3;
                    }
                    $cron_events[] = array(
                        'hook' => (string) $hook,
                        'nextRun' => gmdate('c', (int) $timestamp),
                        'overdue' => (int) $timestamp < $now,
                        'recurrence' => isset($event['schedule']) ? (string) $event['schedule'] : null,
                    );
                }
            }
        }

        $uploads = function_exists('wp_upload_dir') ? wp_upload_dir() : array();
        $upload_path = isset($uploads['basedir']) ? $uploads['basedir'] : '';
        $debug_log = defined('WP_DEBUG_LOG') ? WP_DEBUG_LOG : false;

        return array(
            'wordpressDebug' => defined('WP_DEBUG') && WP_DEBUG,
            'displayErrors' => defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY,
            'debugLogEnabled' => (bool) $debug_log,
            'environmentType' => function_exists('wp_get_environment_type') ? (string) wp_get_environment_type() : 'production',
            'objectCache' => function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache(),
            'cron' => array(
                'eventCount' => count($cron_events),
                'overdueCount' => count(array_filter($cron_events, function ($event) { return !empty($event['overdue']); })),
                'events' => $cron_events,
            ),
            'filesystem' => array(
                'uploadsWritable' => '' !== $upload_path && is_writable($upload_path),
                'pluginDirectoryWritable' => defined('WP_PLUGIN_DIR') && is_writable(WP_PLUGIN_DIR),
                'themeDirectoryWritable' => defined('WP_CONTENT_DIR') && is_writable(WP_CONTENT_DIR . '/themes'),
            ),
            'ssl' => function_exists('is_ssl') && is_ssl(),
            'permalinkStructure' => (string) get_option('permalink_structure', ''),
        );
    }

    private function get_logs($arguments) {
        $max_lines = isset($arguments['maxLines']) ? max(1, min(200, (int) $arguments['maxLines'])) : 100;
        $path = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR . '/debug.log' : '';

        if ('' === $path || !is_readable($path)) {
            return array('available' => false, 'reason' => 'The WordPress debug log is not available.', 'lines' => array());
        }

        $handle = fopen($path, 'rb');
        if (!$handle) {
            return array('available' => false, 'reason' => 'The WordPress debug log could not be opened.', 'lines' => array());
        }
        $size = filesize($path);
        fseek($handle, -min(65536, false === $size ? 0 : $size), SEEK_END);
        $chunk = stream_get_contents($handle);
        fclose($handle);

        $lines = preg_split('/\r\n|\r|\n/', (string) $chunk);
        $lines = array_slice(array_filter($lines, 'strlen'), -$max_lines);
        $lines = array_map(array($this, 'redact_log_line'), $lines);

        return array('available' => true, 'lineCount' => count($lines), 'lines' => $lines);
    }

    private function get_database_schema($arguments) {
        global $wpdb;
        $requested_table = isset($arguments['table']) && is_string($arguments['table']) ? trim($arguments['table']) : '';
        $include_columns = !empty($arguments['includeColumns']);
        if ('' !== $requested_table && !preg_match('/^[A-Za-z0-9_]+$/', $requested_table)) {
            return new WP_Error('invalid_table', 'The table name is invalid.');
        }

        $tables = $wpdb->get_results('SHOW TABLE STATUS', ARRAY_A);
        $result = array();
        foreach (is_array($tables) ? $tables : array() as $table) {
            $name = isset($table['Name']) ? (string) $table['Name'] : '';
            if ('' === $name || ('' !== $requested_table && $requested_table !== $name)) {
                continue;
            }
            $result[] = array(
                'name' => $name,
                'engine' => isset($table['Engine']) ? (string) $table['Engine'] : null,
                'collation' => isset($table['Collation']) ? (string) $table['Collation'] : null,
                'rows' => isset($table['Rows']) ? (int) $table['Rows'] : null,
                'dataBytes' => isset($table['Data_length']) ? (int) $table['Data_length'] : null,
                'indexBytes' => isset($table['Index_length']) ? (int) $table['Index_length'] : null,
            );
            if ('' !== $requested_table && $include_columns) {
                $columns = $wpdb->get_results("DESCRIBE `{$name}`", ARRAY_A);
                $result[count($result) - 1]['columns'] = array_map(array($this, 'sanitize_column'), is_array($columns) ? $columns : array());
            }
            if (count($result) >= 500) {
                break;
            }
        }

        return array(
            'tableCount' => count($result),
            'requestedTable' => '' !== $requested_table ? $requested_table : null,
            'includeColumns' => $include_columns,
            'tables' => $result,
        );
    }

    private function sanitize_column($column) {
        $name = isset($column['Field']) ? (string) $column['Field'] : '';
        $sensitive = (bool) preg_match('/password|secret|token|api[_-]?key|private[_-]?key|salt|cookie/i', $name);
        return array(
            'name' => $name,
            'type' => isset($column['Type']) ? (string) $column['Type'] : '',
            'nullable' => isset($column['Null']) ? 'YES' === $column['Null'] : null,
            'key' => isset($column['Key']) ? (string) $column['Key'] : '',
            'sensitive' => $sensitive,
        );
    }

    private function redact_log_line($line) {
        $line = (string) $line;
        $line = preg_replace('/(Authorization\s*:\s*Bearer\s+)[^\s]+/i', '$1[REDACTED]', $line);
        $line = preg_replace('/((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|signature)\s*[=:]\s*)[^\s,;]+/i', '$1[REDACTED]', $line);
        $line = preg_replace('/([?&](?:token|key|secret|password|signature)=)[^&\s]+/i', '$1[REDACTED]', $line);
        return preg_replace('/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/', '[REDACTED_JWT]', $line);
    }

    private function truncate_text($value, $limit) {
        $value = (string) $value;
        if (function_exists('mb_substr')) {
            return mb_substr($value, 0, $limit);
        }
        return substr($value, 0, $limit);
    }

    private function find_user_by_email($email) {
        global $wpdb;
        $table = $wpdb->users;
        $suppressed = $wpdb->suppress_errors(true);
        $user = $wpdb->get_row($wpdb->prepare(
            "SELECT ID, user_email, user_registered FROM {$table} WHERE LOWER(user_email) = LOWER(%s) LIMIT 1",
            $email
        ));
        $wpdb->suppress_errors($suppressed);
        return $user;
    }

    private function get_memberships_for_user($user_id) {
        global $wpdb;
        $table = $wpdb->prefix . 'mepr_subscriptions';
        $suppressed = $wpdb->suppress_errors(true);
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT id, product_id, status, created_at, expires_at FROM {$table} WHERE user_id = %d ORDER BY id DESC LIMIT %d",
            (int) $user_id,
            100
        ), ARRAY_A);
        $wpdb->suppress_errors($suppressed);

        if (!is_array($rows)) {
            return array();
        }

        return array_map(function ($row) {
            return array(
                'id' => isset($row['id']) ? (string) $row['id'] : '',
                'productId' => isset($row['product_id']) ? (string) $row['product_id'] : '',
                'status' => isset($row['status']) ? (string) $row['status'] : 'unknown',
                'createdAt' => isset($row['created_at']) ? (string) $row['created_at'] : null,
                'expiresAt' => isset($row['expires_at']) ? (string) $row['expires_at'] : null,
            );
        }, $rows);
    }

    private function sanitize_transaction($row) {
        return array(
            'id' => isset($row['id']) ? (string) $row['id'] : '',
            'productId' => isset($row['product_id']) ? (string) $row['product_id'] : '',
            'subscriptionId' => isset($row['subscription_id']) ? (string) $row['subscription_id'] : null,
            'status' => isset($row['status']) ? (string) $row['status'] : 'unknown',
            'amount' => isset($row['amount']) ? (string) $row['amount'] : null,
            'total' => isset($row['total']) ? (string) $row['total'] : null,
            'createdAt' => isset($row['created_at']) ? (string) $row['created_at'] : null,
            'expiresAt' => isset($row['expires_at']) ? (string) $row['expires_at'] : null,
            'transactionNumber' => isset($row['trans_num']) ? (string) $row['trans_num'] : null,
        );
    }

    public function register_abilities() {
        if (!function_exists('wp_register_ability')) {
            return;
        }

        $abilities = array(
            'access-sso/get-member' => array(
                'label' => 'Get Access SSO member',
                'description' => 'Read one MemberPress member by exact email.',
                'input_schema' => $this->email_schema(),
                'execute_callback' => function ($input) { return $this->get_member(strtolower(trim((string) $input['email']))); },
            ),
            'access-sso/get-memberships' => array(
                'label' => 'Get Access SSO memberships',
                'description' => 'Read MemberPress memberships by exact email.',
                'input_schema' => $this->email_schema(),
                'execute_callback' => function ($input) { return $this->get_memberships(strtolower(trim((string) $input['email']))); },
            ),
            'access-sso/get-transactions' => array(
                'label' => 'Get Access SSO transactions',
                'description' => 'Read MemberPress transactions by exact email.',
                'input_schema' => $this->email_schema(),
                'execute_callback' => function ($input) { return $this->get_transactions(strtolower(trim((string) $input['email']))); },
            ),
            'access-sso/list-products' => array(
                'label' => 'List Access SSO products',
                'description' => 'Read published MemberPress products.',
                'input_schema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'execute_callback' => function () { return $this->get_products(); },
            ),
            'access-sso/get-site' => array(
                'label' => 'Get Access SSO site metadata',
                'description' => 'Read non-sensitive WordPress and Access site metadata.',
                'input_schema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'execute_callback' => function () { return $this->get_site_metadata(); },
            ),
            'access-sso/get-inventory' => array(
                'label' => 'Get WordPress site inventory',
                'description' => 'Read bounded WordPress core, runtime, theme, and content inventory metadata.',
                'input_schema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'execute_callback' => function () { return $this->get_inventory(); },
            ),
            'access-sso/list-plugins' => array(
                'label' => 'List WordPress plugins',
                'description' => 'List installed WordPress plugins and their versions.',
                'input_schema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'execute_callback' => function () { return $this->get_plugins(); },
            ),
            'access-sso/list-themes' => array(
                'label' => 'List WordPress themes',
                'description' => 'List installed WordPress themes and their versions.',
                'input_schema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'execute_callback' => function () { return $this->get_themes(); },
            ),
            'access-sso/search-content' => array(
                'label' => 'Search WordPress content',
                'description' => 'Read a bounded page of WordPress post or page content for debugging.',
                'input_schema' => array(
                    'type' => 'object',
                    'properties' => array(
                        'postType' => array('type' => 'string', 'maxLength' => 80),
                        'status' => array('type' => 'string', 'enum' => array('publish', 'draft', 'pending', 'private', 'any')),
                        'search' => array('type' => 'string', 'maxLength' => 200),
                        'page' => array('type' => 'integer', 'minimum' => 1, 'maximum' => 1000),
                        'perPage' => array('type' => 'integer', 'minimum' => 1, 'maximum' => 100),
                    ),
                    'additionalProperties' => false,
                ),
                'execute_callback' => function ($input) { return $this->get_content(is_array($input) ? $input : array()); },
            ),
            'access-sso/get-health' => array(
                'label' => 'Get WordPress health checks',
                'description' => 'Read bounded WordPress health, cron, debug, and filesystem checks.',
                'input_schema' => array('type' => 'object', 'properties' => array(), 'additionalProperties' => false),
                'execute_callback' => function () { return $this->get_health(); },
            ),
            'access-sso/get-logs' => array(
                'label' => 'Get redacted WordPress logs',
                'description' => 'Read a redacted tail of the WordPress debug log.',
                'input_schema' => array(
                    'type' => 'object',
                    'properties' => array('maxLines' => array('type' => 'integer', 'minimum' => 1, 'maximum' => 200)),
                    'additionalProperties' => false,
                ),
                'execute_callback' => function ($input) { return $this->get_logs(is_array($input) ? $input : array()); },
            ),
            'access-sso/get-database-schema' => array(
                'label' => 'Get WordPress database schema',
                'description' => 'Read database table metadata and optionally columns without arbitrary row access.',
                'input_schema' => array(
                    'type' => 'object',
                    'properties' => array(
                        'table' => array('type' => 'string', 'pattern' => '^[A-Za-z0-9_]+$', 'maxLength' => 128),
                        'includeColumns' => array('type' => 'boolean'),
                    ),
                    'additionalProperties' => false,
                ),
                'execute_callback' => function ($input) { return $this->get_database_schema(is_array($input) ? $input : array()); },
            ),
        );

        foreach ($abilities as $name => $config) {
            // Use the dedicated existence check. Calling wp_get_ability() for a
            // missing name emits a doing-it-wrong notice on current WordPress.
            if (function_exists('wp_has_ability') && wp_has_ability($name)) {
                continue;
            }
            $config['category'] = 'site';
            $config['permission_callback'] = function () { return true; };
            $config['meta'] = array(
                'mcp' => array(
                    'public' => false,
                    'type' => 'tool',
                ),
                'annotations' => array(
                    'readOnlyHint' => true,
                    'destructiveHint' => false,
                    'idempotentHint' => true,
                ),
            );
            wp_register_ability($name, $config);
        }
    }

    public function register_adapter_server($adapter) {
        if (!is_object($adapter) || !class_exists('WP\\MCP\\Transport\\HttpTransport')) {
            return;
        }

        $adapter->create_server(
            'access-sso-readonly',
            'access-sso',
            'readonly',
            'Access SSO Read-only',
            'Private read-only site data for the Access platform.',
            defined('ACCESS_SSO_VERSION') ? ACCESS_SSO_VERSION : '1.0.0',
            array('WP\\MCP\\Transport\\HttpTransport'),
            null,
            null,
            array(
                'access-sso/get-member',
                'access-sso/get-memberships',
                'access-sso/get-transactions',
                'access-sso/list-products',
                'access-sso/get-site',
                'access-sso/get-inventory',
                'access-sso/list-plugins',
                'access-sso/list-themes',
                'access-sso/search-content',
                'access-sso/get-health',
                'access-sso/get-logs',
                'access-sso/get-database-schema',
            ),
            array(),
            array(),
            function ($request) {
                return $this->authenticate_request($request);
            }
        );
    }

    private function email_schema() {
        return array(
            'type' => 'object',
            'properties' => array('email' => array('type' => 'string', 'format' => 'email')),
            'required' => array('email'),
            'additionalProperties' => false,
        );
    }

    private function json_result($id, $result) {
        return new WP_REST_Response(array('jsonrpc' => '2.0', 'id' => $id, 'result' => $result), 200);
    }

    private function json_rpc_error($id, $code, $message, $status = 200) {
        return new WP_REST_Response(array(
            'jsonrpc' => '2.0',
            'id' => $id,
            'error' => array('code' => (int) $code, 'message' => (string) $message),
        ), (int) $status);
    }

    private function json_error($code, $message, $data = array()) {
        $status = isset($data['status']) ? (int) $data['status'] : 400;
        return new WP_REST_Response(array('code' => $code, 'message' => $message), $status);
    }
}
