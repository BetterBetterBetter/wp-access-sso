<?php
/**
 * Private, read-only MCP bridge for the Access platform.
 *
 * The public agent-facing MCP lives in Access. This endpoint is a site-local
 * transport used only by Access to read bounded MemberPress/WordPress data.
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
            default:
                return $this->json_rpc_error($id, -32602, 'Unknown read-only MCP tool.', 400);
        }

        if (is_wp_error($value)) {
            return $this->json_rpc_error($id, -32000, $value->get_error_message(), 500);
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
        );

        foreach ($abilities as $name => $config) {
            if (function_exists('wp_get_ability') && wp_get_ability($name)) {
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
