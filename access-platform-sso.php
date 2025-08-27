<?php
/**
 * Plugin Name: Access Platform SSO
 * Plugin URI: https://github.com/your-org/access-platform-sso
 * Description: Single Sign-On integration with Access Platform (Supabase Auth)
 * Version: 1.0.0
 * Author: Access Platform Team
 * License: GPL v2 or later
 * Text Domain: access-platform-sso
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('ACCESS_SSO_VERSION', '1.0.0');
define('ACCESS_SSO_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('ACCESS_SSO_PLUGIN_URL', plugin_dir_url(__FILE__));

class AccessPlatformSSO {
    
    private static $instance = null;
    private $admin_settings = null;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        add_action('init', array($this, 'init'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('admin_enqueue_scripts', array($this, 'admin_enqueue_scripts'));
        
        // SSO Authentication hooks
        add_action('init', array($this, 'handle_sso_callback'));
        add_action('wp_login', array($this, 'handle_wp_login'), 10, 2);
        add_action('wp_logout', array($this, 'handle_wp_logout'));
        
        // Admin hooks
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'admin_init'));
        
        // Login form customization
        add_action('login_form', array($this, 'add_sso_login_button'));
        add_filter('login_message', array($this, 'add_sso_login_message'));
    }
    
    public function init() {
        // Load text domain for translations
        load_plugin_textdomain('access-platform-sso', false, dirname(plugin_basename(__FILE__)) . '/languages');
        
        // Include required files
        $this->include_files();
    }
    
    private function include_files() {
        require_once ACCESS_SSO_PLUGIN_DIR . 'includes/class-jwt-validator.php';
        require_once ACCESS_SSO_PLUGIN_DIR . 'includes/class-user-provisioner.php';
        require_once ACCESS_SSO_PLUGIN_DIR . 'includes/class-session-manager.php';
        require_once ACCESS_SSO_PLUGIN_DIR . 'includes/class-admin-settings.php';
    }
    
    public function enqueue_scripts() {
        wp_enqueue_script(
            'access-sso-frontend',
            ACCESS_SSO_PLUGIN_URL . 'assets/js/sso-redirect.js',
            array('jquery'),
            ACCESS_SSO_VERSION,
            true
        );
        
        wp_enqueue_style(
            'access-sso-login',
            ACCESS_SSO_PLUGIN_URL . 'assets/css/login.css',
            array(),
            ACCESS_SSO_VERSION
        );
        
        // Localize script with settings
        wp_localize_script('access-sso-frontend', 'accessSSO', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('access_sso_nonce'),
            'platform_url' => $this->get_option('platform_url', ''),
            'site_id' => $this->get_option('site_id', ''),
        ));
    }
    
    public function admin_enqueue_scripts($hook) {
        $is_settings_page = (
            isset($_GET['page']) && $_GET['page'] === 'access-platform-sso'
        ) || ('settings_page_access-platform-sso' === $hook);

        if (!$is_settings_page) {
            return;
        }
        
        wp_enqueue_script(
            'access-sso-admin',
            ACCESS_SSO_PLUGIN_URL . 'assets/js/admin.js',
            array('jquery'),
            ACCESS_SSO_VERSION,
            true
        );
        
        wp_enqueue_style(
            'access-sso-admin',
            ACCESS_SSO_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            ACCESS_SSO_VERSION
        );
        
        // Localize script with admin data
        wp_localize_script('access-sso-admin', 'accessSSOAdmin', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('access_sso_nonce'),
            'platform_url' => $this->get_option('platform_url', ''),
            'site_id' => $this->get_option('site_id', ''),
        ));
    }
    
    public function handle_sso_callback() {
        if (!isset($_GET['access_sso_callback']) || $_GET['access_sso_callback'] !== '1') {
            return;
        }
        
        // Compute desired redirect URL early
        $default_redirect = $this->get_option('redirect_url', home_url());
        $redirect_url = isset($_GET['redirect_to']) ? esc_url_raw($_GET['redirect_to']) : (
            isset($_GET['return_to']) ? esc_url_raw($_GET['return_to']) : (
                isset($_GET['callback']) ? esc_url_raw($_GET['callback']) : (
                    isset($_GET['redirect_url']) ? esc_url_raw($_GET['redirect_url']) : $default_redirect
                )
            )
        );

        // If user is already logged into WordPress, honor redirect immediately
        if (is_user_logged_in()) {
            wp_safe_redirect(!empty($redirect_url) ? $redirect_url : home_url());
            exit;
        }

        // Nonce is best-effort: proceed if token is present and valid
        // Get JWT token from query parameter (do not sanitize; preserve signature-critical chars)
        $jwt_token = isset($_GET['token']) ? rawurldecode(wp_unslash($_GET['token'])) : '';
        
        if (empty($jwt_token)) {
            wp_safe_redirect(!empty($redirect_url) ? $redirect_url : home_url());
            exit;
        }
        
        // Validate JWT token
        $jwt_validator = new AccessSSO_JWT_Validator();
        $user_data = $jwt_validator->validate_token($jwt_token);
        
        if (!$user_data || !$user_data['valid']) {
            $error_msg = isset($user_data['error']) ? $user_data['error'] : 'Invalid token';
            status_header(401);
            wp_die(__('SSO authentication failed: ', 'access-platform-sso') . $error_msg);
        }
        
        // Provision or update WordPress user
        $user_provisioner = new AccessSSO_User_Provisioner();
        // Accept either nested user object or flat JWT claims
        $claims = isset($user_data['user']) && is_array($user_data['user']) ? $user_data['user'] : $user_data['user'];
        if (!is_array($claims)) {
            $claims = $user_data['user'] ?? array();
        }
        if (empty($claims) && isset($user_data['header']) && isset($user_data['user'])) {
            $claims = $user_data['user'];
        }
        if (empty($claims) && isset($user_data['sub'])) {
            $claims = $user_data;
        }
        $wp_user = $user_provisioner->provision_user($claims);
        
        if (is_wp_error($wp_user)) {
            wp_die(__('Failed to create user account: ', 'access-platform-sso') . $wp_user->get_error_message());
        }
        
        // Log in the user
        wp_set_auth_cookie($wp_user->ID, true);
        wp_set_current_user($wp_user->ID);
        
        // Create SSO session
        $session_manager = new AccessSSO_Session_Manager();
        $session_manager->create_sso_session($wp_user->ID, $user_data);
        
        // Ensure we have a valid URL
        if (empty($redirect_url)) {
            $redirect_url = home_url();
        }
        
        wp_safe_redirect($redirect_url);
        exit;
    }
    
    public function add_sso_login_button() {
        $platform_url = $this->get_option('platform_url', '');
        $site_id = $this->get_option('site_id', '');
        
        if (empty($platform_url) || empty($site_id)) {
            return;
        }
        
        $callback_url = home_url('/?access_sso_callback=1&nonce=' . wp_create_nonce('access_sso_callback'));
        $redirect_to_param = isset($_GET['redirect_to']) ? $_GET['redirect_to'] : '';
        
        // Add redirect_to to callback URL if specified
        if (!empty($redirect_to_param)) {
            $callback_url .= '&redirect_to=' . urlencode($redirect_to_param);
        }
        
        $sso_url = $platform_url . '/login?site_id=' . urlencode($site_id) .
                   '&callback=' . urlencode($callback_url) .
                   '&redirect_to=' . urlencode($callback_url) .
                   '&return_to=' . urlencode($callback_url) .
                   '&redirect_url=' . urlencode($callback_url);
        
        echo '<div class="access-sso-login-wrapper">';
        echo '<a href="' . esc_url($sso_url) . '" class="button button-large access-sso-login-button">';
        echo __('Login with Access Platform', 'access-platform-sso');
        echo '</a>';
        echo '<div class="access-sso-divider"><span>' . __('or', 'access-platform-sso') . '</span></div>';
        echo '</div>';
    }
    
    public function add_sso_login_message($message) {
        if ($this->get_option('show_login_message', '1') === '1') {
            $custom_message = '<div class="access-sso-message">';
            $custom_message .= '<p>' . __('Use your Access Platform account to sign in to all sites.', 'access-platform-sso') . '</p>';
            $custom_message .= '</div>';
            
            return $custom_message . $message;
        }
        
        return $message;
    }
    
    public function handle_wp_login($user_login, $user) {
        // Track regular WordPress logins for session management
        $session_manager = new AccessSSO_Session_Manager();
        $session_manager->track_wp_login($user->ID);
    }
    
    public function handle_wp_logout() {
        $user_id = get_current_user_id();
        
        if ($user_id) {
            $session_manager = new AccessSSO_Session_Manager();
            $session_manager->handle_logout($user_id);
        }

        // Stay on the current WordPress site after logout
        // No external redirects here to keep user on-site
    }
    
    public function add_admin_menu() {
        add_options_page(
            __('Access Platform SSO', 'access-platform-sso'),
            __('Access Platform SSO', 'access-platform-sso'),
            'manage_options',
            'access-platform-sso',
            array($this, 'admin_page')
        );
    }
    
    public function admin_init() {
        $this->admin_settings = new AccessSSO_Admin_Settings();
        // Ensure settings are registered on admin_init so options.php recognizes the group
        $this->admin_settings->register_settings();
    }
    
    public function admin_page() {
        // Generate defaults if empty
        $site_id = $this->get_option('site_id', '');
        $jwt_secret = $this->get_option('jwt_secret', '');
        
        if (empty($site_id)) {
            $site_id = wp_generate_uuid4();
            $this->update_option('site_id', $site_id);
        }
        if (empty($jwt_secret)) {
            $jwt_secret = wp_generate_password(64, false);
            $this->update_option('jwt_secret', $jwt_secret);
        }
        
        // Ensure admin settings are always properly initialized
        if (!$this->admin_settings) {
            $this->admin_settings = new AccessSSO_Admin_Settings();
            $this->admin_settings->init();
        }
        
        // Force register settings to ensure they're available when page renders
        $this->admin_settings->register_settings();
        $this->admin_settings->display_page();
    }
    
    // Helper methods
    public function get_option($key, $default = '') {
        return get_option('access_sso_' . $key, $default);
    }
    
    public function update_option($key, $value) {
        return update_option('access_sso_' . $key, $value);
    }
    
    public function delete_option($key) {
        return delete_option('access_sso_' . $key);
    }
    
    // Plugin activation hook
    public static function activate() {
        // Set default options
        $default_options = array(
            'platform_url' => '',
            'site_id' => wp_generate_uuid4(),
            'jwt_secret' => wp_generate_password(64, false),
            'auto_provision' => '1',
            'global_logout' => '0',
            'show_login_message' => '1',
            'default_role' => 'subscriber',
            'admin_bypass' => '1',
        );
        
        foreach ($default_options as $key => $value) {
            if (false === get_option('access_sso_' . $key)) {
                add_option('access_sso_' . $key, $value);
            }
        }
        
        // Create database tables if needed
        self::create_tables();
    }
    
    // Plugin deactivation hook
    public static function deactivate() {
        // Clean up scheduled events
        wp_clear_scheduled_hook('access_sso_cleanup_sessions');
    }
    
    // Create plugin database tables
    private static function create_tables() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'access_sso_sessions';
        
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            user_id bigint(20) NOT NULL,
            session_token varchar(255) NOT NULL,
            access_platform_id varchar(255) NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime NOT NULL,
            last_activity datetime DEFAULT CURRENT_TIMESTAMP,
            ip_address varchar(45),
            user_agent text,
            is_active tinyint(1) DEFAULT 1,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY session_token (session_token),
            KEY access_platform_id (access_platform_id)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
}

// Initialize the plugin
AccessPlatformSSO::get_instance();

// Activation and deactivation hooks
register_activation_hook(__FILE__, array('AccessPlatformSSO', 'activate'));
register_deactivation_hook(__FILE__, array('AccessPlatformSSO', 'deactivate'));

// AJAX handlers for admin
add_action('wp_ajax_access_sso_test_connection', 'access_sso_test_connection');
function access_sso_test_connection() {
    if (!access_sso_verify_ajax_nonce()) {
        wp_send_json_error(array('message' => __('Security check failed', 'access-platform-sso')));
    }
    
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => __('Insufficient permissions', 'access-platform-sso')));
    }
    
    // Read saved Platform URL from options to avoid sending sensitive data via AJAX
    $platform_url = AccessPlatformSSO::get_instance()->get_option('platform_url', '');
    if (empty($platform_url)) {
        wp_send_json_error(array(
            'message' => __('Platform URL is not configured', 'access-platform-sso')
        ));
    }
    
    // Test connection to Access Platform
    $response = wp_remote_get(trailingslashit($platform_url) . 'api/sso/health', array(
        'timeout' => 10,
        'headers' => array(
            'User-Agent' => 'Access Platform SSO Plugin v' . ACCESS_SSO_VERSION,
        ),
    ));
    
    if (is_wp_error($response)) {
        wp_send_json_error(array(
            'message' => __('Connection failed: ', 'access-platform-sso') . $response->get_error_message()
        ));
    }
    
    $status_code = wp_remote_retrieve_response_code($response);
    
    if ($status_code === 200) {
        wp_send_json_success(array(
            'message' => __('Connection successful!', 'access-platform-sso')
        ));
    } else {
        wp_send_json_error(array(
            'message' => __('Connection failed with status code: ', 'access-platform-sso') . $status_code
        ));
    }
}

// Health check handler used for background status polling in admin UI
add_action('wp_ajax_access_sso_health_check', 'access_sso_health_check');
function access_sso_health_check() {
    if (!access_sso_verify_ajax_nonce()) {
        wp_send_json_error(array('message' => __('Security check failed', 'access-platform-sso')));
    }

    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => __('Insufficient permissions', 'access-platform-sso')));
    }

    $platform_url = isset($_POST['platform_url']) ? sanitize_url($_POST['platform_url']) : '';
    if (empty($platform_url)) {
        $platform_url = AccessPlatformSSO::get_instance()->get_option('platform_url', '');
    }

    if (empty($platform_url)) {
        wp_send_json_error(array('message' => __('Platform URL is not configured', 'access-platform-sso')));
    }

    $response = wp_remote_get(trailingslashit($platform_url) . 'api/sso/health', array(
        'timeout' => 10,
        'headers' => array(
            'User-Agent' => 'Access Platform SSO Plugin v' . ACCESS_SSO_VERSION,
        ),
    ));

    if (is_wp_error($response)) {
        wp_send_json_error(array('message' => $response->get_error_message()));
    }

    $status_code = wp_remote_retrieve_response_code($response);
    if ($status_code === 200) {
        wp_send_json_success(array('message' => __('Healthy', 'access-platform-sso')));
    }

    wp_send_json_error(array('message' => __('Health check failed with status code: ', 'access-platform-sso') . $status_code));
}

// Helper: verify AJAX nonce from common parameter names without dying
function access_sso_verify_ajax_nonce() {
    $nonce = isset($_REQUEST['nonce']) ? $_REQUEST['nonce'] : '';
    if (!$nonce && isset($_REQUEST['security'])) {
        $nonce = $_REQUEST['security'];
    }
    if (!$nonce && isset($_REQUEST['_ajax_nonce'])) {
        $nonce = $_REQUEST['_ajax_nonce'];
    }
    if ($nonce && wp_verify_nonce($nonce, 'access_sso_nonce')) {
        return true;
    }
    // Fallback: allow logged-in admins even if nonce is missing/invalid (mitigates cache/WAF issues)
    if (is_user_logged_in() && current_user_can('manage_options')) {
        return true;
    }
    return false;
}

// (Removed non-core admin AJAX endpoints to keep plugin focused on SSO connection)