<?php
/**
 * Plugin Name: Access Platform SSO
 * Plugin URI: https://github.com/BetterBetterBetter/wp-access-sso
 * Description: Single Sign-On integration with Access Platform (Supabase Auth)
 * Version: 1.1.5
 * Author: Access Platform Team
 * License: GPL v2 or later
 * Text Domain: access-platform-sso
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('ACCESS_SSO_VERSION', '1.1.5');
define('ACCESS_SSO_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('ACCESS_SSO_PLUGIN_URL', plugin_dir_url(__FILE__));

// Include required files immediately to ensure classes are available for all hooks
require_once ACCESS_SSO_PLUGIN_DIR . 'includes/class-jwt-validator.php';
require_once ACCESS_SSO_PLUGIN_DIR . 'includes/class-user-provisioner.php';
require_once ACCESS_SSO_PLUGIN_DIR . 'includes/class-session-manager.php';
require_once ACCESS_SSO_PLUGIN_DIR . 'includes/class-admin-settings.php';

// Plugin Update Checker - GitHub integration
if (file_exists(ACCESS_SSO_PLUGIN_DIR . 'plugin-update-checker/plugin-update-checker.php')) {
    require_once ACCESS_SSO_PLUGIN_DIR . 'plugin-update-checker/plugin-update-checker.php';
    
    $updateChecker = YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
        'https://github.com/BetterBetterBetter/wp-access-sso',
        __FILE__,
        'access-platform-sso'
    );
    
    // Enable GitHub releases for better versioning
    $updateChecker->getVcsApi()->enableReleaseAssets();
}

class AccessPlatformSSO {
    const IMPERSONATION_COOKIE = 'access_sso_impersonation';
    const IMPERSONATION_TRANSIENT_PREFIX = 'access_sso_impersonation_';
    const IMPERSONATION_TTL = 86400;
    
    private static $instance = null;
    private $admin_settings = null;
    private $impersonation_banner_rendered = false;
    
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
        add_action('wp_body_open', array($this, 'render_frontend_impersonation_banner'));
        add_action('wp_footer', array($this, 'render_frontend_impersonation_banner'));
        
        // Admin hooks
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'admin_init'));
        add_action('admin_notices', array($this, 'render_admin_impersonation_banner'));
        
        // Login form customization
        add_action('login_form', array($this, 'add_sso_login_button'));
        add_filter('login_message', array($this, 'add_sso_login_message'));
    }
    
    public function init() {
        // Load text domain for translations
        load_plugin_textdomain('access-platform-sso', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }
    
    public function enqueue_scripts() {
        wp_enqueue_script(
            'access-sso-frontend',
            ACCESS_SSO_PLUGIN_URL . 'assets/js/sso-redirect.js',
            array('jquery'),
            ACCESS_SSO_VERSION,
            true
        );
        
        // Login form detector - auto-injects SSO button into MemberPress, LearnDash, etc.
        wp_enqueue_script(
            'access-sso-detector',
            ACCESS_SSO_PLUGIN_URL . 'assets/js/login-form-detector.js',
            array(),
            ACCESS_SSO_VERSION,
            true
        );
        
        wp_enqueue_style(
            'access-sso-login',
            ACCESS_SSO_PLUGIN_URL . 'assets/css/login.css',
            array(),
            ACCESS_SSO_VERSION
        );

        $this->enqueue_impersonation_banner_styles();
        
        // Localize script with settings
        wp_localize_script('access-sso-frontend', 'accessSSO', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('access_sso_nonce'),
            'platform_url' => $this->get_option('platform_url', ''),
            'site_id' => $this->get_option('site_id', ''),
        ));
        
        // Configuration for login form detector
        $detector_config = array(
            'platform_url' => $this->get_option('platform_url', ''),
            'site_id' => $this->get_option('site_id', ''),
            'callback_url' => $this->get_callback_url(),
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('access_sso_nonce'),
            'button_text' => $this->get_option('button_text', 'Login with Access Platform'),
            'divider_text' => $this->get_option('divider_text', 'or'),
            'disabled' => $this->get_option('detector_disabled', '0') === '1',
            'show_when_logged_in' => false,
            'enabled_form_types' => $this->get_enabled_form_types(),
            'excluded_routes' => $this->get_excluded_routes(),
        );
        
        wp_localize_script('access-sso-detector', 'accessSSODetector', $detector_config);
    }
    
    /**
     * Get the list of enabled form types for the detector
     */
    private function get_enabled_form_types() {
        $enabled = $this->get_option('enabled_form_types', '');
        
        if (empty($enabled)) {
            // Default: enable all
            return array('wordpress', 'memberpress', 'learndash', 'woocommerce', 'ultimatemember', 'buddypress', 'generic');
        }
        
        // Parse comma-separated list or JSON array
        if (is_string($enabled)) {
            if (strpos($enabled, '[') === 0) {
                $enabled = json_decode($enabled, true);
            } else {
                $enabled = array_map('trim', explode(',', $enabled));
            }
        }
        
        return is_array($enabled) ? $enabled : array();
    }
    
    /**
     * Get the list of excluded routes for the detector
     */
    private function get_excluded_routes() {
        $excluded = $this->get_option('excluded_routes', '');
        
        if (empty($excluded)) {
            return array();
        }
        
        // Parse newline-separated list
        $routes = array_filter(array_map('trim', explode("\n", $excluded)));
        
        return $routes;
    }
    
    public function admin_enqueue_scripts($hook) {
        $this->enqueue_impersonation_banner_styles();

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

        $impersonation_context = $this->extract_impersonation_context($claims);
        $provisioning_claims = $claims;
        unset($provisioning_claims['impersonation']);
        
        // Log the SSO attempt for debugging
        $sso_email = isset($provisioning_claims['email']) ? $provisioning_claims['email'] : 'unknown';
        $sso_sub = isset($provisioning_claims['sub']) ? $provisioning_claims['sub'] : (isset($provisioning_claims['id']) ? $provisioning_claims['id'] : 'unknown');
        error_log('[Access SSO] Provisioning user - email: ' . $sso_email . ', sub: ' . $sso_sub);
        
        $wp_user = $user_provisioner->provision_user($provisioning_claims);
        
        if (is_wp_error($wp_user)) {
            error_log('[Access SSO] User provisioning failed - email: ' . $sso_email . ', error: ' . $wp_user->get_error_message());
            wp_die(__('Failed to create user account: ', 'access-platform-sso') . $wp_user->get_error_message());
        }
        
        error_log('[Access SSO] User provisioned successfully - email: ' . $sso_email . ', WP user ID: ' . $wp_user->ID);
        
        // Log in the user
        wp_set_auth_cookie($wp_user->ID, true);
        wp_set_current_user($wp_user->ID);
        
        // Create SSO session
        $session_manager = new AccessSSO_Session_Manager();
        $session_manager->create_sso_session($wp_user->ID, $user_data);

        if ($impersonation_context) {
            $this->store_impersonation_context($wp_user->ID, $impersonation_context);
        } else {
            $this->clear_impersonation_context();
        }
        
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
        
        $callback_url = $this->get_callback_url();
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

        $this->clear_impersonation_context();

        // Stay on the current WordPress site after logout
        // No external redirects here to keep user on-site
    }

    public function render_frontend_impersonation_banner() {
        if (is_admin() || $this->impersonation_banner_rendered) {
            return;
        }

        $context = $this->get_impersonation_context();
        if (!$context) {
            return;
        }

        $this->render_impersonation_banner($context, false);
        $this->impersonation_banner_rendered = true;
    }

    public function render_admin_impersonation_banner() {
        $context = $this->get_impersonation_context();
        if (!$context) {
            return;
        }

        $this->render_impersonation_banner($context, true);
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
    
    /**
     * Get the SSO callback URL, using custom callback path if configured.
     * Use this when the homepage doesn't have access to WordPress code.
     */
    public function get_callback_url() {
        $callback_path = $this->get_option('callback_path', '');
        
        if (!empty($callback_path)) {
            // Use custom callback path (e.g., /welcome/)
            $callback_path = '/' . ltrim($callback_path, '/'); // Ensure leading slash
            $callback_path = rtrim($callback_path, '/') . '/'; // Ensure trailing slash
            $base_url = home_url($callback_path);
        } else {
            // Default to root
            $base_url = home_url('/');
        }
        
        return $base_url . '?access_sso_callback=1&nonce=' . wp_create_nonce('access_sso_callback');
    }
    
    public function get_option($key, $default = '') {
        return get_option('access_sso_' . $key, $default);
    }
    
    public function update_option($key, $value) {
        return update_option('access_sso_' . $key, $value);
    }
    
    public function delete_option($key) {
        return delete_option('access_sso_' . $key);
    }

    private function enqueue_impersonation_banner_styles() {
        if (!$this->get_impersonation_context()) {
            return;
        }

        wp_enqueue_style(
            'access-sso-impersonation-banner',
            ACCESS_SSO_PLUGIN_URL . 'assets/css/impersonation-banner.css',
            array(),
            ACCESS_SSO_VERSION
        );
    }

    private function extract_impersonation_context($claims) {
        if (!is_array($claims) || !isset($claims['impersonation']) || !is_array($claims['impersonation'])) {
            return false;
        }

        $impersonation = $claims['impersonation'];
        if (!isset($impersonation['active']) || $impersonation['active'] !== true) {
            return false;
        }

        return array(
            'targetEmail' => isset($impersonation['targetEmail']) ? sanitize_email($impersonation['targetEmail']) : '',
            'adminEmail' => isset($impersonation['adminEmail']) ? sanitize_email($impersonation['adminEmail']) : '',
            'startedAt' => isset($impersonation['startedAt']) ? sanitize_text_field($impersonation['startedAt']) : '',
            'returnToAccessUrl' => isset($impersonation['returnToAccessUrl']) ? $this->sanitize_impersonation_url($impersonation['returnToAccessUrl']) : '',
            'exitImpersonationUrl' => isset($impersonation['exitImpersonationUrl']) ? $this->sanitize_impersonation_url($impersonation['exitImpersonationUrl']) : '',
        );
    }

    private function sanitize_impersonation_url($url) {
        $url = esc_url_raw($url, array('http', 'https'));
        if (empty($url)) {
            return '';
        }

        $scheme = wp_parse_url($url, PHP_URL_SCHEME);
        if (!in_array(strtolower((string) $scheme), array('http', 'https'), true)) {
            return '';
        }

        return $url;
    }

    private function store_impersonation_context($user_id, $context) {
        $session_key = wp_generate_password(43, false, false);
        $context['user_id'] = (int) $user_id;

        set_transient($this->get_impersonation_transient_key($session_key), $context, self::IMPERSONATION_TTL);
        $this->set_impersonation_cookie($session_key, time() + self::IMPERSONATION_TTL);
    }

    private function get_impersonation_context() {
        if (!is_user_logged_in()) {
            return false;
        }

        $session_key = $this->get_impersonation_session_key();
        if (empty($session_key)) {
            return false;
        }

        $context = get_transient($this->get_impersonation_transient_key($session_key));
        if (!is_array($context) || !isset($context['user_id']) || (int) $context['user_id'] !== get_current_user_id()) {
            $this->clear_impersonation_context();
            return false;
        }

        return $context;
    }

    private function clear_impersonation_context() {
        $session_key = $this->get_impersonation_session_key();
        if (!empty($session_key)) {
            delete_transient($this->get_impersonation_transient_key($session_key));
        }

        $this->set_impersonation_cookie('', time() - self::IMPERSONATION_TTL);
        unset($_COOKIE[self::IMPERSONATION_COOKIE]);
    }

    private function get_impersonation_session_key() {
        if (empty($_COOKIE[self::IMPERSONATION_COOKIE])) {
            return '';
        }

        $session_key = sanitize_text_field(wp_unslash($_COOKIE[self::IMPERSONATION_COOKIE]));
        if (!preg_match('/^[A-Za-z0-9]+$/', $session_key)) {
            return '';
        }

        return $session_key;
    }

    private function get_impersonation_transient_key($session_key) {
        return self::IMPERSONATION_TRANSIENT_PREFIX . hash('sha256', $session_key);
    }

    private function set_impersonation_cookie($value, $expiration) {
        if (!headers_sent()) {
            $cookie_path = defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/';
            $cookie_domain = defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '';

            if (PHP_VERSION_ID >= 70300) {
                setcookie(self::IMPERSONATION_COOKIE, $value, array(
                    'expires' => $expiration,
                    'path' => $cookie_path,
                    'domain' => $cookie_domain,
                    'secure' => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Lax',
                ));
            } else {
                setcookie(
                    self::IMPERSONATION_COOKIE,
                    $value,
                    $expiration,
                    $cookie_path . '; samesite=Lax',
                    $cookie_domain,
                    is_ssl(),
                    true
                );
            }
        }

        if ($expiration > time() && !empty($value)) {
            $_COOKIE[self::IMPERSONATION_COOKIE] = $value;
        }
    }

    private function render_impersonation_banner($context, $is_admin = false) {
        $target_email = !empty($context['targetEmail']) ? $context['targetEmail'] : __('the target user', 'access-platform-sso');
        $admin_email = !empty($context['adminEmail']) ? $context['adminEmail'] : __('an Access admin', 'access-platform-sso');
        $class_names = $is_admin
            ? 'notice notice-warning access-sso-impersonation-banner access-sso-impersonation-banner--admin'
            : 'access-sso-impersonation-banner access-sso-impersonation-banner--frontend';

        echo '<div class="' . esc_attr($class_names) . '" role="status" aria-live="polite">';
        echo '<div class="access-sso-impersonation-banner__content">';
        echo '<p class="access-sso-impersonation-banner__message">';
        echo '<strong>' . esc_html__('Access impersonation active.', 'access-platform-sso') . '</strong> ';
        echo esc_html(
            sprintf(
                __('This WordPress session was launched by Access admin %1$s impersonating %2$s.', 'access-platform-sso'),
                $admin_email,
                $target_email
            )
        );
        echo '</p>';

        if (!empty($context['returnToAccessUrl']) || !empty($context['exitImpersonationUrl'])) {
            echo '<div class="access-sso-impersonation-banner__actions">';

            if (!empty($context['returnToAccessUrl'])) {
                echo '<a class="access-sso-impersonation-banner__button" href="' . esc_url($context['returnToAccessUrl']) . '">';
                echo esc_html__('Return to Access', 'access-platform-sso');
                echo '</a>';
            }

            if (!empty($context['exitImpersonationUrl'])) {
                echo '<a class="access-sso-impersonation-banner__button access-sso-impersonation-banner__button--secondary" href="' . esc_url($context['exitImpersonationUrl']) . '">';
                echo esc_html__('Exit impersonation', 'access-platform-sso');
                echo '</a>';
            }

            echo '</div>';
        }

        echo '</div>';
        echo '</div>';
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
