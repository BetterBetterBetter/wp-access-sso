<?php
/**
 * Plugin Name: Access Platform SSO
 * Plugin URI: https://github.com/BetterBetterBetter/wp-access-sso
 * Description: Single Sign-On integration with Access Platform (Supabase Auth)
 * Version: 1.1.7
 * Author: Access Platform Team
 * License: GPL v2 or later
 * Text Domain: access-platform-sso
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('ACCESS_SSO_VERSION', '1.1.7');
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
        add_action('init', array($this, 'handle_impersonation_exit'));
        add_action('wp_login', array($this, 'handle_wp_login'), 10, 2);
        add_action('wp_logout', array($this, 'handle_wp_logout'));
        add_action('wp_body_open', array($this, 'render_frontend_impersonation_banner'));
        add_action('wp_footer', array($this, 'render_frontend_impersonation_banner'));
        
        // Admin hooks
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'admin_init'));
        add_action('admin_notices', array($this, 'render_site_id_admin_notice'));
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

        // Nonce is best-effort: proceed if token is present and valid
        // Get JWT token from query parameter (do not sanitize; preserve signature-critical chars)
        $jwt_token = isset($_GET['token']) ? rawurldecode(wp_unslash($_GET['token'])) : '';
        
        if (empty($jwt_token)) {
            // Existing logged-in callback hits without a token are just redirects.
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

    public function handle_impersonation_exit() {
        if (!isset($_GET['access_sso_exit_impersonation']) || $_GET['access_sso_exit_impersonation'] !== '1') {
            return;
        }

        $nonce = isset($_GET['nonce']) ? sanitize_text_field(wp_unslash($_GET['nonce'])) : '';
        if (!wp_verify_nonce($nonce, 'access_sso_exit_impersonation')) {
            wp_die(__('Invalid impersonation exit request.', 'access-platform-sso'));
        }

        $context = $this->get_impersonation_context();
        $exit_url = is_array($context) && !empty($context['exitImpersonationUrl']) ? $context['exitImpersonationUrl'] : '';

        $this->clear_impersonation_context();

        if (is_user_logged_in()) {
            wp_logout();
        }

        if (empty($exit_url)) {
            wp_safe_redirect(home_url());
            exit;
        }

        wp_redirect($exit_url);
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

    public function render_site_id_admin_notice() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $site_id = $this->get_option('site_id', '');
        $platform_url = $this->get_option('platform_url', '');
        $settings_url = admin_url('options-general.php?page=access-platform-sso');

        if (empty($site_id)) {
            echo '<div class="notice notice-error"><p>';
            echo '<strong>' . esc_html__('Access Platform SSO is not connected.', 'access-platform-sso') . '</strong> ';
            echo esc_html__('The canonical Access site ID is missing. Connect this WordPress site to Access or configure the canonical Access site ID before using SSO.', 'access-platform-sso') . ' ';
            echo '<a href="' . esc_url($settings_url) . '">' . esc_html__('Open SSO settings', 'access-platform-sso') . '</a>';
            echo '</p></div>';
            return;
        }

        $is_verified = get_option('access_sso_site_id_verified', '0') === '1';
        if ($is_verified) {
            return;
        }

        $validation_code = get_option('access_sso_site_id_validation_code', 'unverified');
        $validation_error = get_option('access_sso_site_id_validation_error', '');
        $notice_class = in_array($validation_code, array('site_not_found', 'site_host_mismatch'), true) ? 'notice-error' : 'notice-warning';

        access_sso_maybe_notify_stored_site_validation_issue($platform_url, $site_id);

        echo '<div class="notice ' . esc_attr($notice_class) . '"><p>';
        echo '<strong>' . esc_html__('Access Platform SSO site ID is not verified.', 'access-platform-sso') . '</strong> ';
        echo esc_html__('The stored WordPress value may be a local plugin-generated ID. The canonical Access site ID is the source of truth.', 'access-platform-sso') . ' ';

        if (!empty($validation_error)) {
            echo esc_html($validation_error) . ' ';
        } elseif (empty($platform_url)) {
            echo esc_html__('Configure the Access Platform URL, then test the connection to verify this site ID.', 'access-platform-sso') . ' ';
        } else {
            echo esc_html__('Test the connection to verify that Access recognizes this site ID and domain.', 'access-platform-sso') . ' ';
        }

        if (!empty($platform_url)) {
            echo esc_html__('Access admins will be notified centrally when this issue is detected.', 'access-platform-sso') . ' ';
        }

        echo '<a href="' . esc_url($settings_url) . '">' . esc_html__('Review SSO settings', 'access-platform-sso') . '</a>';
        echo '</p></div>';
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
        // Generate non-identity defaults if empty. Site IDs must come from Access.
        $jwt_secret = $this->get_option('jwt_secret', '');

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

    private function get_impersonation_exit_url() {
        return add_query_arg(
            array(
                'access_sso_exit_impersonation' => '1',
                'nonce' => wp_create_nonce('access_sso_exit_impersonation'),
            ),
            home_url('/')
        );
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
                echo '<a class="access-sso-impersonation-banner__button access-sso-impersonation-banner__button--secondary" href="' . esc_url($this->get_impersonation_exit_url()) . '">';
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
            'site_id' => '',
            'site_id_verified' => '0',
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

function access_sso_validate_configured_site($platform_url, $site_id, $home_url = '') {
    $platform_url = esc_url_raw($platform_url);
    $site_id = sanitize_text_field($site_id);
    $home_url = !empty($home_url) ? esc_url_raw($home_url) : home_url();

    if (empty($platform_url)) {
        return new WP_Error('missing_platform_url', __('Platform URL is not configured', 'access-platform-sso'));
    }

    if (empty($site_id)) {
        return new WP_Error('missing_site_id', __('Canonical Access site ID is not configured. Connect this site to Access or paste the canonical Access site ID.', 'access-platform-sso'));
    }

    $base_url = trailingslashit($platform_url) . 'api/sso/';
    $requests = array(
        array(
            'method' => 'GET',
            'url' => $base_url . 'sites/' . rawurlencode($site_id),
        ),
        array(
            'method' => 'GET',
            'url' => add_query_arg('site_id', $site_id, $base_url . 'sites'),
        ),
        array(
            'method' => 'GET',
            'url' => add_query_arg('site_id', $site_id, $base_url . 'site'),
        ),
        array(
            'method' => 'POST',
            'url' => $base_url . 'site/validate',
            'body' => array(
                'site_id' => $site_id,
                'home_url' => $home_url,
            ),
        ),
    );

    $requests = apply_filters('access_sso_site_verification_requests', $requests, $platform_url, $site_id, $home_url);

    $last_error = __('Unable to verify the Access site ID.', 'access-platform-sso');
    $not_found_error = '';

    foreach ($requests as $request) {
        $method = isset($request['method']) ? strtoupper($request['method']) : 'GET';
        $url = isset($request['url']) ? $request['url'] : '';

        if (empty($url)) {
            continue;
        }

        $args = array(
            'timeout' => 15,
            'headers' => array(
                'Accept' => 'application/json',
                'User-Agent' => 'Access Platform SSO Plugin v' . ACCESS_SSO_VERSION,
            ),
        );

        if ($method === 'POST') {
            $args['headers']['Content-Type'] = 'application/json';
            $args['body'] = wp_json_encode(isset($request['body']) ? $request['body'] : array('site_id' => $site_id));
            $response = wp_remote_post($url, $args);
        } else {
            $response = wp_remote_get($url, $args);
        }

        if (is_wp_error($response)) {
            $last_error = $response->get_error_message();
            continue;
        }

        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        $response_error_code = access_sso_extract_response_error_code($data);

        if ($status_code === 200) {
            $site = access_sso_extract_site_from_response($data, $site_id);

            if (empty($site)) {
                $last_error = __('Access responded successfully but did not return a matching site record.', 'access-platform-sso');
                continue;
            }

            $access_site_url = access_sso_extract_site_url($site);
            if (empty($access_site_url)) {
                return new WP_Error(
                    'site_url_missing',
                    __('Access recognized the site ID but did not return a site URL/domain to verify against this WordPress home URL.', 'access-platform-sso')
                );
            }

            $wordpress_host = access_sso_normalize_host(wp_parse_url($home_url, PHP_URL_HOST));
            $access_host = access_sso_normalize_host(access_sso_extract_host($access_site_url));

            if (empty($wordpress_host) || empty($access_host)) {
                return new WP_Error(
                    'site_host_missing',
                    sprintf(
                        __('Unable to compare WordPress host "%1$s" with Access site URL "%2$s".', 'access-platform-sso'),
                        $home_url,
                        $access_site_url
                    )
                );
            }

            if ($wordpress_host !== $access_host) {
                return new WP_Error(
                    'site_host_mismatch',
                    sprintf(
                        __('Access site host mismatch. WordPress home URL host is "%1$s" from "%2$s"; Access site URL host is "%3$s" from "%4$s". Configure the canonical Access site ID for this WordPress site.', 'access-platform-sso'),
                        $wordpress_host,
                        $home_url,
                        $access_host,
                        $access_site_url
                    )
                );
            }

            return array(
                'site_id' => $site_id,
                'site' => $site,
                'access_site_url' => $access_site_url,
                'access_host' => $access_host,
                'wordpress_home_url' => $home_url,
                'wordpress_host' => $wordpress_host,
            );
        }

        if ($response_error_code === 'site_not_found' || $status_code === 404 || $status_code === 410) {
            $not_found_error = sprintf(
                __('Access does not recognize the configured site ID "%s". Replace it with the canonical Access site ID for this WordPress site.', 'access-platform-sso'),
                $site_id
            );

            if ($response_error_code === 'site_not_found') {
                return new WP_Error('site_not_found', $not_found_error);
            }
        }

        $last_error = sprintf(
            __('Access site verification returned status %1$d from %2$s.', 'access-platform-sso'),
            $status_code,
            $url
        );
    }

    if (!empty($not_found_error)) {
        return new WP_Error('site_not_found', $not_found_error);
    }

    return new WP_Error('site_verification_failed', $last_error);
}

function access_sso_extract_response_error_code($data) {
    if (!is_array($data)) {
        return '';
    }

    foreach (array('error', 'code', 'error_code') as $key) {
        if (!empty($data[$key]) && is_string($data[$key])) {
            return $data[$key];
        }

        if (!empty($data[$key]) && is_array($data[$key])) {
            return access_sso_extract_response_error_code($data[$key]);
        }
    }

    if (!empty($data['data']) && is_array($data['data'])) {
        return access_sso_extract_response_error_code($data['data']);
    }

    return '';
}

function access_sso_extract_site_from_response($data, $site_id) {
    if (!is_array($data)) {
        return array();
    }

    foreach (array('site', 'data', 'result') as $key) {
        if (!empty($data[$key]) && is_array($data[$key])) {
            $site = access_sso_extract_site_from_response($data[$key], $site_id);
            if (!empty($site)) {
                return $site;
            }
        }
    }

    foreach (array('sites', 'items', 'results') as $key) {
        if (!empty($data[$key]) && is_array($data[$key])) {
            foreach ($data[$key] as $candidate) {
                if (!is_array($candidate)) {
                    continue;
                }

                $candidate_id = access_sso_extract_site_id($candidate);
                if (empty($candidate_id) || $candidate_id === $site_id) {
                    return $candidate;
                }
            }
        }
    }

    $candidate_id = access_sso_extract_site_id($data);
    if (!empty($candidate_id) && $candidate_id !== $site_id) {
        return array();
    }

    if (!empty($candidate_id) || !empty(access_sso_extract_site_url($data))) {
        return $data;
    }

    return array();
}

function access_sso_extract_site_id($site) {
    foreach (array('site_id', 'siteId', 'id', 'uuid') as $key) {
        if (!empty($site[$key]) && is_string($site[$key])) {
            return $site[$key];
        }
    }

    return '';
}

function access_sso_extract_site_url($site) {
    foreach (array('site_url', 'siteUrl', 'url', 'home_url', 'homeUrl', 'wordpress_url', 'wordpressUrl', 'domain', 'host') as $key) {
        if (!empty($site[$key]) && is_string($site[$key])) {
            return $site[$key];
        }
    }

    return '';
}

function access_sso_extract_host($value) {
    $host = wp_parse_url($value, PHP_URL_HOST);
    if (!empty($host)) {
        return $host;
    }

    $host = wp_parse_url('https://' . ltrim($value, '/'), PHP_URL_HOST);
    return !empty($host) ? $host : $value;
}

function access_sso_normalize_host($host) {
    return strtolower(rtrim((string) $host, '.'));
}

function access_sso_store_site_validation_result($result, $context = array()) {
    if (is_wp_error($result)) {
        update_option('access_sso_site_id_verified', '0');
        update_option('access_sso_site_id_validation_code', $result->get_error_code());
        update_option('access_sso_site_id_validation_error', $result->get_error_message());
        access_sso_notify_access_admins($result, $context);
        return;
    }

    update_option('access_sso_site_id_verified', '1');
    update_option('access_sso_site_id_validation_code', '');
    update_option('access_sso_site_id_validation_error', '');
    update_option('access_sso_site_id_verified_at', current_time('mysql'));

    if (!empty($result['access_site_url'])) {
        update_option('access_sso_site_url', esc_url_raw($result['access_site_url']));
    }
}

function access_sso_maybe_notify_stored_site_validation_issue($platform_url, $site_id) {
    if (empty($platform_url)) {
        return;
    }

    if (get_option('access_sso_site_id_verified', '0') === '1') {
        return;
    }

    $validation_code = get_option('access_sso_site_id_validation_code', 'unverified');
    $validation_error = get_option('access_sso_site_id_validation_error', '');

    if (empty($validation_error)) {
        $validation_error = __('Stored WordPress site ID has not been verified against Access.', 'access-platform-sso');
    }

    access_sso_notify_access_admins(
        new WP_Error($validation_code, $validation_error),
        array(
            'platform_url' => $platform_url,
            'site_id' => $site_id,
            'source' => 'admin_notice',
        )
    );
}

function access_sso_notify_access_admins($result, $context = array()) {
    if (!is_wp_error($result)) {
        return false;
    }

    $platform_url = !empty($context['platform_url'])
        ? esc_url_raw($context['platform_url'])
        : AccessPlatformSSO::get_instance()->get_option('platform_url', '');

    if (empty($platform_url)) {
        update_option('access_sso_access_admin_alert_last_error', __('Access admin alert skipped because Platform URL is not configured.', 'access-platform-sso'));
        return false;
    }

    $site_id = isset($context['site_id'])
        ? sanitize_text_field($context['site_id'])
        : AccessPlatformSSO::get_instance()->get_option('site_id', '');
    $error_code = $result->get_error_code();
    $error_message = $result->get_error_message();
    $source = !empty($context['source']) ? sanitize_text_field($context['source']) : 'site_validation';
    $fingerprint = hash('sha256', $platform_url . '|' . $site_id . '|' . $error_code . '|' . $error_message);
    $last_fingerprint = get_option('access_sso_access_admin_alert_last_attempt_fingerprint', '');
    $last_attempt_at = (int) get_option('access_sso_access_admin_alert_last_attempt_at', 0);
    $throttle_seconds = (int) apply_filters('access_sso_access_admin_alert_throttle_seconds', 6 * HOUR_IN_SECONDS, $result, $context);

    if ($fingerprint === $last_fingerprint && $last_attempt_at > 0 && (time() - $last_attempt_at) < $throttle_seconds) {
        return false;
    }

    $endpoint_url = apply_filters(
        'access_sso_access_admin_alert_url',
        trailingslashit($platform_url) . 'api/sso/plugin-alerts',
        $platform_url,
        $result,
        $context
    );

    if (empty($endpoint_url)) {
        update_option('access_sso_access_admin_alert_last_error', __('Access admin alert skipped because no alert endpoint is configured.', 'access-platform-sso'));
        return false;
    }

    $payload = array(
        'event' => 'wordpress_sso_site_id_validation_failed',
        'severity' => in_array($error_code, array('site_not_found', 'site_host_mismatch', 'missing_site_id'), true) ? 'critical' : 'warning',
        'source' => $source,
        'site_id' => $site_id,
        'error_code' => $error_code,
        'error_message' => $error_message,
        'wordpress_home_url' => home_url(),
        'wordpress_admin_url' => admin_url(),
        'wordpress_host' => access_sso_normalize_host(wp_parse_url(home_url(), PHP_URL_HOST)),
        'platform_url' => $platform_url,
        'plugin_version' => ACCESS_SSO_VERSION,
        'reported_at' => current_time('mysql'),
        'fingerprint' => $fingerprint,
    );

    if (!empty($context['access_site_url'])) {
        $payload['access_site_url'] = esc_url_raw($context['access_site_url']);
    }

    if (!empty($context['access_host'])) {
        $payload['access_host'] = sanitize_text_field($context['access_host']);
    }

    $payload = apply_filters('access_sso_access_admin_alert_payload', $payload, $result, $context);

    do_action('access_sso_before_access_admin_alert', $payload, $result, $context);

    update_option('access_sso_access_admin_alert_last_attempt_fingerprint', $fingerprint);
    update_option('access_sso_access_admin_alert_last_attempt_at', time());

    $response = wp_remote_post($endpoint_url, array(
        'timeout' => 10,
        'headers' => array(
            'Content-Type' => 'application/json',
            'User-Agent' => 'Access Platform SSO Plugin v' . ACCESS_SSO_VERSION,
        ),
        'body' => wp_json_encode($payload),
    ));

    if (is_wp_error($response)) {
        update_option('access_sso_access_admin_alert_last_error', $response->get_error_message());
        return false;
    }

    $status_code = wp_remote_retrieve_response_code($response);
    if ($status_code < 200 || $status_code >= 300) {
        update_option(
            'access_sso_access_admin_alert_last_error',
            sprintf(__('Access admin alert endpoint returned status %d.', 'access-platform-sso'), $status_code)
        );
        return false;
    }

    update_option('access_sso_access_admin_alert_last_fingerprint', $fingerprint);
    update_option('access_sso_access_admin_alert_last_sent_at', time());
    update_option('access_sso_access_admin_alert_last_error', '');

    return true;
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
    
    $platform_url = isset($_POST['platform_url']) ? sanitize_url(wp_unslash($_POST['platform_url'])) : '';
    if (empty($platform_url)) {
        $platform_url = AccessPlatformSSO::get_instance()->get_option('platform_url', '');
    }

    if (empty($platform_url)) {
        wp_send_json_error(array(
            'message' => __('Platform URL is not configured', 'access-platform-sso')
        ));
    }

    $site_id = isset($_POST['site_id']) ? sanitize_text_field(wp_unslash($_POST['site_id'])) : '';
    if (empty($site_id)) {
        $site_id = AccessPlatformSSO::get_instance()->get_option('site_id', '');
    }

    if (empty($site_id)) {
        $result = new WP_Error('missing_site_id', __('Canonical Access site ID is not configured. Connect this site to Access or paste the canonical Access site ID.', 'access-platform-sso'));
        access_sso_store_site_validation_result($result, array(
            'platform_url' => $platform_url,
            'site_id' => $site_id,
            'source' => 'connection_test',
        ));
        wp_send_json_error(array(
            'message' => $result->get_error_message(),
            'code' => $result->get_error_code(),
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
        access_sso_store_site_validation_result(new WP_Error(
            'platform_connection_failed',
            __('Connection failed: ', 'access-platform-sso') . $response->get_error_message()
        ), array(
            'platform_url' => $platform_url,
            'site_id' => $site_id,
            'source' => 'connection_test',
        ));

        wp_send_json_error(array(
            'message' => __('Connection failed: ', 'access-platform-sso') . $response->get_error_message()
        ));
    }
    
    $status_code = wp_remote_retrieve_response_code($response);
    
    if ($status_code === 200) {
        $site_validation = access_sso_validate_configured_site($platform_url, $site_id, home_url());
        access_sso_store_site_validation_result($site_validation, array(
            'platform_url' => $platform_url,
            'site_id' => $site_id,
            'source' => 'connection_test',
        ));

        if (is_wp_error($site_validation)) {
            wp_send_json_error(array(
                'message' => $site_validation->get_error_message(),
                'code' => $site_validation->get_error_code(),
            ));
        }

        wp_send_json_success(array(
            'message' => __('Connection successful. Access recognizes this canonical site ID and the site host matches.', 'access-platform-sso'),
            'site_id' => $site_id,
            'wordpress_host' => $site_validation['wordpress_host'],
            'access_host' => $site_validation['access_host'],
        ));
    } else {
        access_sso_store_site_validation_result(new WP_Error(
            'platform_health_failed',
            __('Connection failed with status code: ', 'access-platform-sso') . $status_code
        ), array(
            'platform_url' => $platform_url,
            'site_id' => $site_id,
            'source' => 'connection_test',
        ));

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

    $site_id = AccessPlatformSSO::get_instance()->get_option('site_id', '');
    if (empty($site_id)) {
        wp_send_json_error(array('message' => __('Canonical Access site ID is not configured', 'access-platform-sso')));
    }

    if (get_option('access_sso_site_id_verified', '0') !== '1') {
        $validation_error = get_option('access_sso_site_id_validation_error', __('Canonical Access site ID is not verified', 'access-platform-sso'));
        wp_send_json_error(array('message' => $validation_error));
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
