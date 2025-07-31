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
        if ('settings_page_access-platform-sso' !== $hook) {
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
        
        // Verify nonce for security
        if (!isset($_GET['nonce']) || !wp_verify_nonce($_GET['nonce'], 'access_sso_callback')) {
            wp_die(__('Security check failed. Please try again.', 'access-platform-sso'));
        }
        
        // Get JWT token from query parameter
        $jwt_token = isset($_GET['token']) ? sanitize_text_field($_GET['token']) : '';
        
        if (empty($jwt_token)) {
            wp_die(__('Missing SSO token. Please try logging in again.', 'access-platform-sso'));
        }
        
        // Validate JWT token
        $jwt_validator = new AccessSSO_JWT_Validator();
        $user_data = $jwt_validator->validate_token($jwt_token);
        
        if (!$user_data || !$user_data['valid']) {
            $error_msg = isset($user_data['error']) ? $user_data['error'] : 'Invalid token';
            wp_die(__('SSO authentication failed: ', 'access-platform-sso') . $error_msg);
        }
        
        // Provision or update WordPress user
        $user_provisioner = new AccessSSO_User_Provisioner();
        $wp_user = $user_provisioner->provision_user($user_data['user']);
        
        if (is_wp_error($wp_user)) {
            wp_die(__('Failed to create user account: ', 'access-platform-sso') . $wp_user->get_error_message());
        }
        
        // Log in the user
        wp_set_auth_cookie($wp_user->ID, true);
        wp_set_current_user($wp_user->ID);
        
        // Create SSO session
        $session_manager = new AccessSSO_Session_Manager();
        $session_manager->create_sso_session($wp_user->ID, $user_data);
        
        // Redirect to intended page or dashboard
        $redirect_url = isset($_GET['redirect_to']) ? esc_url_raw($_GET['redirect_to']) : admin_url();
        wp_redirect($redirect_url);
        exit;
    }
    
    public function add_sso_login_button() {
        $platform_url = $this->get_option('platform_url', '');
        $site_id = $this->get_option('site_id', '');
        
        if (empty($platform_url) || empty($site_id)) {
            return;
        }
        
        $callback_url = home_url('/?access_sso_callback=1&nonce=' . wp_create_nonce('access_sso_callback'));
        $redirect_to = isset($_GET['redirect_to']) ? urlencode($_GET['redirect_to']) : '';
        
        $sso_url = $platform_url . '/login?site_id=' . urlencode($site_id) . 
                   '&callback=' . urlencode($callback_url) . 
                   '&redirect_to=' . $redirect_to;
        
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
        
        // Optionally redirect to Access Platform logout
        if ($this->get_option('global_logout', '1') === '1') {
            $platform_url = $this->get_option('platform_url', '');
            if (!empty($platform_url)) {
                wp_redirect($platform_url . '/logout?callback=' . urlencode(home_url()));
                exit;
            }
        }
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
        $admin_settings = new AccessSSO_Admin_Settings();
        $admin_settings->init();
    }
    
    public function admin_page() {
        // Handle form submission
        if (isset($_POST['submit']) && check_admin_referer('access_sso_settings')) {
            $this->update_option('platform_url', sanitize_url($_POST['platform_url']));
            $this->update_option('site_id', sanitize_text_field($_POST['site_id']));
            $this->update_option('jwt_secret', sanitize_text_field($_POST['jwt_secret']));
            $this->update_option('auto_provision', isset($_POST['auto_provision']) ? '1' : '0');
            $this->update_option('default_role', sanitize_text_field($_POST['default_role']));
            $this->update_option('global_logout', isset($_POST['global_logout']) ? '1' : '0');
            
            echo '<div class="notice notice-success"><p>' . __('Settings saved!', 'access-platform-sso') . '</p></div>';
        }
        
        // Get current values with defaults
        $platform_url = $this->get_option('platform_url', '');
        $site_id = $this->get_option('site_id', '');
        $jwt_secret = $this->get_option('jwt_secret', '');
        $auto_provision = $this->get_option('auto_provision', '1');
        $default_role = $this->get_option('default_role', 'subscriber');
        $global_logout = $this->get_option('global_logout', '1');
        
        // Generate defaults if empty
        if (empty($site_id)) {
            $site_id = wp_generate_uuid4();
            $this->update_option('site_id', $site_id);
        }
        if (empty($jwt_secret)) {
            $jwt_secret = wp_generate_password(64, false);
            $this->update_option('jwt_secret', $jwt_secret);
        }
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4; border-left: 4px solid #00a0d2;">
                <h2 style="margin-top: 0;"><?php _e('Quick Setup Guide', 'access-platform-sso'); ?></h2>
                <ol>
                    <li><strong><?php _e('Platform URL:', 'access-platform-sso'); ?></strong> <?php _e('Enter your Access Platform URL (e.g., https://your-platform.com)', 'access-platform-sso'); ?></li>
                    <li><strong><?php _e('JWT Secret:', 'access-platform-sso'); ?></strong> <?php _e('Copy the generated secret to your Access Platform environment as SSO_JWT_SECRET', 'access-platform-sso'); ?></li>
                    <li><strong><?php _e('Test Connection:', 'access-platform-sso'); ?></strong> <?php _e('Click test to verify everything works', 'access-platform-sso'); ?></li>
                    <li><strong><?php _e('Save Settings', 'access-platform-sso'); ?></strong></li>
                </ol>
            </div>
            
            <!-- Connection Status -->
            <div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">
                <h3><?php _e('Connection Status', 'access-platform-sso'); ?></h3>
                <div style="display: flex; align-items: center; margin-bottom: 15px;">
                    <span id="status-indicator" style="display: inline-block; width: 12px; height: 12px; border-radius: 50%; background: #ddd; margin-right: 10px;"></span>
                    <span id="status-text"><?php _e('Not configured', 'access-platform-sso'); ?></span>
                </div>
                <button type="button" class="button" onclick="testConnection()" id="test-connection-btn">
                    <?php _e('Test Connection', 'access-platform-sso'); ?>
                </button>
            </div>
            
            <form method="post" action="">
                <?php wp_nonce_field('access_sso_settings'); ?>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <label for="platform_url"><?php _e('Access Platform URL', 'access-platform-sso'); ?></label>
                        </th>
                        <td>
                            <input type="url" id="platform_url" name="platform_url" 
                                   value="<?php echo esc_attr($platform_url); ?>" 
                                   class="regular-text" required>
                            <p class="description"><?php _e('The URL of your Access Platform (e.g., https://your-platform.com)', 'access-platform-sso'); ?></p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">
                            <label for="site_id"><?php _e('Site ID', 'access-platform-sso'); ?></label>
                        </th>
                        <td>
                            <input type="text" id="site_id" name="site_id" 
                                   value="<?php echo esc_attr($site_id); ?>" 
                                   class="regular-text" readonly>
                            <p class="description"><?php _e('Unique identifier for this WordPress site (auto-generated)', 'access-platform-sso'); ?></p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">
                            <label for="jwt_secret"><?php _e('JWT Secret Key', 'access-platform-sso'); ?></label>
                        </th>
                        <td>
                            <textarea id="jwt_secret" name="jwt_secret" rows="3" class="large-text" style="font-family: monospace;"><?php echo esc_textarea($jwt_secret); ?></textarea>
                            <br><br>
                            <button type="button" onclick="generateNewSecret()" class="button"><?php _e('Generate New Secret', 'access-platform-sso'); ?></button>
                            <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin-top: 10px;">
                                <strong><?php _e('Important:', 'access-platform-sso'); ?></strong> 
                                <?php _e('Copy this secret to your Access Platform environment variable', 'access-platform-sso'); ?> <code>SSO_JWT_SECRET</code>
                            </div>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row"><?php _e('User Management', 'access-platform-sso'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="auto_provision" value="1" 
                                       <?php checked($auto_provision, '1'); ?>>
                                <?php _e('Automatically create WordPress users from SSO data', 'access-platform-sso'); ?>
                            </label>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">
                            <label for="default_role"><?php _e('Default User Role', 'access-platform-sso'); ?></label>
                        </th>
                        <td>
                            <select id="default_role" name="default_role">
                                <?php
                                $roles = get_editable_roles();
                                foreach ($roles as $role_key => $role) {
                                    echo '<option value="' . esc_attr($role_key) . '" ' . 
                                         selected($default_role, $role_key, false) . '>' . 
                                         esc_html($role['name']) . '</option>';
                                }
                                ?>
                            </select>
                            <p class="description"><?php _e('Default role for new users created via SSO', 'access-platform-sso'); ?></p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row"><?php _e('Global Logout', 'access-platform-sso'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="global_logout" value="1" 
                                       <?php checked($global_logout, '1'); ?>>
                                <?php _e('Redirect to Access Platform on logout for cross-site logout', 'access-platform-sso'); ?>
                            </label>
                        </td>
                    </tr>
                </table>
                
                <?php submit_button(); ?>
            </form>
            
            <!-- Environment Setup Instructions -->
            <div style="background: #f8f9fa; padding: 20px; margin: 20px 0; border: 1px solid #dee2e6;">
                <h3><?php _e('Environment Setup', 'access-platform-sso'); ?></h3>
                <p><?php _e('Add this to your Access Platform', 'access-platform-sso'); ?> <code>.env.local</code> <?php _e('file:', 'access-platform-sso'); ?></p>
                <pre style="background: #fff; padding: 10px; border: 1px solid #ccc; overflow-x: auto;">SSO_JWT_SECRET=<?php echo esc_html($jwt_secret); ?></pre>
                
                <h3><?php _e('Test SSO Flow', 'access-platform-sso'); ?></h3>
                <ol>
                    <li><?php _e('Save these settings', 'access-platform-sso'); ?></li>
                    <li><?php _e('Test the connection above', 'access-platform-sso'); ?></li>
                    <li><?php _e('Logout of WordPress', 'access-platform-sso'); ?></li>
                    <li><?php _e('You should see "Login with Access Platform" button on login page', 'access-platform-sso'); ?></li>
                </ol>
            </div>
        </div>
        
        <script>
        function generateNewSecret() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
            let secret = '';
            for (let i = 0; i < 64; i++) {
                secret += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            document.getElementById('jwt_secret').value = secret;
            alert('<?php _e('New JWT secret generated! Make sure to save settings and update your Access Platform environment.', 'access-platform-sso'); ?>');
        }
        
        function testConnection() {
            const btn = document.getElementById('test-connection-btn');
            const indicator = document.getElementById('status-indicator');
            const statusText = document.getElementById('status-text');
            const platformUrl = document.getElementById('platform_url').value;
            
            if (!platformUrl) {
                statusText.textContent = '<?php _e('Please enter Platform URL first', 'access-platform-sso'); ?>';
                indicator.style.background = 'red';
                return;
            }
            
            btn.disabled = true;
            btn.textContent = '<?php _e('Testing...', 'access-platform-sso'); ?>';
            statusText.textContent = '<?php _e('Testing connection...', 'access-platform-sso'); ?>';
            indicator.style.background = 'orange';
            
            fetch(platformUrl + '/api/sso/health')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'healthy') {
                        statusText.textContent = '<?php _e('Connection successful!', 'access-platform-sso'); ?>';
                        indicator.style.background = 'green';
                    } else {
                        statusText.textContent = '<?php _e('Connection failed:', 'access-platform-sso'); ?> ' + (data.error || '<?php _e('Unknown error', 'access-platform-sso'); ?>');
                        indicator.style.background = 'red';
                    }
                })
                .catch(error => {
                    statusText.textContent = '<?php _e('Connection failed:', 'access-platform-sso'); ?> ' + error.message;
                    indicator.style.background = 'red';
                })
                .finally(() => {
                    btn.disabled = false;
                    btn.textContent = '<?php _e('Test Connection', 'access-platform-sso'); ?>';
                });
        }
        
        // Test connection on page load if URL is set
        document.addEventListener('DOMContentLoaded', function() {
            const platformUrl = document.getElementById('platform_url').value;
            if (platformUrl) {
                setTimeout(testConnection, 1000);
            }
        });
        </script>
        <?php
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
            'global_logout' => '1',
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
    check_ajax_referer('access_sso_nonce', 'nonce');
    
    if (!current_user_can('manage_options')) {
        wp_die(__('Insufficient permissions', 'access-platform-sso'));
    }
    
    $platform_url = sanitize_url($_POST['platform_url']);
    $jwt_secret = sanitize_text_field($_POST['jwt_secret']);
    
    // Test connection to Access Platform
    $response = wp_remote_get($platform_url . '/api/sso/health', array(
        'timeout' => 10,
        'headers' => array(
            'Content-Type' => 'application/json',
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