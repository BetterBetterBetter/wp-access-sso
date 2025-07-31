<?php
/**
 * Admin Settings Class
 * Handles WordPress admin interface for SSO configuration
 */

if (!defined('ABSPATH')) {
    exit;
}

class AccessSSO_Admin_Settings {
    
    private $options_group = 'access_sso_settings';
    private $page_slug = 'access-platform-sso';
    
    public function init() {
        add_action('admin_init', array($this, 'register_settings'));
    }
    
    public function register_settings() {
        // Register settings sections
        add_settings_section(
            'access_sso_connection',
            __('Connection Settings', 'access-platform-sso'),
            array($this, 'connection_section_callback'),
            $this->page_slug
        );
        
        add_settings_section(
            'access_sso_user_management',
            __('User Management', 'access-platform-sso'),
            array($this, 'user_management_section_callback'),
            $this->page_slug
        );
        
        add_settings_section(
            'access_sso_security',
            __('Security Settings', 'access-platform-sso'),
            array($this, 'security_section_callback'),
            $this->page_slug
        );
        
        // Connection settings
        add_settings_field(
            'access_sso_platform_url',
            __('Access Platform URL', 'access-platform-sso'),
            array($this, 'platform_url_callback'),
            $this->page_slug,
            'access_sso_connection'
        );
        
        add_settings_field(
            'access_sso_site_id',
            __('Site ID', 'access-platform-sso'),
            array($this, 'site_id_callback'),
            $this->page_slug,
            'access_sso_connection'
        );
        
        add_settings_field(
            'access_sso_jwt_secret',
            __('JWT Secret Key', 'access-platform-sso'),
            array($this, 'jwt_secret_callback'),
            $this->page_slug,
            'access_sso_connection'
        );
        
        add_settings_field(
            'access_sso_redirect_url',
            __('Post-Login Redirect URL', 'access-platform-sso'),
            array($this, 'redirect_url_callback'),
            $this->page_slug,
            'access_sso_connection'
        );
        
        // User management settings
        add_settings_field(
            'access_sso_auto_provision',
            __('Auto-Provision Users', 'access-platform-sso'),
            array($this, 'auto_provision_callback'),
            $this->page_slug,
            'access_sso_user_management'
        );
        
        add_settings_field(
            'access_sso_default_role',
            __('Default User Role', 'access-platform-sso'),
            array($this, 'default_role_callback'),
            $this->page_slug,
            'access_sso_user_management'
        );
        
        add_settings_field(
            'access_sso_role_mapping',
            __('Role Mapping', 'access-platform-sso'),
            array($this, 'role_mapping_callback'),
            $this->page_slug,
            'access_sso_user_management'
        );
        
        // Security settings
        add_settings_field(
            'access_sso_global_logout',
            __('Global Logout', 'access-platform-sso'),
            array($this, 'global_logout_callback'),
            $this->page_slug,
            'access_sso_security'
        );
        
        add_settings_field(
            'access_sso_admin_bypass',
            __('Admin Bypass', 'access-platform-sso'),
            array($this, 'admin_bypass_callback'),
            $this->page_slug,
            'access_sso_security'
        );
        
        add_settings_field(
            'access_sso_enable_logging',
            __('Enable Logging', 'access-platform-sso'),
            array($this, 'enable_logging_callback'),
            $this->page_slug,
            'access_sso_security'
        );
        
        // Register all settings
        $settings = array(
            'platform_url', 'site_id', 'jwt_secret', 'redirect_url', 'auto_provision',
            'default_role', 'role_mapping', 'global_logout', 'admin_bypass',
            'enable_logging', 'show_login_message', 'notify_suspicious_activity'
        );
        
        foreach ($settings as $setting) {
            register_setting($this->options_group, 'access_sso_' . $setting);
        }
    }
    
    public function display_page() {
        if (isset($_POST['submit'])) {
            // Handle form submission
            echo '<div class="notice notice-success"><p>' . __('Settings saved.', 'access-platform-sso') . '</p></div>';
        }
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <?php settings_errors(); ?>
            
            <!-- Connection Status -->
            <div class="access-sso-status-card">
                <h3><?php _e('Connection Status', 'access-platform-sso'); ?></h3>
                <div id="connection-status">
                    <span class="status-indicator" id="status-indicator"></span>
                    <span id="status-text"><?php _e('Not configured', 'access-platform-sso'); ?></span>
                </div>
                <button type="button" class="button" id="test-connection">
                    <?php _e('Test Connection', 'access-platform-sso'); ?>
                </button>
            </div>
            
            <!-- Statistics -->
            <?php $this->display_statistics(); ?>
            
            <!-- Settings Form -->
            <form method="post" action="options.php">
                <?php
                settings_fields($this->options_group);
                do_settings_sections($this->page_slug);
                submit_button();
                ?>
            </form>
            
            <!-- Tools Section -->
            <div class="access-sso-tools">
                <h3><?php _e('Tools', 'access-platform-sso'); ?></h3>
                
                <div class="tool-section">
                    <h4><?php _e('Session Management', 'access-platform-sso'); ?></h4>
                    <button type="button" class="button" id="cleanup-sessions">
                        <?php _e('Cleanup Expired Sessions', 'access-platform-sso'); ?>
                    </button>
                    <button type="button" class="button" id="view-active-sessions">
                        <?php _e('View Active Sessions', 'access-platform-sso'); ?>
                    </button>
                </div>
                
                <div class="tool-section">
                    <h4><?php _e('Logs', 'access-platform-sso'); ?></h4>
                    <button type="button" class="button" id="view-logs">
                        <?php _e('View SSO Logs', 'access-platform-sso'); ?>
                    </button>
                    <button type="button" class="button" id="clear-logs">
                        <?php _e('Clear Logs', 'access-platform-sso'); ?>
                    </button>
                </div>
            </div>
        </div>
        <?php
    }
    
    // Section callbacks
    public function connection_section_callback() {
        echo '<p>' . __('Configure the connection to your Access Platform.', 'access-platform-sso') . '</p>';
        
        // Show current SSO URL for testing
        $platform_url = AccessPlatformSSO::get_instance()->get_option('platform_url', '');
        $site_id = AccessPlatformSSO::get_instance()->get_option('site_id', '');
        
        if (!empty($platform_url) && !empty($site_id)) {
            $callback_url = home_url('/?access_sso_callback=1&nonce=' . wp_create_nonce('access_sso_callback'));
            $sso_url = $platform_url . '/login?site_id=' . urlencode($site_id) . '&redirect_to=' . urlencode($callback_url);
            
            echo '<div class="notice notice-info inline" style="margin: 10px 0; padding: 10px;">';
            echo '<p><strong>' . __('Test SSO URL:', 'access-platform-sso') . '</strong></p>';
            echo '<p><a href="' . esc_url($sso_url) . '" target="_blank" class="button">' . __('Test SSO Login', 'access-platform-sso') . '</a></p>';
            echo '<p class="description">' . __('Use this link to test your SSO configuration.', 'access-platform-sso') . '</p>';
            echo '</div>';
        }
    }
    
    public function user_management_section_callback() {
        echo '<p>' . __('Settings for user provisioning and role management.', 'access-platform-sso') . '</p>';
    }
    
    public function security_section_callback() {
        echo '<p>' . __('Security and logging configuration.', 'access-platform-sso') . '</p>';
    }
    
    // Field callbacks
    public function platform_url_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('platform_url', '');
        echo '<input type="url" name="access_sso_platform_url" value="' . esc_attr($value) . '" class="regular-text" required>';
        echo '<p class="description">' . __('The URL of your Access Platform (e.g., https://your-platform.com)', 'access-platform-sso') . '</p>';
    }
    
    public function site_id_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('site_id', '');
        echo '<input type="text" name="access_sso_site_id" value="' . esc_attr($value) . '" class="regular-text" readonly>';
        echo '<p class="description">' . __('Unique identifier for this WordPress site. Generated automatically.', 'access-platform-sso') . '</p>';
    }
    
    public function jwt_secret_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('jwt_secret', '');
        
        echo '<div class="jwt-secret-field-wrapper">';
        echo '<input type="password" name="access_sso_jwt_secret" id="access_sso_jwt_secret" value="' . esc_attr($value) . '" class="regular-text">';
        echo '<button type="button" class="button" id="toggle-secret-visibility">' . __('Show', 'access-platform-sso') . '</button>';
        echo '<button type="button" class="button" id="generate-secret">' . __('Generate New Secret', 'access-platform-sso') . '</button>';
        echo '</div>';
        echo '<p class="description">' . __('Secret key for JWT token validation. Must match the secret in your Access Platform.', 'access-platform-sso') . '</p>';
    }
    
    public function redirect_url_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('redirect_url', '');
        $home_url = home_url();
        
        echo '<input type="url" name="access_sso_redirect_url" value="' . esc_attr($value) . '" class="regular-text" placeholder="' . esc_attr($home_url) . '">';
        echo '<p class="description">' . __('URL to redirect users to after successful SSO login. Leave empty to redirect to homepage.', 'access-platform-sso') . '</p>';
        echo '<p class="description"><strong>' . __('Examples:', 'access-platform-sso') . '</strong></p>';
        echo '<ul class="description">';
        echo '<li><code>' . esc_html($home_url) . '</code> - Homepage</li>';
        echo '<li><code>' . esc_html($home_url . '/dashboard') . '</code> - Custom dashboard</li>';
        echo '<li><code>' . esc_html($home_url . '/my-account') . '</code> - User account page</li>';
        echo '</ul>';
    }
    
    public function auto_provision_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('auto_provision', '1');
        echo '<label><input type="checkbox" name="access_sso_auto_provision" value="1" ' . checked($value, '1', false) . '>';
        echo ' ' . __('Automatically create WordPress users from SSO data', 'access-platform-sso') . '</label>';
    }
    
    public function default_role_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('default_role', 'subscriber');
        $roles = get_editable_roles();
        
        echo '<select name="access_sso_default_role">';
        foreach ($roles as $role_key => $role) {
            echo '<option value="' . esc_attr($role_key) . '" ' . selected($value, $role_key, false) . '>';
            echo esc_html($role['name']);
            echo '</option>';
        }
        echo '</select>';
        echo '<p class="description">' . __('Default role for new users created via SSO.', 'access-platform-sso') . '</p>';
    }
    
    public function role_mapping_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('role_mapping', '');
        echo '<textarea name="access_sso_role_mapping" rows="10" cols="50" class="large-text">' . esc_textarea($value) . '</textarea>';
        echo '<p class="description">' . __('JSON mapping of Access Platform roles to WordPress roles. Example: {"premium_member": "editor", "basic_member": "subscriber"}', 'access-platform-sso') . '</p>';
    }
    
    public function global_logout_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('global_logout', '1');
        echo '<label><input type="checkbox" name="access_sso_global_logout" value="1" ' . checked($value, '1', false) . '>';
        echo ' ' . __('Redirect to Access Platform on logout for global logout', 'access-platform-sso') . '</label>';
    }
    
    public function admin_bypass_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('admin_bypass', '1');
        echo '<label><input type="checkbox" name="access_sso_admin_bypass" value="1" ' . checked($value, '1', false) . '>';
        echo ' ' . __('Allow administrators to bypass SSO and login normally', 'access-platform-sso') . '</label>';
    }
    
    public function enable_logging_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('enable_logging', '1');
        echo '<label><input type="checkbox" name="access_sso_enable_logging" value="1" ' . checked($value, '1', false) . '>';
        echo ' ' . __('Enable detailed logging of SSO events', 'access-platform-sso') . '</label>';
    }
    
    private function display_statistics() {
        $session_manager = new AccessSSO_Session_Manager();
        $stats = $session_manager->get_session_stats();
        
        ?>
        <div class="access-sso-stats">
            <h3><?php _e('SSO Statistics', 'access-platform-sso'); ?></h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number"><?php echo esc_html($stats['active_sessions']); ?></div>
                    <div class="stat-label"><?php _e('Active Sessions', 'access-platform-sso'); ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo esc_html($stats['total_sessions_today']); ?></div>
                    <div class="stat-label"><?php _e('Sessions Today', 'access-platform-sso'); ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo esc_html($stats['unique_users_today']); ?></div>
                    <div class="stat-label"><?php _e('Unique Users Today', 'access-platform-sso'); ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo esc_html($stats['expired_sessions']); ?></div>
                    <div class="stat-label"><?php _e('Expired Sessions', 'access-platform-sso'); ?></div>
                </div>
            </div>
        </div>
        <?php
    }
    
    private function test_connection() {
        $platform_url = sanitize_url($_POST['access_sso_platform_url'] ?? '');
        $jwt_secret = sanitize_text_field($_POST['access_sso_jwt_secret'] ?? '');
        
        if (empty($platform_url)) {
            add_settings_error('access_sso_settings', 'missing_url', __('Platform URL is required', 'access-platform-sso'));
            return;
        }
        
        // Test connection to Access Platform
        $test_url = trailingslashit($platform_url) . 'api/sso/health';
        $response = wp_remote_get($test_url, array(
            'timeout' => 10,
            'headers' => array(
                'User-Agent' => 'Access Platform SSO Plugin v' . ACCESS_SSO_VERSION,
            ),
        ));
        
        if (is_wp_error($response)) {
            add_settings_error(
                'access_sso_settings',
                'connection_failed',
                __('Connection failed: ', 'access-platform-sso') . $response->get_error_message()
            );
            return;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        
        if ($status_code === 200) {
            add_settings_error(
                'access_sso_settings',
                'connection_success',
                __('Connection successful!', 'access-platform-sso'),
                'success'
            );
        } else {
            add_settings_error(
                'access_sso_settings',
                'connection_failed',
                __('Connection failed with status code: ', 'access-platform-sso') . $status_code
            );
        }
    }
}