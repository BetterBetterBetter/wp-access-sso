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
        // Register only the connection settings section
        add_settings_section(
            'access_sso_connection',
            __('Connection Settings', 'access-platform-sso'),
            array($this, 'connection_section_callback'),
            $this->page_slug
        );

        // Connection settings fields
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
            'access_sso_callback_path',
            __('Callback Path', 'access-platform-sso'),
            array($this, 'callback_path_callback'),
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

        // Login Form Detector section
        add_settings_section(
            'access_sso_detector',
            __('Login Form Detection', 'access-platform-sso'),
            array($this, 'detector_section_callback'),
            $this->page_slug
        );

        add_settings_field(
            'access_sso_button_text',
            __('Button Text', 'access-platform-sso'),
            array($this, 'button_text_callback'),
            $this->page_slug,
            'access_sso_detector'
        );

        add_settings_field(
            'access_sso_enabled_form_types',
            __('Enabled Form Types', 'access-platform-sso'),
            array($this, 'enabled_form_types_callback'),
            $this->page_slug,
            'access_sso_detector'
        );

        add_settings_field(
            'access_sso_excluded_routes',
            __('Excluded Pages/Routes', 'access-platform-sso'),
            array($this, 'excluded_routes_callback'),
            $this->page_slug,
            'access_sso_detector'
        );

        add_settings_field(
            'access_sso_detector_disabled',
            __('Disable Auto-Detection', 'access-platform-sso'),
            array($this, 'detector_disabled_callback'),
            $this->page_slug,
            'access_sso_detector'
        );

        // Register all options
        $settings = array(
            'platform_url', 'site_id', 'jwt_secret', 'callback_path', 'redirect_url',
            'button_text', 'divider_text', 'enabled_form_types', 'excluded_routes', 'detector_disabled'
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
            
            
            
            <!-- Settings Form -->
            <form method="post" action="options.php">
                <?php
                settings_fields($this->options_group);
                do_settings_sections($this->page_slug);
                submit_button();
                ?>
            </form>
            
            
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
            $callback_url = AccessPlatformSSO::get_instance()->get_callback_url();
            $sso_url = $platform_url . '/login?site_id=' . urlencode($site_id) . '&redirect_to=' . urlencode($callback_url);
            
            echo '<div class="notice notice-info inline" style="margin: 10px 0; padding: 10px;">';
            echo '<p><strong>' . __('Test SSO URL:', 'access-platform-sso') . '</strong></p>';
            echo '<p><a href="' . esc_url($sso_url) . '" target="_blank" class="button">' . __('Test SSO Login', 'access-platform-sso') . '</a></p>';
            echo '<p class="description">' . __('Use this link to test your SSO configuration.', 'access-platform-sso') . '</p>';
            echo '</div>';
        }
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
    
    public function callback_path_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('callback_path', '');
        $home_url = home_url();
        
        echo '<input type="text" name="access_sso_callback_path" value="' . esc_attr($value) . '" class="regular-text" placeholder="/">';
        echo '<p class="description">' . __('Path where SSO callback is processed. Use this if your homepage doesn\'t run WordPress code.', 'access-platform-sso') . '</p>';
        echo '<p class="description"><strong>' . __('Important:', 'access-platform-sso') . '</strong> ' . __('Leave empty to use the homepage (/). If your homepage is static or doesn\'t run WordPress, enter a page path that does (e.g., welcome or members).', 'access-platform-sso') . '</p>';
        
        // Show current callback URL
        $callback_url = AccessPlatformSSO::get_instance()->get_callback_url();
        echo '<p class="description"><strong>' . __('Current Callback URL:', 'access-platform-sso') . '</strong> <code>' . esc_html($callback_url) . '</code></p>';
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
    
    // Login Form Detector callbacks
    
    public function detector_section_callback() {
        echo '<p>' . __('Automatically detect and add SSO login buttons to login forms across your site.', 'access-platform-sso') . '</p>';
        echo '<p class="description">' . __('The detector finds login forms from MemberPress, LearnDash, WooCommerce, and other plugins, then automatically adds a "Login with Access Platform" button.', 'access-platform-sso') . '</p>';
    }
    
    public function button_text_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('button_text', 'Login with Access Platform');
        
        echo '<input type="text" name="access_sso_button_text" value="' . esc_attr($value) . '" class="regular-text">';
        echo '<p class="description">' . __('Text displayed on the SSO login button.', 'access-platform-sso') . '</p>';
    }
    
    public function enabled_form_types_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('enabled_form_types', '');
        
        $all_types = array(
            'wordpress' => 'WordPress Core Login',
            'memberpress' => 'MemberPress',
            'learndash' => 'LearnDash',
            'woocommerce' => 'WooCommerce',
            'ultimatemember' => 'Ultimate Member',
            'buddypress' => 'BuddyPress / BuddyBoss',
            'generic' => 'Generic Login Forms (catch-all)'
        );
        
        // Parse current value
        $enabled = array();
        if (empty($value)) {
            $enabled = array_keys($all_types); // All enabled by default
        } elseif (is_string($value)) {
            if (strpos($value, '[') === 0) {
                $enabled = json_decode($value, true) ?: array();
            } else {
                $enabled = array_map('trim', explode(',', $value));
            }
        }
        
        echo '<fieldset>';
        foreach ($all_types as $type => $label) {
            $checked = in_array($type, $enabled) ? 'checked' : '';
            echo '<label style="display: block; margin-bottom: 5px;">';
            echo '<input type="checkbox" name="access_sso_form_types[]" value="' . esc_attr($type) . '" ' . $checked . '> ';
            echo esc_html($label);
            echo '</label>';
        }
        echo '</fieldset>';
        echo '<input type="hidden" name="access_sso_enabled_form_types" id="access_sso_enabled_form_types" value="' . esc_attr($value) . '">';
        echo '<p class="description">' . __('Select which login form types to detect and enhance with SSO buttons.', 'access-platform-sso') . '</p>';
        
        // JavaScript to update the hidden field
        ?>
        <script>
        (function() {
            function updateFormTypes() {
                var checkboxes = document.querySelectorAll('input[name="access_sso_form_types[]"]:checked');
                var values = Array.from(checkboxes).map(function(cb) { return cb.value; });
                document.getElementById('access_sso_enabled_form_types').value = JSON.stringify(values);
            }
            document.querySelectorAll('input[name="access_sso_form_types[]"]').forEach(function(cb) {
                cb.addEventListener('change', updateFormTypes);
            });
            updateFormTypes(); // Initial update
        })();
        </script>
        <?php
    }
    
    public function excluded_routes_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('excluded_routes', '');
        
        echo '<textarea name="access_sso_excluded_routes" rows="5" class="large-text code" placeholder="/checkout&#10;/cart&#10;/my-account/edit-*">' . esc_textarea($value) . '</textarea>';
        echo '<p class="description">' . __('Enter page paths to exclude from SSO button injection (one per line).', 'access-platform-sso') . '</p>';
        echo '<p class="description"><strong>' . __('Supported formats:', 'access-platform-sso') . '</strong></p>';
        echo '<ul class="description" style="list-style: disc; margin-left: 20px;">';
        echo '<li><code>/login</code> - ' . __('Exact path match', 'access-platform-sso') . '</li>';
        echo '<li><code>/checkout*</code> - ' . __('Prefix match (any path starting with /checkout)', 'access-platform-sso') . '</li>';
        echo '<li><code>checkout</code> - ' . __('Contains match (any URL containing "checkout")', 'access-platform-sso') . '</li>';
        echo '<li><code>/\\/order-\\d+\\//</code> - ' . __('Regex pattern (wrapped in slashes)', 'access-platform-sso') . '</li>';
        echo '</ul>';
    }
    
    public function detector_disabled_callback() {
        $value = AccessPlatformSSO::get_instance()->get_option('detector_disabled', '0');
        
        echo '<label>';
        echo '<input type="checkbox" name="access_sso_detector_disabled" value="1" ' . checked($value, '1', false) . '>';
        echo ' ' . __('Disable automatic login form detection', 'access-platform-sso');
        echo '</label>';
        echo '<p class="description">' . __('Check this to disable the automatic detection and injection of SSO buttons. SSO will only appear on the WordPress login page.', 'access-platform-sso') . '</p>';
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