<?php
/**
 * Debug script for SSO Admin Settings
 * Add this to your WordPress theme's functions.php temporarily to debug
 */

// Add debug info to admin footer
add_action('admin_footer', function() {
    if (isset($_GET['page']) && $_GET['page'] === 'access-platform-sso') {
        echo '<script>console.log("SSO Admin Page Loaded");</script>';
        
        // Check if settings are registered
        global $wp_settings_sections, $wp_settings_fields;
        echo '<script>';
        echo 'console.log("Settings sections:", ' . json_encode($wp_settings_sections) . ');';
        echo 'console.log("Settings fields:", ' . json_encode($wp_settings_fields) . ');';
        echo '</script>';
        
        // Check if options exist
        $options = array(
            'platform_url',
            'site_id', 
            'jwt_secret',
            'auto_provision',
            'default_role'
        );
        
        echo '<div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccc;">';
        echo '<h3>Debug Information</h3>';
        
        foreach ($options as $option) {
            $value = get_option('access_sso_' . $option, 'NOT SET');
            echo "<p><strong>access_sso_{$option}:</strong> " . esc_html($value) . "</p>";
        }
        
        // Check if admin settings class exists
        if (class_exists('AccessSSO_Admin_Settings')) {
            echo '<p><strong>AccessSSO_Admin_Settings:</strong> ✅ Class exists</p>';
        } else {
            echo '<p><strong>AccessSSO_Admin_Settings:</strong> ❌ Class not found</p>';
        }
        
        // Check if main plugin class exists
        if (class_exists('AccessPlatformSSO')) {
            echo '<p><strong>AccessPlatformSSO:</strong> ✅ Class exists</p>';
            $instance = AccessPlatformSSO::get_instance();
            echo '<p><strong>Plugin Instance:</strong> ✅ Available</p>';
        } else {
            echo '<p><strong>AccessPlatformSSO:</strong> ❌ Class not found</p>';
        }
        
        echo '</div>';
    }
});

// Add admin notice to show that debug is active
add_action('admin_notices', function() {
    if (isset($_GET['page']) && $_GET['page'] === 'access-platform-sso') {
        echo '<div class="notice notice-info"><p><strong>Debug Mode Active:</strong> Check the bottom of this page for debug information.</p></div>';
    }
});

// Force regenerate non-identity default options
add_action('admin_init', function() {
    if (isset($_GET['page']) && $_GET['page'] === 'access-platform-sso' && isset($_GET['regenerate_options'])) {
        $default_options = array(
            'platform_url' => '',
            'site_id_verified' => '0',
            'jwt_secret' => wp_generate_password(64, false),
            'auto_provision' => '1',
            'global_logout' => '1',
            'show_login_message' => '1',
            'default_role' => 'subscriber',
            'admin_bypass' => '1',
        );
        
        foreach ($default_options as $key => $value) {
            update_option('access_sso_' . $key, $value);
        }
        
        if (false === get_option('access_sso_site_id')) {
            update_option('access_sso_site_id', '');
        }

        wp_redirect(admin_url('options-general.php?page=access-platform-sso&options_generated=1'));
        exit;
    }
    
    if (isset($_GET['options_generated'])) {
        add_action('admin_notices', function() {
            echo '<div class="notice notice-success"><p>Default options regenerated! Please refresh the page.</p></div>';
        });
    }
});
?>