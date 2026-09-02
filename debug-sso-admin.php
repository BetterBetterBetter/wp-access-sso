<?php
/**
 * Read-only debug helper for SSO Admin Settings.
 *
 * This file intentionally reports configuration presence only. It must never
 * render secret values or mutate SSO configuration.
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('admin_footer', function() {
    if (!current_user_can('manage_options') || !isset($_GET['page']) || 'access-platform-sso' !== $_GET['page']) {
        return;
    }

    $checks = array(
        'Platform URL configured' => '' !== get_option('access_sso_platform_url', ''),
        'Canonical site ID configured' => '' !== get_option('access_sso_site_id', ''),
        'JWT secret configured' => '' !== get_option('access_sso_jwt_secret', ''),
        'Admin settings class loaded' => class_exists('AccessSSO_Admin_Settings'),
        'Main plugin class loaded' => class_exists('AccessPlatformSSO'),
    );

    echo '<div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccc;">';
    echo '<h3>' . esc_html__('SSO Debug Information', 'access-platform-sso') . '</h3>';
    echo '<p>' . esc_html__('Configuration values are intentionally not displayed.', 'access-platform-sso') . '</p>';

    foreach ($checks as $label => $passed) {
        echo '<p><strong>' . esc_html($label) . ':</strong> ' . esc_html($passed ? 'Yes' : 'No') . '</p>';
    }

    echo '</div>';
});
