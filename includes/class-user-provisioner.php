<?php
/**
 * User Provisioner Class
 * Handles WordPress user creation and synchronization
 */

if (!defined('ABSPATH')) {
    exit;
}

class AccessSSO_User_Provisioner {
    
    private $auto_provision;
    private $default_role;
    private $role_mapping;
    
    public function __construct() {
        $this->auto_provision = AccessPlatformSSO::get_instance()->get_option('auto_provision', '1') === '1';
        $this->default_role = AccessPlatformSSO::get_instance()->get_option('default_role', 'subscriber');
        $this->role_mapping = $this->get_role_mapping();
    }
    
    /**
     * Provision or update WordPress user from SSO data
     */
    public function provision_user($user_data) {
        if (!$this->auto_provision) {
            return new WP_Error('provisioning_disabled', __('User provisioning is disabled', 'access-platform-sso'));
        }
        
        if (!isset($user_data['email']) || empty($user_data['email'])) {
            return new WP_Error('missing_email', __('User email is required', 'access-platform-sso'));
        }
        
        $email = sanitize_email($user_data['email']);
        $access_platform_id = isset($user_data['id']) ? sanitize_text_field($user_data['id']) : '';
        
        // Check if user exists by email or Access Platform ID
        $existing_user = $this->find_existing_user($email, $access_platform_id);
        
        if ($existing_user) {
            // Update existing user
            return $this->update_user($existing_user, $user_data);
        } else {
            // Create new user
            return $this->create_user($user_data);
        }
    }
    
    /**
     * Find existing user by email or Access Platform ID
     */
    private function find_existing_user($email, $access_platform_id) {
        // First try by email
        $user = get_user_by('email', $email);
        if ($user) {
            return $user;
        }
        
        // Then try by Access Platform ID
        if (!empty($access_platform_id)) {
            $users = get_users(array(
                'meta_key' => 'access_platform_id',
                'meta_value' => $access_platform_id,
                'number' => 1,
            ));
            
            if (!empty($users)) {
                return $users[0];
            }
        }
        
        return false;
    }
    
    /**
     * Create new WordPress user
     */
    private function create_user($user_data) {
        $email = sanitize_email($user_data['email']);
        $username = $this->generate_username($email, $user_data);
        $display_name = $this->get_display_name($user_data);
        $role = $this->map_user_role($user_data);
        
        // Generate random password
        $password = wp_generate_password(20, false);
        
        $user_id = wp_create_user($username, $password, $email);
        
        if (is_wp_error($user_id)) {
            return $user_id;
        }
        
        // Update user data
        wp_update_user(array(
            'ID' => $user_id,
            'display_name' => $display_name,
            'first_name' => isset($user_data['first_name']) ? sanitize_text_field($user_data['first_name']) : '',
            'last_name' => isset($user_data['last_name']) ? sanitize_text_field($user_data['last_name']) : '',
            'role' => $role,
        ));
        
        // Set Access Platform metadata
        $this->update_user_metadata($user_id, $user_data);
        
        // Log user creation
        $this->log_user_action('created', $user_id, $user_data);
        
        return get_user_by('ID', $user_id);
    }
    
    /**
     * Update existing WordPress user
     */
    private function update_user($user, $user_data) {
        $role = $this->map_user_role($user_data);
        $display_name = $this->get_display_name($user_data);
        
        // Update user data
        wp_update_user(array(
            'ID' => $user->ID,
            'display_name' => $display_name,
            'first_name' => isset($user_data['first_name']) ? sanitize_text_field($user_data['first_name']) : '',
            'last_name' => isset($user_data['last_name']) ? sanitize_text_field($user_data['last_name']) : '',
        ));
        
        // Update role if different
        if (!in_array($role, $user->roles)) {
            $user->set_role($role);
        }
        
        // Update Access Platform metadata
        $this->update_user_metadata($user->ID, $user_data);
        
        // Log user update
        $this->log_user_action('updated', $user->ID, $user_data);
        
        return get_user_by('ID', $user->ID);
    }
    
    /**
     * Generate unique username from email and user data
     */
    private function generate_username($email, $user_data) {
        // Try email prefix first
        $username = sanitize_user(substr($email, 0, strpos($email, '@')));
        
        // If not unique, try with first name
        if (username_exists($username) && isset($user_data['first_name'])) {
            $username = sanitize_user($user_data['first_name'] . '_' . substr($email, 0, strpos($email, '@')));
        }
        
        // If still not unique, add random suffix
        $counter = 1;
        $base_username = $username;
        while (username_exists($username)) {
            $username = $base_username . '_' . $counter;
            $counter++;
        }
        
        return $username;
    }
    
    /**
     * Get display name from user data
     */
    private function get_display_name($user_data) {
        if (isset($user_data['name']) && !empty($user_data['name'])) {
            return sanitize_text_field($user_data['name']);
        }
        
        $first_name = isset($user_data['first_name']) ? sanitize_text_field($user_data['first_name']) : '';
        $last_name = isset($user_data['last_name']) ? sanitize_text_field($user_data['last_name']) : '';
        
        if (!empty($first_name) && !empty($last_name)) {
            return $first_name . ' ' . $last_name;
        }
        
        if (!empty($first_name)) {
            return $first_name;
        }
        
        return sanitize_email($user_data['email']);
    }
    
    /**
     * Map Access Platform role to WordPress role
     */
    private function map_user_role($user_data) {
        // Check for explicit role mapping
        if (isset($user_data['role']) && !empty($user_data['role'])) {
            $access_role = sanitize_text_field($user_data['role']);
            
            if (isset($this->role_mapping[$access_role])) {
                $wp_role = $this->role_mapping[$access_role];
                
                // Verify role exists in WordPress
                if (get_role($wp_role)) {
                    return $wp_role;
                }
            }
        }
        
        // Check subscription status for automatic role mapping
        if (isset($user_data['subscription_status'])) {
            switch ($user_data['subscription_status']) {
                case 'ACTIVE':
                    return isset($this->role_mapping['active_subscriber']) ? 
                           $this->role_mapping['active_subscriber'] : 'subscriber';
                case 'EXPIRED':
                case 'CANCELED':
                    return isset($this->role_mapping['inactive_subscriber']) ? 
                           $this->role_mapping['inactive_subscriber'] : 'subscriber';
            }
        }
        
        // Check admin status
        if (isset($user_data['is_admin']) && $user_data['is_admin']) {
            return 'administrator';
        }
        
        // Default role
        return $this->default_role;
    }
    
    /**
     * Update user metadata from Access Platform
     */
    private function update_user_metadata($user_id, $user_data) {
        // Store Access Platform ID
        if (isset($user_data['id'])) {
            update_user_meta($user_id, 'access_platform_id', sanitize_text_field($user_data['id']));
        }
        
        // Store subscription information
        if (isset($user_data['subscription_status'])) {
            update_user_meta($user_id, 'access_subscription_status', sanitize_text_field($user_data['subscription_status']));
        }
        
        if (isset($user_data['subscription_expires'])) {
            update_user_meta($user_id, 'access_subscription_expires', sanitize_text_field($user_data['subscription_expires']));
        }
        
        // Store additional metadata
        if (isset($user_data['metadata']) && is_array($user_data['metadata'])) {
            foreach ($user_data['metadata'] as $key => $value) {
                update_user_meta($user_id, 'access_' . sanitize_key($key), sanitize_text_field($value));
            }
        }
        
        // Update last SSO login
        update_user_meta($user_id, 'access_last_sso_login', current_time('mysql'));
        
        // Update sync timestamp
        update_user_meta($user_id, 'access_last_sync', current_time('mysql'));
    }
    
    /**
     * Get role mapping configuration
     */
    private function get_role_mapping() {
        $default_mapping = array(
            'admin' => 'administrator',
            'editor' => 'editor',
            'author' => 'author',
            'contributor' => 'contributor',
            'subscriber' => 'subscriber',
            'active_subscriber' => 'subscriber',
            'inactive_subscriber' => 'subscriber',
        );
        
        $custom_mapping = AccessPlatformSSO::get_instance()->get_option('role_mapping', '');
        
        if (!empty($custom_mapping)) {
            $parsed_mapping = json_decode($custom_mapping, true);
            if (is_array($parsed_mapping)) {
                return array_merge($default_mapping, $parsed_mapping);
            }
        }
        
        return $default_mapping;
    }
    
    /**
     * Bulk provision users (for admin tools)
     */
    public function bulk_provision($users_data) {
        if (!current_user_can('manage_options')) {
            return new WP_Error('insufficient_permissions', __('Insufficient permissions', 'access-platform-sso'));
        }
        
        $results = array(
            'success' => 0,
            'failed' => 0,
            'errors' => array(),
        );
        
        foreach ($users_data as $user_data) {
            $result = $this->provision_user($user_data);
            
            if (is_wp_error($result)) {
                $results['failed']++;
                $results['errors'][] = $result->get_error_message();
            } else {
                $results['success']++;
            }
        }
        
        return $results;
    }
    
    /**
     * Log user provisioning actions
     */
    private function log_user_action($action, $user_id, $user_data) {
        if (AccessPlatformSSO::get_instance()->get_option('enable_logging', '1') === '1') {
            $log_entry = array(
                'timestamp' => current_time('mysql'),
                'action' => $action,
                'user_id' => $user_id,
                'access_platform_id' => isset($user_data['id']) ? $user_data['id'] : '',
                'email' => isset($user_data['email']) ? $user_data['email'] : '',
                'ip_address' => $this->get_client_ip(),
            );
            
            $logs = get_option('access_sso_user_logs', array());
            $logs[] = $log_entry;
            
            // Keep only last 1000 entries
            if (count($logs) > 1000) {
                $logs = array_slice($logs, -1000);
            }
            
            update_option('access_sso_user_logs', $logs);
        }
    }
    
    /**
     * Get client IP address
     */
    private function get_client_ip() {
        $ip_keys = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR');
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    }
}