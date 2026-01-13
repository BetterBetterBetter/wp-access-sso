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
    
    public function __construct() {
        $this->auto_provision = AccessPlatformSSO::get_instance()->get_option('auto_provision', '1') === '1';
        $this->default_role = AccessPlatformSSO::get_instance()->get_option('default_role', 'subscriber');
    }
    
    /**
     * Provision or update WordPress user from SSO data
     */
    public function provision_user($user_data) {
        if (!$this->auto_provision) {
            return new WP_Error('provisioning_disabled', __('User provisioning is disabled', 'access-platform-sso'));
        }
        
        if (!isset($user_data['email']) || empty($user_data['email'])) {
            // Try common JWT claim alternatives
            if (isset($user_data['user']) && is_array($user_data['user']) && isset($user_data['user']['email'])) {
                $user_data['email'] = $user_data['user']['email'];
            } elseif (isset($user_data['preferred_username'])) {
                $user_data['email'] = $user_data['preferred_username'];
            } elseif (isset($user_data['upn'])) {
                $user_data['email'] = $user_data['upn'];
            }
        }
        if (!isset($user_data['email']) || empty($user_data['email'])) {
            return new WP_Error('missing_email', __('User email is required', 'access-platform-sso'));
        }
        
        $email = sanitize_email($user_data['email']);
        $access_platform_id = isset($user_data['id']) ? sanitize_text_field($user_data['id']) : (isset($user_data['sub']) ? sanitize_text_field($user_data['sub']) : '');
        
        // Use transient-based lock to prevent race conditions from duplicate SSO callbacks
        // This handles cases where user double-clicks SSO button or browser sends duplicate requests
        $lock_key = 'access_sso_provision_' . md5(strtolower($email));
        $lock_value = get_transient($lock_key);
        
        if ($lock_value) {
            // Another request is currently provisioning this user
            // Wait briefly and then try to find the user
            error_log('[Access SSO] Provisioning lock detected for ' . $email . ', waiting for other request to complete');
            usleep(500000); // 500ms
            
            // Try to find the user that should have been created
            $existing_user = $this->find_existing_user($email, $access_platform_id);
            if ($existing_user) {
                error_log('[Access SSO] Found user after lock wait: ' . $existing_user->ID);
                return $this->update_user($existing_user, $user_data);
            }
            // If still not found, proceed with normal flow (lock may have expired)
        }
        
        // Set a short lock (10 seconds) to prevent duplicate provisioning
        set_transient($lock_key, time(), 10);
        
        try {
            // Check if user exists by email or Access Platform ID
            $existing_user = $this->find_existing_user($email, $access_platform_id);
            
            if ($existing_user) {
                // Update existing user
                $result = $this->update_user($existing_user, $user_data);
            } else {
                // Create new user
                $result = $this->create_user($user_data);
            }
            
            // Clear the lock after successful provisioning
            delete_transient($lock_key);
            
            return $result;
        } catch (Exception $e) {
            // Clear the lock on error
            delete_transient($lock_key);
            throw $e;
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
            // Handle race condition: if email already exists, find and update that user instead
            // This can happen when:
            // 1. User double-clicks the SSO button
            // 2. Browser sends duplicate requests
            // 3. User was created by another process (sync, webhook, etc.)
            $error_code = $user_id->get_error_code();
            $error_message = $user_id->get_error_message();
            
            if ($error_code === 'existing_user_email' || 
                strpos($error_message, 'email address is already used') !== false ||
                strpos($error_message, 'email already exists') !== false) {
                
                error_log('[Access SSO] Race condition detected: email already exists, attempting to find and update user: ' . $email);
                
                // Try to find the user by email and update them instead
                $existing_user = get_user_by('email', $email);
                if ($existing_user) {
                    error_log('[Access SSO] Found existing user by email after race condition: ' . $existing_user->ID);
                    return $this->update_user($existing_user, $user_data);
                }
                
                // If still can't find by email, try by Access Platform ID
                $access_platform_id = isset($user_data['id']) ? sanitize_text_field($user_data['id']) : 
                                     (isset($user_data['sub']) ? sanitize_text_field($user_data['sub']) : '');
                if (!empty($access_platform_id)) {
                    $users = get_users(array(
                        'meta_key' => 'access_platform_id',
                        'meta_value' => $access_platform_id,
                        'number' => 1,
                    ));
                    if (!empty($users)) {
                        error_log('[Access SSO] Found existing user by Access Platform ID after race condition: ' . $users[0]->ID);
                        return $this->update_user($users[0], $user_data);
                    }
                }
                
                // Last resort: the user might exist but with different case email
                // WordPress email lookup should be case-insensitive, but let's be thorough
                global $wpdb;
                $user_id_from_db = $wpdb->get_var($wpdb->prepare(
                    "SELECT ID FROM $wpdb->users WHERE LOWER(user_email) = LOWER(%s) LIMIT 1",
                    $email
                ));
                if ($user_id_from_db) {
                    $existing_user = get_user_by('ID', $user_id_from_db);
                    if ($existing_user) {
                        error_log('[Access SSO] Found existing user by case-insensitive email query: ' . $existing_user->ID);
                        return $this->update_user($existing_user, $user_data);
                    }
                }
                
                error_log('[Access SSO] Could not recover from race condition for email: ' . $email);
            }
            
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
     * NOTE: SSO only handles authentication - we do NOT modify WordPress roles here.
     * Role management should be handled by WordPress admins, not SSO.
     */
    private function update_user($user, $user_data) {
        // Update Access Platform metadata (for tracking SSO logins)
        $this->update_user_metadata($user->ID, $user_data);
        
        // Log user update
        $this->log_user_action('updated', $user->ID, $user_data);
        
        return $user;
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
     * Map Access Platform role to WordPress role (for NEW users only)
     * Returns the default role configured in plugin settings
     */
    private function map_user_role($user_data) {
        // For new users, just use the default role from settings
        // SSO should not manage WordPress roles - that's for WP admins to handle
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