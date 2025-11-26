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
        
        // Provision MemberPress membership if applicable
        $this->provision_memberpress_membership($user_id, $user_data);
        
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
        
        // Provision MemberPress membership if applicable
        $this->provision_memberpress_membership($user->ID, $user_data);
        
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
    
    /**
     * Provision MemberPress membership based on Access Platform subscription data
     * 
     * NOTE: This is a FALLBACK mechanism. The primary way memberships are created
     * is via the Access Platform API calling MemberPress directly when a Stripe
     * subscription is created. This fallback handles edge cases where:
     * - The API provisioning failed
     * - The user was migrated without API provisioning
     * - Manual SSO testing without Stripe checkout
     * 
     * Race condition handling: This method checks for existing memberships before
     * creating new ones. If the API provisioning completes first, this will detect
     * it and skip duplicate creation.
     */
    private function provision_memberpress_membership($user_id, $user_data) {
        // Check if MemberPress is active
        if (!class_exists('MeprTransaction') || !class_exists('MeprUser')) {
            error_log('[Access SSO] MemberPress not active, skipping membership provisioning');
            return false;
        }
        
        // Check subscription status - only provision if active
        $subscription_status = isset($user_data['subscription_status']) ? $user_data['subscription_status'] : '';
        if (strtolower($subscription_status) !== 'active') {
            error_log('[Access SSO] Subscription not active (' . $subscription_status . '), skipping membership provisioning');
            return false;
        }
        
        // Get MemberPress membership ID from plugin settings or JWT
        $membership_id = $this->get_memberpress_membership_id($user_data);
        
        if (!$membership_id) {
            error_log('[Access SSO] No MemberPress membership ID configured or found in JWT');
            return false;
        }
        
        // Verify membership exists
        $membership = new \MeprProduct($membership_id);
        if (!$membership->ID) {
            error_log('[Access SSO] MemberPress membership ID ' . $membership_id . ' does not exist');
            return false;
        }
        
        // Check if user already has an active subscription to this membership
        // This catches memberships created by the Access API
        $mepr_user = new \MeprUser($user_id);
        $active_subs = $mepr_user->active_product_subscriptions('ids');
        
        if (in_array($membership_id, $active_subs)) {
            error_log('[Access SSO] User ' . $user_id . ' already has active subscription to membership ' . $membership_id . ' (likely provisioned by API)');
            return true; // Already has access - API provisioning succeeded
        }
        
        // Additional race condition check: Look for any recent transactions for this user/membership
        // This catches cases where API provisioning is in progress or just completed
        if ($this->has_recent_membership_transaction($user_id, $membership_id)) {
            error_log('[Access SSO] User ' . $user_id . ' has recent transaction for membership ' . $membership_id . ', skipping duplicate creation');
            return true;
        }
        
        // Use transient lock to prevent duplicate creation during race condition
        $lock_key = 'access_sso_provision_' . $user_id . '_' . $membership_id;
        if (get_transient($lock_key)) {
            error_log('[Access SSO] Provisioning lock active for user ' . $user_id . ', membership ' . $membership_id);
            return true; // Another process is handling this
        }
        
        // Set lock for 30 seconds
        set_transient($lock_key, true, 30);
        
        // Double-check after acquiring lock (another process may have completed)
        $active_subs = $mepr_user->active_product_subscriptions('ids');
        if (in_array($membership_id, $active_subs)) {
            delete_transient($lock_key);
            error_log('[Access SSO] User ' . $user_id . ' now has active subscription (created during lock wait)');
            return true;
        }
        
        // Create a MemberPress transaction to grant access
        $txn = new \MeprTransaction();
        $txn->user_id = $user_id;
        $txn->product_id = $membership_id;
        $txn->trans_num = 'access_sso_fallback_' . uniqid();
        $txn->txn_type = 'payment';
        $txn->gateway = 'manual';
        $txn->status = 'complete';
        $txn->created_at = current_time('mysql');
        $txn->expires_at = $this->calculate_expiration($user_data, $membership);
        $txn->total = 0; // SSO-provisioned, no payment
        $txn->tax_amount = 0;
        $txn->tax_rate = 0;
        
        // Store the transaction
        $txn->store();
        
        // Release lock
        delete_transient($lock_key);
        
        if ($txn->id) {
            error_log('[Access SSO] Created MemberPress transaction ' . $txn->id . ' for user ' . $user_id . ' on membership ' . $membership_id . ' (fallback provisioning)');
            
            // Fire MemberPress hooks so other plugins can react
            do_action('mepr-txn-status-complete', $txn);
            do_action('mepr-event-transaction-completed', $txn);
            
            return true;
        }
        
        error_log('[Access SSO] Failed to create MemberPress transaction for user ' . $user_id);
        return false;
    }
    
    /**
     * Check if user has a recent MemberPress transaction for the given membership
     * Used to detect if API provisioning just completed (race condition protection)
     */
    private function has_recent_membership_transaction($user_id, $membership_id) {
        global $wpdb;
        
        $table = $wpdb->prefix . 'mepr_transactions';
        
        // Look for transactions created in the last 5 minutes
        $recent_cutoff = date('Y-m-d H:i:s', strtotime('-5 minutes'));
        
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} 
             WHERE user_id = %d 
             AND product_id = %d 
             AND status IN ('complete', 'confirmed') 
             AND created_at >= %s",
            $user_id,
            $membership_id,
            $recent_cutoff
        ));
        
        return $count > 0;
    }
    
    /**
     * Get MemberPress membership ID from settings or JWT data
     */
    private function get_memberpress_membership_id($user_data) {
        // First check JWT for product/membership info
        if (isset($user_data['site']) && isset($user_data['site']['membership_id'])) {
            return intval($user_data['site']['membership_id']);
        }
        
        if (isset($user_data['membership_id'])) {
            return intval($user_data['membership_id']);
        }
        
        if (isset($user_data['product_id'])) {
            return intval($user_data['product_id']);
        }
        
        // Fall back to plugin setting
        $default_membership = AccessPlatformSSO::get_instance()->get_option('memberpress_membership_id', '');
        if (!empty($default_membership)) {
            return intval($default_membership);
        }
        
        return null;
    }
    
    /**
     * Calculate membership expiration date
     */
    private function calculate_expiration($user_data, $membership) {
        // Check if JWT includes expiration info
        if (isset($user_data['subscription_expires']) && !empty($user_data['subscription_expires'])) {
            return date('Y-m-d H:i:s', strtotime($user_data['subscription_expires']));
        }
        
        if (isset($user_data['current_period_end']) && !empty($user_data['current_period_end'])) {
            return date('Y-m-d H:i:s', strtotime($user_data['current_period_end']));
        }
        
        // Use membership's default period
        if ($membership->period_type === 'lifetime') {
            return '0000-00-00 00:00:00'; // Lifetime = no expiration
        }
        
        // Default to 1 year if no info available
        return date('Y-m-d H:i:s', strtotime('+1 year'));
    }
}