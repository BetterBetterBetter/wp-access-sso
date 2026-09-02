<?php
/**
 * Session Manager Class
 * Handles SSO session tracking and management
 */

if (!defined('ABSPATH')) {
    exit;
}

class AccessSSO_Session_Manager {
    const STORAGE_VERSION = 2;
    const TOKEN_HASH_PREFIX = 'sha256:';
    const PRIVACY_HASH_PREFIX = 'h:';
    
    private $table_name;
    
    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'access_sso_sessions';
        self::migrate_legacy_storage();
    }
    
    /**
     * Create SSO session after successful authentication
     */
    public function create_sso_session($user_id, $user_data) {
        global $wpdb;
        
        $session_token = $this->generate_session_token();
        $stored_session_token = $this->hash_session_token($session_token);
        $access_platform_id = '';
        if (is_array($user_data)) {
            if (isset($user_data['user']) && is_array($user_data['user']) && isset($user_data['user']['id'])) {
                $access_platform_id = $user_data['user']['id'];
            } elseif (isset($user_data['id'])) {
                $access_platform_id = $user_data['id'];
            } elseif (isset($user_data['sub'])) { // standard JWT subject claim
                $access_platform_id = $user_data['sub'];
            }
        }
        
        $session_data = array(
            'user_id' => $user_id,
            'session_token' => $stored_session_token,
            'access_platform_id' => $this->privacy_hash($access_platform_id),
            'created_at' => current_time('mysql'),
            'expires_at' => date('Y-m-d H:i:s', time() + (24 * 60 * 60)), // 24 hours
            'last_activity' => current_time('mysql'),
            'ip_address' => $this->privacy_hash($this->get_client_ip()),
            'user_agent' => $this->privacy_hash(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''),
            'is_active' => 1,
        );
        
        $result = $wpdb->insert($this->table_name, $session_data);
        
        if ($result === false) {
            error_log('Access SSO: Failed to create session for user ' . $user_id);
            return false;
        }
        
        // Clean up old sessions for this user
        $this->cleanup_user_sessions($user_id);
        
        // Store session token in user meta for quick access
        update_user_meta($user_id, 'access_sso_session_token', $stored_session_token);
        
        return $session_token;
    }
    
    /**
     * Track regular WordPress login
     */
    public function track_wp_login($user_id) {
        // Update last activity if SSO session exists
        $session_token = get_user_meta($user_id, 'access_sso_session_token', true);
        
        if (!empty($session_token)) {
            $this->update_session_activity($session_token);
        }
    }
    
    /**
     * Handle user logout
     */
    public function handle_logout($user_id) {
        global $wpdb;
        
        // Deactivate all sessions for this user
        $wpdb->update(
            $this->table_name,
            array('is_active' => 0),
            array('user_id' => $user_id),
            array('%d'),
            array('%d')
        );
        
        // Remove session token from user meta
        delete_user_meta($user_id, 'access_sso_session_token');
        
        // Log logout event
        $this->log_session_event('logout', $user_id);
    }
    
    /**
     * Update session activity timestamp
     */
    public function update_session_activity($session_token) {
        global $wpdb;
        $stored_session_token = $this->hash_session_token($session_token);
        
        $wpdb->update(
            $this->table_name,
            array('last_activity' => current_time('mysql')),
            array('session_token' => $stored_session_token, 'is_active' => 1),
            array('%s'),
            array('%s', '%d')
        );
    }
    
    /**
     * Get active session for user
     */
    public function get_user_session($user_id) {
        global $wpdb;
        
        $session = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table_name} 
             WHERE user_id = %d AND is_active = 1 
             ORDER BY created_at DESC LIMIT 1",
            $user_id
        ));
        
        return $session;
    }
    
    /**
     * Validate session token
     */
    public function validate_session($session_token) {
        global $wpdb;
        $stored_session_token = $this->hash_session_token($session_token);
        
        $session = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table_name} 
             WHERE session_token = %s AND is_active = 1 
             AND expires_at > NOW()",
            $stored_session_token
        ));
        
        if ($session) {
            // Update last activity
            $this->update_session_activity($stored_session_token);
            return $session;
        }
        
        return false;
    }
    
    /**
     * Cleanup expired sessions
     */
    public function cleanup_expired_sessions() {
        global $wpdb;
        
        // Mark expired sessions as inactive
        $wpdb->query("UPDATE {$this->table_name} SET is_active = 0 WHERE expires_at < NOW()");
        
        // Delete old inactive sessions (older than 30 days)
        $wpdb->query(
            "DELETE FROM {$this->table_name} WHERE is_active = 0 AND created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)"
        );
    }
    
    /**
     * Cleanup old sessions for a specific user (keep only latest 5)
     */
    private function cleanup_user_sessions($user_id, $keep_count = 5) {
        global $wpdb;
        
        // Get session IDs to keep
        $keep_sessions = $wpdb->get_col($wpdb->prepare(
            "SELECT id FROM {$this->table_name} 
             WHERE user_id = %d 
             ORDER BY created_at DESC 
             LIMIT %d",
            $user_id,
            $keep_count
        ));
        
        if (!empty($keep_sessions)) {
            $placeholders = implode(',', array_fill(0, count($keep_sessions), '%d'));
            
            // Delete old sessions
            $wpdb->query($wpdb->prepare(
                "DELETE FROM {$this->table_name} 
                 WHERE user_id = %d AND id NOT IN ($placeholders)",
                array_merge(array($user_id), $keep_sessions)
            ));
        }
    }
    
    /**
     * Generate secure session token
     */
    private function generate_session_token() {
        return 'sso_' . wp_generate_password(32, false);
    }

    private function hash_session_token($session_token) {
        $session_token = (string) $session_token;
        if (self::is_hashed_session_token($session_token)) {
            return $session_token;
        }

        return self::TOKEN_HASH_PREFIX . hash('sha256', $session_token);
    }

    private function privacy_hash($value) {
        return self::privacy_hash_value($value);
    }

    private static function privacy_hash_value($value) {
        $value = (string) $value;
        if (empty($value) || self::is_privacy_hash($value)) {
            return $value;
        }

        $digest = hash_hmac('sha256', $value, wp_salt('auth'), true);
        return self::PRIVACY_HASH_PREFIX . rtrim(strtr(base64_encode($digest), '+/', '-_'), '=');
    }

    private static function hash_session_token_value($session_token) {
        $session_token = (string) $session_token;
        if (self::is_hashed_session_token($session_token)) {
            return $session_token;
        }

        return self::TOKEN_HASH_PREFIX . hash('sha256', $session_token);
    }

    private static function is_hashed_session_token($value) {
        return (bool) preg_match('/^sha256:[a-f0-9]{64}$/', (string) $value);
    }

    private static function is_privacy_hash($value) {
        return (bool) preg_match('/^h:[A-Za-z0-9_-]{43}$/', (string) $value);
    }

    /**
     * Incrementally hash tokens and request fingerprints written by older releases.
     */
    public static function migrate_legacy_storage() {
        if ((int) get_option('access_sso_session_storage_version', 0) >= self::STORAGE_VERSION) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'access_sso_sessions';
        $table_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table_name));
        if ($table_exists !== $table_name) {
            return;
        }

        $rows = $wpdb->get_results(
            "SELECT id, user_id, session_token, access_platform_id, ip_address, user_agent
             FROM {$table_name}
             WHERE session_token NOT REGEXP '^sha256:[a-f0-9]{64}$'
                OR (access_platform_id <> '' AND access_platform_id NOT REGEXP '^h:[A-Za-z0-9_-]{43}$')
                OR (ip_address <> '' AND ip_address NOT REGEXP '^h:[A-Za-z0-9_-]{43}$')
                OR (user_agent <> '' AND user_agent NOT REGEXP '^h:[A-Za-z0-9_-]{43}$')
             LIMIT 250"
        );

        $migration_succeeded = true;
        foreach ((array) $rows as $row) {
            $old_session_token = (string) $row->session_token;
            $stored_session_token = self::hash_session_token_value($old_session_token);
            $updated = $wpdb->update(
                $table_name,
                array(
                    'session_token' => $stored_session_token,
                    'access_platform_id' => self::privacy_hash_value($row->access_platform_id),
                    'ip_address' => self::privacy_hash_value($row->ip_address),
                    'user_agent' => self::privacy_hash_value($row->user_agent),
                ),
                array('id' => (int) $row->id),
                array('%s', '%s', '%s', '%s'),
                array('%d')
            );
            if (false === $updated) {
                $migration_succeeded = false;
                continue;
            }

            $meta_token = get_user_meta((int) $row->user_id, 'access_sso_session_token', true);
            if (!empty($meta_token) && hash_equals($old_session_token, (string) $meta_token)) {
                update_user_meta((int) $row->user_id, 'access_sso_session_token', $stored_session_token);
            }
        }

        if ($migration_succeeded && count((array) $rows) < 250) {
            update_option('access_sso_session_storage_version', self::STORAGE_VERSION, false);
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
     * Detect suspicious session activity
     */
    public function detect_suspicious_activity($user_id) {
        global $wpdb;
        
        $suspicious_indicators = array();
        
        // Check for multiple active sessions from different IPs
        $ip_sessions = $wpdb->get_results($wpdb->prepare(
            "SELECT ip_address, COUNT(*) as session_count 
             FROM {$this->table_name} 
             WHERE user_id = %d AND is_active = 1 
             GROUP BY ip_address 
             HAVING session_count > 1",
            $user_id
        ));
        
        if (!empty($ip_sessions)) {
            $suspicious_indicators[] = 'multiple_ip_sessions';
        }
        
        // Check for rapid session creation
        $recent_sessions = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table_name} 
             WHERE user_id = %d AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
            $user_id
        ));
        
        if ($recent_sessions > 5) {
            $suspicious_indicators[] = 'rapid_session_creation';
        }
        
        // Check for unusual user agent patterns
        $user_agents = $wpdb->get_col($wpdb->prepare(
            "SELECT DISTINCT user_agent FROM {$this->table_name} 
             WHERE user_id = %d AND is_active = 1",
            $user_id
        ));
        
        if (count($user_agents) > 3) {
            $suspicious_indicators[] = 'multiple_user_agents';
        }
        
        if (!empty($suspicious_indicators)) {
            $this->log_suspicious_activity($user_id, $suspicious_indicators);
        }
        
        return $suspicious_indicators;
    }
    
    /**
     * Log session events
     */
    private function log_session_event($event, $user_id, $details = array()) {
        if (AccessPlatformSSO::get_instance()->get_option('enable_logging', '1') === '1') {
            $log_entry = array(
                'timestamp' => current_time('mysql'),
                'event' => sanitize_key($event),
                'user_id' => (int) $user_id,
                'details' => $details,
            );
            
            $logs = get_option('access_sso_session_logs', array());
            $logs[] = $log_entry;
            
            // Keep only last 1000 entries
            if (count($logs) > 1000) {
                $logs = array_slice($logs, -1000);
            }
            
            update_option('access_sso_session_logs', $logs);
        }
    }
    
    /**
     * Log suspicious activity
     */
    private function log_suspicious_activity($user_id, $indicators) {
        $this->log_session_event('suspicious_activity', $user_id, array(
            'indicators' => $indicators,
            'severity' => 'medium',
        ));
        
        // Optionally send notification to administrators
        if (AccessPlatformSSO::get_instance()->get_option('notify_suspicious_activity', '0') === '1') {
            $this->notify_admins_suspicious_activity($user_id, $indicators);
        }
    }
    
    /**
     * Notify administrators of suspicious activity
     */
    private function notify_admins_suspicious_activity($user_id, $indicators) {
        $user = get_user_by('ID', $user_id);
        if (!$user) {
            return;
        }
        
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        
        $subject = sprintf(__('[%s] Suspicious SSO Activity Detected', 'access-platform-sso'), $site_name);
        
        $message = sprintf(
            __("Suspicious SSO activity detected for user:\n\nUser: %s (%s)\nIndicators: %s\nTime: %s\n\nPlease review the user's account and sessions.", 'access-platform-sso'),
            $user->display_name,
            $user->user_email,
            implode(', ', $indicators),
            current_time('mysql')
        );
        
        wp_mail($admin_email, $subject, $message);
    }
    
    /**
     * Get session statistics for admin dashboard
     */
    public function get_session_stats() {
        global $wpdb;
        
        $stats = array(
            'active_sessions' => $wpdb->get_var(
                "SELECT COUNT(*) FROM {$this->table_name} WHERE is_active = 1"
            ),
            'total_sessions_today' => $wpdb->get_var(
                "SELECT COUNT(*) FROM {$this->table_name} WHERE DATE(created_at) = CURDATE()"
            ),
            'unique_users_today' => $wpdb->get_var(
                "SELECT COUNT(DISTINCT user_id) FROM {$this->table_name} WHERE DATE(created_at) = CURDATE()"
            ),
            'expired_sessions' => $wpdb->get_var(
                "SELECT COUNT(*) FROM {$this->table_name} WHERE expires_at < NOW() AND is_active = 1"
            ),
        );
        
        return $stats;
    }
}
