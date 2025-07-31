<?php
/**
 * JWT Token Validator Class
 * Handles JWT token validation from Access Platform
 */

if (!defined('ABSPATH')) {
    exit;
}

class AccessSSO_JWT_Validator {
    
    private $platform_url;
    private $jwt_secret;
    private $site_id;
    
    public function __construct() {
        $this->platform_url = AccessPlatformSSO::get_instance()->get_option('platform_url');
        $this->jwt_secret = AccessPlatformSSO::get_instance()->get_option('jwt_secret');
        $this->site_id = AccessPlatformSSO::get_instance()->get_option('site_id');
    }
    
    /**
     * Validate JWT token locally and via remote API
     */
    public function validate_token($jwt_token) {
        if (empty($jwt_token)) {
            return array('valid' => false, 'error' => 'Empty token');
        }
        
        // Try local validation first
        $local_validation = $this->validate_locally($jwt_token);
        if ($local_validation['valid']) {
            return $local_validation;
        }
        
        // Fallback to remote validation
        return $this->validate_remotely($jwt_token);
    }
    
    /**
     * Local JWT validation using HMAC SHA256
     */
    private function validate_locally($jwt_token) {
        if (empty($this->jwt_secret)) {
            return array('valid' => false, 'error' => 'JWT secret not configured');
        }
        
        $parts = explode('.', $jwt_token);
        if (count($parts) !== 3) {
            return array('valid' => false, 'error' => 'Invalid JWT format');
        }
        
        list($header, $payload, $signature) = $parts;
        
        // Decode header and payload
        $decoded_header = json_decode($this->base64url_decode($header), true);
        $decoded_payload = json_decode($this->base64url_decode($payload), true);
        
        if (!$decoded_header || !$decoded_payload) {
            return array('valid' => false, 'error' => 'Invalid JWT encoding');
        }
        
        // Verify algorithm
        if (!isset($decoded_header['alg']) || $decoded_header['alg'] !== 'HS256') {
            return array('valid' => false, 'error' => 'Unsupported algorithm');
        }
        
        // Verify signature
        $expected_signature = $this->base64url_encode(
            hash_hmac('sha256', $header . '.' . $payload, $this->jwt_secret, true)
        );
        
        if (!hash_equals($expected_signature, $signature)) {
            return array('valid' => false, 'error' => 'Invalid signature');
        }
        
        // Check expiration
        if (isset($decoded_payload['exp']) && $decoded_payload['exp'] < time()) {
            return array('valid' => false, 'error' => 'Token expired');
        }
        
        // Check site_id if present
        if (isset($decoded_payload['site_id']) && $decoded_payload['site_id'] !== $this->site_id) {
            return array('valid' => false, 'error' => 'Invalid site ID');
        }
        
        return array(
            'valid' => true,
            'user' => $decoded_payload,
            'header' => $decoded_header
        );
    }
    
    /**
     * Remote JWT validation via Access Platform API
     */
    private function validate_remotely($jwt_token) {
        if (empty($this->platform_url)) {
            return array('valid' => false, 'error' => 'Platform URL not configured');
        }
        
        $validation_url = trailingslashit($this->platform_url) . 'api/sso/token/validate';
        
        $response = wp_remote_post($validation_url, array(
            'timeout' => 15,
            'headers' => array(
                'Content-Type' => 'application/json',
                'User-Agent' => 'Access Platform SSO Plugin v' . ACCESS_SSO_VERSION,
            ),
            'body' => json_encode(array(
                'token' => $jwt_token,
                'site_id' => $this->site_id,
            )),
        ));
        
        if (is_wp_error($response)) {
            return array(
                'valid' => false, 
                'error' => 'Remote validation failed: ' . $response->get_error_message()
            );
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        if ($status_code !== 200) {
            return array(
                'valid' => false,
                'error' => 'Remote validation returned status: ' . $status_code
            );
        }
        
        $data = json_decode($body, true);
        if (!$data) {
            return array('valid' => false, 'error' => 'Invalid response format');
        }
        
        return $data;
    }
    
    /**
     * Generate JWT token for local user (for testing)
     */
    public function generate_test_token($user_data) {
        if (empty($this->jwt_secret)) {
            return false;
        }
        
        $header = array(
            'typ' => 'JWT',
            'alg' => 'HS256'
        );
        
        $payload = array_merge($user_data, array(
            'iat' => time(),
            'exp' => time() + (15 * 60), // 15 minutes
            'site_id' => $this->site_id,
        ));
        
        $header_encoded = $this->base64url_encode(json_encode($header));
        $payload_encoded = $this->base64url_encode(json_encode($payload));
        
        $signature = $this->base64url_encode(
            hash_hmac('sha256', $header_encoded . '.' . $payload_encoded, $this->jwt_secret, true)
        );
        
        return $header_encoded . '.' . $payload_encoded . '.' . $signature;
    }
    
    /**
     * Base64URL decode
     */
    private function base64url_decode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }
    
    /**
     * Base64URL encode
     */
    private function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    /**
     * Log validation events for security monitoring
     */
    private function log_validation($event, $details) {
        if (AccessPlatformSSO::get_instance()->get_option('enable_logging', '1') === '1') {
            $log_entry = array(
                'timestamp' => current_time('mysql'),
                'event' => $event,
                'details' => $details,
                'ip_address' => $this->get_client_ip(),
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
            );
            
            // Store in WordPress option or custom table
            $logs = get_option('access_sso_validation_logs', array());
            $logs[] = $log_entry;
            
            // Keep only last 1000 entries
            if (count($logs) > 1000) {
                $logs = array_slice($logs, -1000);
            }
            
            update_option('access_sso_validation_logs', $logs);
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