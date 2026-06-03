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
        return $local_validation;
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
            error_log('[Access SSO] JWT alg unsupported: ' . json_encode($decoded_header));
            return array('valid' => false, 'error' => 'Unsupported algorithm');
        }
        
        // Logging: claims overview (safe)
        $claims_info = array(
            'iss' => isset($decoded_payload['iss']) ? $decoded_payload['iss'] : null,
            'aud' => isset($decoded_payload['aud']) ? $decoded_payload['aud'] : null,
            'has_site' => isset($decoded_payload['site']),
            'site_id' => isset($decoded_payload['site_id']) ? $decoded_payload['site_id'] : (isset($decoded_payload['site']['site_id']) ? $decoded_payload['site']['site_id'] : null),
            'sub_present' => isset($decoded_payload['sub'])
        );
        error_log('[Access SSO] JWT claims: ' . json_encode($claims_info));

        // Verify signature (support both raw and base64-encoded secrets)
        $signing_input = $header . '.' . $payload;
        $expected_signature_raw = $this->base64url_encode(
            hash_hmac('sha256', $signing_input, $this->jwt_secret, true)
        );

        $is_valid = hash_equals($expected_signature_raw, $signature);

        if (!$is_valid) {
            $decoded_secret = base64_decode($this->jwt_secret, true);
            if ($decoded_secret !== false) {
                $expected_signature_b64 = $this->base64url_encode(
                    hash_hmac('sha256', $signing_input, $decoded_secret, true)
                );
                $is_valid = hash_equals($expected_signature_b64, $signature);
            }
        }

        if (!$is_valid) {
            // Log diagnostic hashes, not secrets
            $secret_hash = substr(hash('sha256', $this->jwt_secret), 0, 12);
            $sig_short = substr($signature, 0, 10);
            $exp_short = substr($expected_signature_raw, 0, 10);
            error_log('[Access SSO] JWT signature mismatch. secret_sha256_12=' . $secret_hash . ' provided_sig=' . $sig_short . ' expected_raw=' . $exp_short . ' used_b64_secret=' . (isset($decoded_secret) && $decoded_secret !== false ? 'yes' : 'no'));
            return array('valid' => false, 'error' => 'Invalid signature');
        }
        
        // Check expiration. Privileged claims are only trusted on bounded tokens.
        if (!isset($decoded_payload['exp']) || !is_numeric($decoded_payload['exp'])) {
            return array('valid' => false, 'error' => 'Token expiration missing');
        }

        if ((int) $decoded_payload['exp'] <= time()) {
            return array('valid' => false, 'error' => 'Token expired');
        }

        // Check issuer against the configured Access Platform URL.
        $expected_issuer = $this->get_expected_issuer();
        $token_issuer = isset($decoded_payload['iss']) ? $this->normalize_url_claim($decoded_payload['iss']) : '';
        if (empty($expected_issuer) || empty($token_issuer) || $token_issuer !== $expected_issuer) {
            return array('valid' => false, 'error' => 'Invalid issuer');
        }

        // Check audience against the configured canonical Access site ID by default.
        $expected_audiences = $this->get_expected_audiences();
        if (!isset($decoded_payload['aud']) || !$this->audience_matches($decoded_payload['aud'], $expected_audiences)) {
            return array('valid' => false, 'error' => 'Invalid audience');
        }

        // Check exact canonical Access site_id. Do not fall back to host matching.
        $payload_site_id = isset($decoded_payload['site_id']) ? $decoded_payload['site_id'] : (isset($decoded_payload['site']['site_id']) ? $decoded_payload['site']['site_id'] : null);
        if (empty($payload_site_id) || empty($this->site_id) || $payload_site_id !== $this->site_id) {
            error_log('[Access SSO] Site ID mismatch. token_site_id=' . $payload_site_id . ' wp_site_id=' . $this->site_id);
            return array('valid' => false, 'error' => 'Invalid site ID');
        }
        
        return array(
            'valid' => true,
            'user' => $decoded_payload,
            'header' => $decoded_header,
            'verified' => array(
                'signature' => true,
                'expiration' => true,
                'issuer' => true,
                'audience' => true,
                'site_id' => true,
            ),
        );
    }

    /**
     * Expected issuer is the configured Access Platform URL.
     */
    private function get_expected_issuer() {
        $issuer = $this->normalize_url_claim($this->platform_url);
        $issuer = apply_filters('access_sso_expected_jwt_issuer', $issuer, $this->platform_url);
        return $this->normalize_url_claim($issuer);
    }

    /**
     * Expected audience defaults to the canonical Access site ID.
     */
    private function get_expected_audiences() {
        $audiences = array_filter(array($this->site_id));
        $audiences = apply_filters('access_sso_expected_jwt_audiences', $audiences, $this->site_id);

        if (!is_array($audiences)) {
            $audiences = array($audiences);
        }

        return array_values(array_filter(array_map('strval', $audiences)));
    }

    /**
     * Match string or array JWT audiences.
     */
    private function audience_matches($token_audience, $expected_audiences) {
        if (empty($expected_audiences)) {
            return false;
        }

        $token_audiences = is_array($token_audience) ? $token_audience : array($token_audience);
        $token_audiences = array_map('strval', $token_audiences);

        foreach ($expected_audiences as $expected_audience) {
            if (in_array((string) $expected_audience, $token_audiences, true)) {
                return true;
            }
        }

        return false;
    }

    private function normalize_url_claim($value) {
        $value = trim((string) $value);
        if (empty($value)) {
            return '';
        }

        return untrailingslashit($value);
    }
    
    /**
     * Remote JWT validation via Access Platform API
     */
    private function validate_remotely($jwt_token) {
        if (empty($this->platform_url)) {
            return array('valid' => false, 'error' => 'Platform URL not configured');
        }

        $base = trailingslashit($this->platform_url) . 'api/sso/';
        $candidate_paths = array(
            'token/validate',
            'validate',
            'token/verify',
            'verify',
        );

        $last_error = 'Unknown error';
        foreach ($candidate_paths as $path) {
            $validation_url = $base . $path;

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
                $last_error = 'Remote validation failed: ' . $response->get_error_message();
                continue;
            }

            $status_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);

            if ($status_code === 200) {
                $data = json_decode($body, true);
                if ($data) {
                    return $data;
                }
                $last_error = 'Invalid response format';
                continue;
            }

            // Record last error with status and tried path
            $last_error = 'Remote validation returned status: ' . $status_code . ' for ' . $path;
        }

        return array('valid' => false, 'error' => $last_error);
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
            'iss' => $this->get_expected_issuer(),
            'aud' => $this->site_id,
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