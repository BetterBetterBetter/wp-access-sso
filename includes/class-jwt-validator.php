<?php
/**
 * JWT Token Validator Class
 * Handles JWT token validation from Access Platform
 */

if (!defined('ABSPATH')) {
    exit;
}

class AccessSSO_JWT_Validator {
    const DEFAULT_JWT_AUDIENCE = 'wordpress-sso';
    const MAX_TOKEN_LIFETIME = 900;
    const CLOCK_SKEW = 60;
    const REPLAY_OPTION_PREFIX = 'access_sso_replay_';
    
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
            return array('valid' => false, 'error' => 'Unsupported algorithm');
        }

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
            return array('valid' => false, 'error' => 'Invalid signature');
        }
        
        // Require a short, bounded lifetime so a leaked callback URL expires quickly.
        if (!isset($decoded_payload['exp']) || !is_numeric($decoded_payload['exp'])) {
            return array('valid' => false, 'error' => 'Token expiration missing');
        }

        if (!isset($decoded_payload['iat']) || !is_numeric($decoded_payload['iat'])) {
            return array('valid' => false, 'error' => 'Token issued-at missing');
        }

        $now = time();
        $issued_at = (int) $decoded_payload['iat'];
        $expires_at = (int) $decoded_payload['exp'];

        if ($expires_at <= $now) {
            return array('valid' => false, 'error' => 'Token expired');
        }

        if ($issued_at > ($now + self::CLOCK_SKEW)) {
            return array('valid' => false, 'error' => 'Token issued in the future');
        }

        if ($expires_at <= $issued_at || ($expires_at - $issued_at) > (self::MAX_TOKEN_LIFETIME + self::CLOCK_SKEW)) {
            return array('valid' => false, 'error' => 'Token lifetime exceeds limit');
        }

        if (isset($decoded_payload['nbf']) && (!is_numeric($decoded_payload['nbf']) || (int) $decoded_payload['nbf'] > ($now + self::CLOCK_SKEW))) {
            return array('valid' => false, 'error' => 'Token not yet valid');
        }

        // Check issuer against the configured Access Platform URL.
        $expected_issuer = $this->get_expected_issuer();
        $token_issuer = isset($decoded_payload['iss']) ? $this->normalize_url_claim($decoded_payload['iss']) : '';
        if (empty($expected_issuer) || empty($token_issuer) || $token_issuer !== $expected_issuer) {
            return array('valid' => false, 'error' => 'Invalid issuer');
        }

        // Check audience against Access's SSO audience. The exact site binding is the site_id claim below.
        $expected_audiences = $this->get_expected_audiences();
        if (!isset($decoded_payload['aud']) || !$this->audience_matches($decoded_payload['aud'], $expected_audiences)) {
            return array('valid' => false, 'error' => 'Invalid audience');
        }

        // Check exact canonical Access site_id. Do not fall back to host matching.
        $payload_site_id = isset($decoded_payload['site_id']) ? $decoded_payload['site_id'] : (isset($decoded_payload['site']['site_id']) ? $decoded_payload['site']['site_id'] : null);
        if (empty($payload_site_id) || empty($this->site_id) || $payload_site_id !== $this->site_id) {
            return array('valid' => false, 'error' => 'Invalid site ID');
        }
        
        return array(
            'valid' => true,
            'user' => $decoded_payload,
            'header' => $decoded_header,
            'verified' => array(
                'signature' => true,
                'expiration' => true,
                'issued_at' => true,
                'issuer' => true,
                'audience' => true,
                'site_id' => true,
            ),
        );
    }

    /**
     * Atomically mark a validated JWT as consumed for the rest of its lifetime.
     */
    public function consume_token_once($jwt_token, $expires_at) {
        $jwt_token = (string) $jwt_token;
        $expires_at = (int) $expires_at;
        if (empty($jwt_token) || $expires_at <= time()) {
            return false;
        }

        $option_name = self::REPLAY_OPTION_PREFIX . hash('sha256', $jwt_token);
        $existing_expiration = get_option($option_name, false);

        if (false !== $existing_expiration) {
            if ((int) $existing_expiration > time()) {
                return false;
            }

            delete_option($option_name);
        }

        $consumed = add_option($option_name, $expires_at, '', 'no');
        if ($consumed && wp_rand(1, 100) === 1) {
            $this->cleanup_replay_options();
        }

        return $consumed;
    }

    private function cleanup_replay_options() {
        global $wpdb;

        $like = $wpdb->esc_like(self::REPLAY_OPTION_PREFIX) . '%';
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 200",
                $like
            )
        );

        foreach ((array) $rows as $row) {
            if ((int) $row->option_value <= time()) {
                delete_option($row->option_name);
            }
        }
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
     * Expected audience defaults to Access's fixed WordPress SSO audience.
     */
    private function get_expected_audiences() {
        $audiences = array(self::DEFAULT_JWT_AUDIENCE);
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
            'aud' => self::DEFAULT_JWT_AUDIENCE,
            'jti' => wp_generate_uuid4(),
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
    
}
