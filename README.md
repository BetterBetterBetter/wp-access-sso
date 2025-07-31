# Access Platform SSO WordPress Plugin

A comprehensive Single Sign-On (SSO) plugin that integrates WordPress sites with your Access Platform (Supabase Auth).

## Features

- **JWT-based Authentication**: Secure token-based authentication using your existing Supabase infrastructure
- **Auto User Provisioning**: Automatically creates WordPress users from Access Platform data
- **Role Mapping**: Flexible mapping between Access Platform roles and WordPress roles
- **Session Management**: Cross-site session tracking and management
- **Security Features**: Comprehensive logging, suspicious activity detection, and admin tools
- **Professional Admin Interface**: Easy-to-use configuration and monitoring dashboard

## Installation

1. Upload the plugin files to `/wp-content/plugins/access-platform-sso/`
2. Activate the plugin through the WordPress admin panel
3. Go to Settings > Access Platform SSO to configure

## Configuration

### Required Settings

1. **Access Platform URL**: The URL of your Access Platform (e.g., `https://your-platform.com`)
2. **Site ID**: Automatically generated unique identifier for this WordPress site  
3. **JWT Secret Key**: Shared secret for JWT token validation (must match your Access Platform)

### Optional Settings

- **Auto-Provision Users**: Automatically create WordPress users from SSO data
- **Default User Role**: Default role for new users created via SSO
- **Role Mapping**: JSON configuration for mapping Access Platform roles to WordPress roles
- **Global Logout**: Redirect to Access Platform on logout for cross-site logout
- **Admin Bypass**: Allow administrators to bypass SSO and login normally
- **Enable Logging**: Detailed logging of SSO events for security monitoring

## Usage

### For End Users

1. Visit any WordPress site with the plugin installed
2. Click "Login with Access Platform" on the login page
3. You'll be redirected to your Access Platform for authentication
4. After successful login, you'll be redirected back and automatically logged in
5. Logout from any site will optionally log you out from all sites

### For Administrators

1. Configure the plugin settings in WordPress admin
2. Test the connection to your Access Platform
3. Monitor SSO statistics and active sessions
4. View detailed logs of authentication events
5. Manage user sessions and revoke access if needed

## Access Platform Integration

This plugin works with your existing Access Platform JWT endpoint at `/api/sso/jwt`. The endpoint should:

1. Generate JWT tokens for authenticated users
2. Include user data (email, name, role, subscription status)
3. Sign tokens with the shared JWT secret
4. Handle token validation requests

### Example JWT Payload

```json
{
  "id": "user-123",
  "email": "user@example.com",
  "name": "John Doe", 
  "role": "premium_member",
  "subscription_status": "ACTIVE",
  "is_admin": false,
  "iat": 1640995200,
  "exp": 1640996100,
  "site_id": "wp-site-456"
}
```

## Role Mapping

Configure role mapping in the plugin settings using JSON format:

```json
{
  "admin": "administrator",
  "premium_member": "editor", 
  "basic_member": "subscriber",
  "active_subscriber": "subscriber",
  "inactive_subscriber": "subscriber"
}
```

## Security Features

- **JWT Signature Verification**: HMAC SHA256 validation
- **Token Expiration**: Automatic token expiry handling
- **Session Tracking**: Comprehensive session monitoring
- **Suspicious Activity Detection**: Alerts for unusual login patterns
- **Audit Logging**: Detailed logs of all SSO events
- **IP Address Tracking**: Security monitoring by IP address
- **Rate Limiting**: Protection against authentication abuse

## Database Tables

The plugin creates the following table:

- `wp_access_sso_sessions`: Stores SSO session data

## Hooks and Filters

### Actions

- `access_sso_user_created`: Fired when a new user is created via SSO
- `access_sso_user_updated`: Fired when an existing user is updated via SSO
- `access_sso_login_success`: Fired on successful SSO login
- `access_sso_login_failed`: Fired on failed SSO login attempt

### Filters

- `access_sso_user_data`: Modify user data before provisioning
- `access_sso_user_role`: Modify the assigned user role
- `access_sso_redirect_url`: Modify the post-login redirect URL
- `access_sso_jwt_claims`: Modify JWT claims before validation

## Troubleshooting

### Common Issues

1. **Connection Failed**: Check that your Access Platform URL is correct and accessible
2. **Invalid Token**: Ensure JWT secret matches between plugin and Access Platform
3. **User Not Created**: Check that auto-provisioning is enabled
4. **Login Loop**: Verify callback URL configuration and nonce validation

### Debug Mode

Enable WordPress debug mode and check logs for detailed error information:

```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
```

### Testing Connection

Use the "Test Connection" button in the plugin settings to verify:
- Access Platform URL is reachable
- JWT secret is configured correctly
- Token validation is working

## Requirements

- WordPress 5.0 or higher
- PHP 7.4 or higher
- SSL/HTTPS (required for secure token transmission)
- Active Access Platform with JWT SSO endpoint

## Security Considerations

1. **Always use HTTPS** in production environments
2. **Rotate JWT secrets** regularly for enhanced security  
3. **Monitor logs** for suspicious authentication attempts
4. **Limit admin bypass** to trusted administrators only
5. **Regular updates** to keep security patches current

## Support

For support and bug reports, please contact your Access Platform administrator or create an issue in the project repository.

## License

This plugin is licensed under GPL v2 or later.

## Changelog

### Version 1.0.0
- Initial release
- JWT-based SSO authentication
- User provisioning and role mapping
- Session management and security logging
- Professional admin interface
- Comprehensive documentation

---

© 2024 Access Platform Team. All rights reserved.