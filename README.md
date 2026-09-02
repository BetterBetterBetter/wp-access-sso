# Access Platform SSO WordPress Plugin

A comprehensive Single Sign-On (SSO) plugin that integrates WordPress sites with your Access Platform (Supabase Auth).

## Features

- **JWT-based Authentication**: Secure token-based authentication using your existing Supabase infrastructure
- **Safe User Provisioning**: Creates WordPress users without allowing external claims to grant or change privileged WordPress roles
- **Authorization Separation**: Access proves identity; WordPress and plugins such as MemberPress remain the source of roles and permissions
- **Session Management**: Tracks SSO sessions with tokens and request fingerprints hashed at rest
- **Security Features**: Browser-bound login state, single-use short-lived JWTs, rate limiting, and redacted diagnostics
- **Professional Admin Interface**: Easy-to-use configuration and monitoring dashboard
- **Login Form Detection**: Automatically detects and enhances login forms from MemberPress, LearnDash, WooCommerce, and more

## Installation

1. Upload the plugin files to `/wp-content/plugins/access-platform-sso/`
2. Activate the plugin through the WordPress admin panel
3. Go to Settings > Access Platform SSO to configure

## Configuration

### Required Settings

1. **Access Platform URL**: The URL of your Access Platform (e.g., `https://your-platform.com`)
2. **Site ID**: The canonical site identifier copied from Access and verified against this WordPress host
3. **JWT Secret Key**: Shared secret for JWT token validation (must match your Access Platform)

### Optional Settings

- **Callback Path**: Path where SSO callback is processed. Use this if your homepage doesn't run WordPress code (e.g., static homepage). Set to `welcome` or `members` to use `/welcome/?access_sso_callback=1` instead.
- **Post-Login Redirect URL**: Where to redirect users after successful SSO login
- **Button and Form Detection Settings**: Control the injected login button and which form types are enhanced
- **Excluded Routes**: Prevent automatic form detection where it is not wanted

### Sites with Static Homepages

If your WordPress site has a homepage that doesn't run WordPress code (e.g., static HTML, different CMS, or reverse proxy), the SSO callback won't work on the root URL.

**Solution:** Set the **Callback Path** to a WordPress page that does run PHP:

1. Go to Settings > Access Platform SSO
2. Set **Callback Path** to `welcome` (or any WordPress page slug)
3. The SSO callback will now use `https://your-site.com/welcome/?access_sso_callback=1`
4. Set **Post-Login Redirect URL** to where you want users to land after login

## Login Form Detection

The plugin automatically detects login forms across your site and injects an SSO login button. This works with:

### Supported Plugins

- **MemberPress** - All login forms and widgets
- **LearnDash** - Course login forms and widgets
- **WooCommerce** - My Account login, checkout login
- **Ultimate Member** - Login forms and widgets
- **BuddyPress / BuddyBoss** - Community login forms
- **Generic** - Any form with username/password fields

### How It Works

1. The JavaScript detector scans the page for known login form patterns
2. When a login form is found, an SSO button is automatically injected
3. The button appears above the form fields with an "or" divider
4. Users can click to authenticate via Access Platform

### Configuration

In **Settings > Access Platform SSO > Login Form Detection**:

- **Button Text**: Customize the SSO button text (default: "Login with Access Platform")
- **Enabled Form Types**: Choose which plugin forms to detect
- **Disable Auto-Detection**: Turn off automatic detection if needed

### Manual Integration

If the automatic detector doesn't find your form, you can manually trigger it:

```javascript
// Inject SSO button into a specific form
AccessSSODetector.injectInto('#my-custom-login-form');

// Re-scan the page for forms
AccessSSODetector.detect();
```

### Adding Custom Form Selectors

You can extend the detector with custom selectors:

```javascript
// Add custom selectors before page load
window.accessSSODetector = window.accessSSODetector || {};
window.accessSSODetector.custom_selectors = [
    '#my-custom-form',
    '.my-login-widget form'
];
```

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
2. Include user identity data and the required trust claims (`iss`, `aud`, `site_id`, `iat`, and `exp`)
3. Sign tokens with the shared JWT secret
4. Handle token validation requests

### Example JWT Payload

```json
{
  "id": "user-123",
  "email": "user@example.com",
  "name": "John Doe", 
  "first_name": "John",
  "last_name": "Doe",
  "iss": "https://access.example.com",
  "aud": "wordpress-sso",
  "iat": 1640995200,
  "exp": 1640996100,
  "site_id": "wp-site-456"
}
```

## Identity and Authorization Boundary

Access authenticates the person and supplies signed identity claims. It does not grant WordPress roles, MemberPress memberships, course access, or administrator permissions. Existing WordPress users retain their local roles; new SSO users receive only the site's safe non-privileged default role (falling back to `subscriber`). Authorization remains in WordPress and MemberPress.

## Security Features

- **JWT Signature Verification**: HMAC SHA256 validation
- **Bounded, Single-Use Tokens**: `iat` and `exp` are required, JWT lifetime is capped at 15 minutes, and callbacks cannot be replayed
- **Browser-Bound State**: WordPress-started login uses a short-lived HttpOnly, Secure, SameSite=Lax state cookie
- **Safe Redirects**: Post-login redirects are limited to the WordPress host and an empty setting falls back to the homepage
- **Continuation-Aware Login Buttons**: Injected login buttons preserve WordPress and MemberPress `redirect_to` destinations, including OAuth authorization requests started by connected applications
- **Private Session Storage**: Session tokens, Access IDs, IP addresses, and user agents are one-way hashed at rest
- **Rate Limiting**: Application-level limits protect the login start and callback endpoints
- **Cache Protection**: Authentication responses use `no-store`, mark requests `DONOTCACHEPAGE`, and register WP Rocket exclusions

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
4. **Login Loop**: Verify the callback URL, browser state cookie, and that cache/CDN rules bypass authentication endpoints

### Debug Mode

Enable WordPress debug logging temporarily when diagnosing a development site. The plugin intentionally emits only generic/redacted authentication failures:

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

### Version 1.1.9
- Added browser-bound state for WordPress-started SSO and retained constrained signed compatibility for Access dashboard launches
- Enforced 15-minute JWT lifetimes and one-time callback token consumption
- Prevented Access claims from granting or changing WordPress roles
- Hashed session tokens and request fingerprints at rest, including incremental legacy-data migration
- Added strict admin nonces, application rate limits, safe local redirects, no-store responses, and WP Rocket exclusions
- Removed the frontend processing splash and sensitive diagnostics

### Version 1.1.0
- **NEW**: Login Form Detector - Automatically detects and enhances login forms
- **NEW**: MemberPress support - Works with all MemberPress login forms and widgets
- **NEW**: LearnDash support - Detects course and widget login forms
- **NEW**: WooCommerce support - My Account and checkout login forms
- **NEW**: Callback Path setting - Use custom path for SSO on sites with static homepages
- **NEW**: Post-Login Redirect URL setting - Configure where users land after SSO
- **NEW**: Configurable button text and enabled form types
- Updated MemberPress selectors based on official documentation
- MutationObserver for detecting dynamically loaded forms

### Version 1.0.0
- Initial release
- JWT-based SSO authentication
- User provisioning and role mapping
- Session management and security logging
- Professional admin interface
- Comprehensive documentation

---

© 2024 Access Platform Team. All rights reserved.
