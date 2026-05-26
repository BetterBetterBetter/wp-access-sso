# Access Impersonation Verification

This repository does not currently include a root PHPUnit, Composer, or WordPress test scaffold, so impersonation awareness should be verified manually in a WordPress environment.

## Required Scenarios

1. JWT without impersonation claim:
   - Complete SSO with a valid JWT that has no `impersonation` claim.
   - Confirm the user logs in normally.
   - Confirm no Access impersonation banner appears on frontend pages or in `wp-admin`.
   - While already logged into WordPress from a previous impersonation session, complete SSO again with a valid non-impersonation JWT and confirm the old banner is cleared.

2. JWT with active impersonation claim:
   - Complete SSO with a valid JWT containing `impersonation.active === true`.
   - Include `targetEmail`, `adminEmail`, `startedAt`, `returnToAccessUrl`, and optionally `exitImpersonationUrl`.
   - Confirm the banner appears on frontend pages and in `wp-admin`.
   - Confirm `Return to Access` links to `returnToAccessUrl`.
   - Confirm `Exit impersonation` appears only when `exitImpersonationUrl` is provided.
   - Confirm clicking `Exit impersonation` clears the local WordPress impersonation banner, logs out the impersonated WordPress session, and redirects to Access.

3. Logout clears impersonation context:
   - Log out of WordPress from a session with an active impersonation banner.
   - Confirm the impersonation cookie is cleared or expired.
   - Confirm no banner appears after the next login unless the new SSO JWT includes active impersonation.

4. Claims do not change WordPress authorization:
   - Before SSO, record the target user's WordPress roles and capabilities.
   - Complete SSO with active impersonation claims.
   - Confirm roles and capabilities are unchanged for existing users.
   - Confirm new users still receive only the plugin's configured default role.
   - Confirm no role or capability is granted from any `impersonation` claim field.
