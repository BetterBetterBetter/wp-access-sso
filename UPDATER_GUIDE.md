# GitHub Updater Guide

This plugin uses the Plugin Update Checker library to enable automatic updates from GitHub.

## How It Works

1. The plugin checks GitHub for new releases
2. When a new version is detected, WordPress shows an update notification
3. Users can update with one click from the WordPress admin

## Creating a New Release

When you're ready to release a new version:

### Step 1: Update Version Numbers

Update these **three places** in `access-platform-sso.php`:

1. Plugin header: `Version: 1.1.2` (line 6)
2. Constant: `define('ACCESS_SSO_VERSION', '1.1.2');` (line 18)

### Step 2: Commit and Push

```bash
git add .
git commit -m "Bump version to 1.1.2"
git push origin main
```

### Step 3: Create a GitHub Release

**Option A: Via GitHub Web Interface**
1. Go to: https://github.com/BetterBetterBetter/wp-access-sso/releases/new
2. Click "Choose a tag" → "Create new tag: v1.1.2"
3. Release title: `Version 1.1.2`
4. Description: Add your changelog
5. Click "Publish release"

**Option B: Via Git Tags**
```bash
git tag v1.1.2
git push origin v1.1.2
```

Then create a release on GitHub web interface and attach the tag.

## Testing Updates

1. Install the plugin on a test WordPress site
2. Create a new release (e.g., `v1.1.2`) on GitHub
3. Go to WordPress Admin → Plugins
4. You should see "There is a new version available"
5. Click "Update Now" to test

## Troubleshooting

### Updates Not Showing?

Clear WordPress transients:
```php
// Add this temporarily to your theme's functions.php or run via WP-CLI
delete_site_transient('update_plugins');
```

### Wrong Version Detected?

- Ensure plugin header `Version:` matches the tag (without the `v` prefix)
- Tag format: `v1.1.2` → Version in header: `1.1.2`

### 403 Errors?

If your repository is private, you'll need to add authentication. See Plugin Update Checker documentation for private repo setup.

## Important Notes

- **Always update version numbers** before creating a release
- **Use semantic versioning**: `MAJOR.MINOR.PATCH` (e.g., 1.1.2)
- **Tag format**: Use `v` prefix (e.g., `v1.1.2`)
- **Version format**: No `v` prefix in plugin header (e.g., `1.1.2`)

## Version Number Sync Checklist

Before each release, verify:
- [ ] Plugin header `Version:` updated
- [ ] `ACCESS_SSO_VERSION` constant updated
- [ ] Git tag created with `v` prefix
- [ ] GitHub release created
- [ ] Changes committed and pushed

