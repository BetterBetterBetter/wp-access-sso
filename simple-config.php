<?php
/**
 * Simple SSO Configuration Interface
 * Replace your current admin page with this simplified version
 */

// Add this to your main plugin file to replace the admin page temporarily

add_action('admin_menu', 'access_sso_simple_admin_menu', 20);
function access_sso_simple_admin_menu() {
    add_options_page(
        'Access Platform SSO - Simple Config',
        'Access Platform SSO',
        'manage_options',
        'access-platform-sso-simple',
        'access_sso_simple_admin_page'
    );
}

function access_sso_simple_admin_page() {
    // Handle form submission
    if (isset($_POST['submit']) && check_admin_referer('access_sso_simple_settings')) {
        update_option('access_sso_platform_url', sanitize_url($_POST['platform_url']));
        update_option('access_sso_site_id', sanitize_text_field($_POST['site_id']));
        update_option('access_sso_jwt_secret', sanitize_text_field($_POST['jwt_secret']));
        update_option('access_sso_auto_provision', isset($_POST['auto_provision']) ? '1' : '0');
        update_option('access_sso_default_role', sanitize_text_field($_POST['default_role']));
        
        echo '<div class="notice notice-success"><p>Settings saved!</p></div>';
    }
    
    // Get current values
    $platform_url = get_option('access_sso_platform_url', '');
    $site_id = get_option('access_sso_site_id', wp_generate_uuid4());
    $jwt_secret = get_option('access_sso_jwt_secret', wp_generate_password(64, false));
    $auto_provision = get_option('access_sso_auto_provision', '1');
    $default_role = get_option('access_sso_default_role', 'subscriber');
    
    // Update defaults if empty
    if (empty(get_option('access_sso_site_id'))) {
        update_option('access_sso_site_id', $site_id);
    }
    if (empty(get_option('access_sso_jwt_secret'))) {
        update_option('access_sso_jwt_secret', $jwt_secret);
    }
    ?>
    
    <div class="wrap">
        <h1>Access Platform SSO Configuration</h1>
        
        <div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">
            <h2>Quick Setup Guide</h2>
            <ol>
                <li><strong>Platform URL:</strong> Enter your Access Platform URL (e.g., https://your-platform.com)</li>
                <li><strong>JWT Secret:</strong> Use the generated secret (copy this to your Access Platform environment)</li>
                <li><strong>Test Connection:</strong> Click test to verify everything works</li>
                <li><strong>Save Settings</strong></li>
            </ol>
        </div>
        
        <form method="post" action="">
            <?php wp_nonce_field('access_sso_simple_settings'); ?>
            
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="platform_url">Access Platform URL</label>
                    </th>
                    <td>
                        <input type="url" id="platform_url" name="platform_url" 
                               value="<?php echo esc_attr($platform_url); ?>" 
                               class="regular-text" required>
                        <p class="description">The URL of your Access Platform (e.g., https://your-platform.com)</p>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">
                        <label for="site_id">Site ID</label>
                    </th>
                    <td>
                        <input type="text" id="site_id" name="site_id" 
                               value="<?php echo esc_attr($site_id); ?>" 
                               class="regular-text" readonly>
                        <p class="description">Unique identifier for this WordPress site (auto-generated)</p>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">
                        <label for="jwt_secret">JWT Secret Key</label>
                    </th>
                    <td>
                        <input type="text" id="jwt_secret" name="jwt_secret" 
                               value="<?php echo esc_attr($jwt_secret); ?>" 
                               class="large-text">
                        <br>
                        <button type="button" onclick="generateNewSecret()" class="button">Generate New Secret</button>
                        <p class="description">
                            <strong>Important:</strong> Copy this secret to your Access Platform environment variable <code>SSO_JWT_SECRET</code>
                        </p>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">User Management</th>
                    <td>
                        <label>
                            <input type="checkbox" name="auto_provision" value="1" 
                                   <?php checked($auto_provision, '1'); ?>>
                            Automatically create WordPress users from SSO data
                        </label>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">
                        <label for="default_role">Default User Role</label>
                    </th>
                    <td>
                        <select id="default_role" name="default_role">
                            <?php
                            $roles = get_editable_roles();
                            foreach ($roles as $role_key => $role) {
                                echo '<option value="' . esc_attr($role_key) . '" ' . 
                                     selected($default_role, $role_key, false) . '>' . 
                                     esc_html($role['name']) . '</option>';
                            }
                            ?>
                        </select>
                        <p class="description">Default role for new users created via SSO</p>
                    </td>
                </tr>
            </table>
            
            <div style="margin: 20px 0;">
                <button type="button" onclick="testConnection()" class="button" id="test-connection-btn">
                    Test Connection
                </button>
                <span id="connection-status" style="margin-left: 10px;"></span>
            </div>
            
            <?php submit_button(); ?>
        </form>
        
        <div style="background: #f0f0f1; padding: 20px; margin: 20px 0;">
            <h3>Environment Setup</h3>
            <p>Add this to your Access Platform <code>.env.local</code> file:</p>
            <pre style="background: #fff; padding: 10px; border: 1px solid #ccc;">SSO_JWT_SECRET=<?php echo esc_html($jwt_secret); ?></pre>
            
            <h3>Test SSO Flow</h3>
            <ol>
                <li>Save these settings</li>
                <li>Test the connection above</li>
                <li>Logout of WordPress</li>
                <li>You should see "Login with Access Platform" button on login page</li>
            </ol>
        </div>
    </div>
    
    <script>
    function generateNewSecret() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        let secret = '';
        for (let i = 0; i < 64; i++) {
            secret += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        document.getElementById('jwt_secret').value = secret;
        alert('New JWT secret generated! Make sure to save settings and update your Access Platform environment.');
    }
    
    function testConnection() {
        const btn = document.getElementById('test-connection-btn');
        const status = document.getElementById('connection-status');
        const platformUrl = document.getElementById('platform_url').value;
        
        if (!platformUrl) {
            status.innerHTML = '<span style="color: red;">Please enter Platform URL first</span>';
            return;
        }
        
        btn.disabled = true;
        btn.textContent = 'Testing...';
        status.innerHTML = '<span style="color: orange;">Testing connection...</span>';
        
        fetch(platformUrl + '/api/sso/health')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'healthy') {
                    status.innerHTML = '<span style="color: green;">✅ Connection successful!</span>';
                } else {
                    status.innerHTML = '<span style="color: red;">❌ Connection failed: ' + (data.error || 'Unknown error') + '</span>';
                }
            })
            .catch(error => {
                status.innerHTML = '<span style="color: red;">❌ Connection failed: ' + error.message + '</span>';
            })
            .finally(() => {
                btn.disabled = false;
                btn.textContent = 'Test Connection';
            });
    }
    </script>
    
    <?php
}
?>