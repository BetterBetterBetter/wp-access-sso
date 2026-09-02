/* Access Platform SSO Admin JavaScript */

(function($) {
    'use strict';
    
    $(document).ready(function() {
        
        // Test connection functionality
        $('#test-connection').on('click', function(e) {
            e.preventDefault();
            testConnection();
        });
        
        // Generate JWT secret
        $('#generate-secret').on('click', function(e) {
            e.preventDefault();
            generateSecret();
        });
        
        // Toggle JWT secret visibility
        $('#toggle-secret-visibility').on('click', function(e) {
            e.preventDefault();
            toggleSecretVisibility();
        });
        
        // Removed non-core tools (sessions/logs)
        
        // Auto-save settings on change
        $('input[name^="access_sso_"], select[name^="access_sso_"], textarea[name^="access_sso_"]').on('change', function() {
            if ($(this).data('auto-save') !== false) {
                autoSaveSettings();
            }
        });
        
        // Initialize connection status
        updateConnectionStatus();
        
        // Periodic status updates
        setInterval(updateConnectionStatus, 30000); // Every 30 seconds
    });
    
    function testConnection() {
        var $button = $('#test-connection');
        var $status = $('#connection-status');
        var $indicator = $('#status-indicator');
        var $text = $('#status-text');
        
        var platformUrl = $('input[name="access_sso_platform_url"]').val();
        var siteId = $('input[name="access_sso_site_id"]').val();
        
        if (!platformUrl) {
            showNotice('Platform URL is required', 'error');
            return;
        }

        if (!siteId) {
            showNotice('Canonical Access site ID is required', 'error');
            return;
        }
        
        // Update UI
        $button.addClass('loading').prop('disabled', true);
        $indicator.removeClass('connected disconnected').addClass('testing');
        $text.text('Testing connection...');
        
        // Make AJAX request
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'access_sso_test_connection',
                nonce: accessSSOAdmin.test_connection_nonce,
                platform_url: platformUrl,
                site_id: siteId
            },
            success: function(response) {
                if (response.success) {
                    $indicator.removeClass('testing disconnected').addClass('connected');
                    $text.text('Connected successfully');
                    showNotice(response.data.message, 'success');
                } else {
                    $indicator.removeClass('testing connected').addClass('disconnected');
                    $text.text('Connection failed');
                    showNotice(response.data.message || 'Connection test failed', 'error');
                }
            },
            error: function(xhr, status, error) {
                $indicator.removeClass('testing connected').addClass('disconnected');
                $text.text('Connection failed');
                showNotice('AJAX error: ' + error, 'error');
            },
            complete: function() {
                $button.removeClass('loading').prop('disabled', false);
            }
        });
    }
    
    function generateSecret() {
        var $input = $('input[name="access_sso_jwt_secret"]');
        var $button = $('#generate-secret');
        
        var secret = generateRandomString(64);
        if (!secret) {
            showNotice('Secure random generation is unavailable in this browser.', 'error');
            return;
        }
        
        $input.val(secret);
        $button.text('Generated!').addClass('button-primary');
        
        setTimeout(function() {
            $button.text('Generate New Secret').removeClass('button-primary');
        }, 2000);
        
        showNotice('New JWT secret generated. Make sure to save your settings!', 'info');
    }
    
    function toggleSecretVisibility() {
        var $input = $('#access_sso_jwt_secret');
        var $button = $('#toggle-secret-visibility');
        
        if ($input.attr('type') === 'password') {
            $input.attr('type', 'text');
            $button.text('Hide');
        } else {
            $input.attr('type', 'password');
            $button.text('Show');
        }
    }
    
    function generateRandomString(length) {
        if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') {
            return '';
        }

        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        var bytes = new Uint8Array(length);
        window.crypto.getRandomValues(bytes);
        var result = '';
        for (var i = 0; i < length; i++) {
            result += chars.charAt(bytes[i] & 63);
        }
        return result;
    }
    
    // Removed non-core functions: cleanupSessions, viewActiveSessions, viewLogs, clearLogs
    
    function autoSaveSettings() {
        // Debounced auto-save functionality
        clearTimeout(window.autoSaveTimeout);
        window.autoSaveTimeout = setTimeout(function() {
            $('#submit').trigger('click');
        }, 2000);
    }
    
    function updateConnectionStatus() {
        var platformUrl = $('input[name="access_sso_platform_url"]').val();
        var siteId = $('input[name="access_sso_site_id"]').val();
        
        if (!platformUrl || !siteId) {
            $('#status-indicator').removeClass('connected testing').addClass('disconnected');
            $('#status-text').text('Not configured');
            return;
        }
        
        // Quick health check without user interaction
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'access_sso_health_check',
                nonce: accessSSOAdmin.health_check_nonce
            },
            success: function(response) {
                if (response.success) {
                    $('#status-indicator').removeClass('disconnected testing').addClass('connected');
                    $('#status-text').text('Connected');
                } else {
                    $('#status-indicator').removeClass('connected testing').addClass('disconnected');
                    $('#status-text').text('Disconnected');
                }
            },
            error: function() {
                $('#status-indicator').removeClass('connected testing').addClass('disconnected');
                $('#status-text').text('Connection error');
            }
        });
    }
    
    function showNotice(message, type) {
        var noticeClass = 'notice notice-' + type;
        var $notice = $('<div class="' + noticeClass + ' is-dismissible"><p>' + escapeHtml(message) + '</p></div>');
        
        $('.wrap h1').after($notice);
        
        // Auto-dismiss after 5 seconds
        setTimeout(function() {
            $notice.fadeOut(function() {
                $(this).remove();
            });
        }, 5000);
        
        // Manual dismiss
        $notice.on('click', '.notice-dismiss', function() {
            $notice.remove();
        });
    }
    
    function escapeHtml(text) {
        if (typeof text !== 'string') {
            return text;
        }
        
        var map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }
    
    // Make functions available globally for debugging
    window.accessSSOAdmin = {
        testConnection: testConnection,
        generateSecret: generateSecret,
        toggleSecretVisibility: toggleSecretVisibility
    };
    
})(jQuery);
