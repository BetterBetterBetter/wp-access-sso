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
        
        // Session management tools
        $('#cleanup-sessions').on('click', function(e) {
            e.preventDefault();
            cleanupSessions();
        });
        
        $('#view-active-sessions').on('click', function(e) {
            e.preventDefault();
            viewActiveSessions();
        });
        
        // Log management tools
        $('#view-logs').on('click', function(e) {
            e.preventDefault();
            viewLogs();
        });
        
        $('#clear-logs').on('click', function(e) {
            e.preventDefault();
            clearLogs();
        });
        
        // Auto-save settings on change
        $('input[name^="access_sso_"], select[name^="access_sso_"], textarea[name^="access_sso_"]').on('change', function() {
            if ($(this).data('auto-save') !== false) {
                autoSaveSettings();
            }
        });
        
        // Validate role mapping JSON
        $('textarea[name="access_sso_role_mapping"]').on('blur', function() {
            validateRoleMapping($(this));
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
        var jwtSecret = $('input[name="access_sso_jwt_secret"]').val();
        
        if (!platformUrl) {
            showNotice('Platform URL is required', 'error');
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
                nonce: accessSSOAdmin.nonce,
                platform_url: platformUrl,
                jwt_secret: jwtSecret
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
        
        // Generate a random secret (64 characters)
        var secret = generateRandomString(64);
        
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
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        var result = '';
        for (var i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }
    
    function cleanupSessions() {
        if (!confirm('Are you sure you want to cleanup expired sessions?')) {
            return;
        }
        
        var $button = $('#cleanup-sessions');
        $button.addClass('loading').prop('disabled', true);
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'access_sso_cleanup_sessions',
                nonce: accessSSOAdmin.nonce
            },
            success: function(response) {
                if (response.success) {
                    showNotice(response.data.message, 'success');
                    // Refresh statistics
                    location.reload();
                } else {
                    showNotice(response.data.message || 'Session cleanup failed', 'error');
                }
            },
            error: function(xhr, status, error) {
                showNotice('AJAX error: ' + error, 'error');
            },
            complete: function() {
                $button.removeClass('loading').prop('disabled', false);
            }
        });
    }
    
    function viewActiveSessions() {
        var $button = $('#view-active-sessions');
        $button.addClass('loading').prop('disabled', true);
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'access_sso_get_sessions',
                nonce: accessSSOAdmin.nonce
            },
            success: function(response) {
                if (response.success) {
                    showSessionsModal(response.data.sessions);
                } else {
                    showNotice(response.data.message || 'Failed to load sessions', 'error');
                }
            },
            error: function(xhr, status, error) {
                showNotice('AJAX error: ' + error, 'error');
            },
            complete: function() {
                $button.removeClass('loading').prop('disabled', false);
            }
        });
    }
    
    function viewLogs() {
        var $button = $('#view-logs');
        $button.addClass('loading').prop('disabled', true);
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'access_sso_get_logs',
                nonce: accessSSOAdmin.nonce
            },
            success: function(response) {
                if (response.success) {
                    showLogsModal(response.data.logs);
                } else {
                    showNotice(response.data.message || 'Failed to load logs', 'error');
                }
            },
            error: function(xhr, status, error) {
                showNotice('AJAX error: ' + error, 'error');
            },
            complete: function() {
                $button.removeClass('loading').prop('disabled', false);
            }
        });
    }
    
    function clearLogs() {
        if (!confirm('Are you sure you want to clear all SSO logs? This action cannot be undone.')) {
            return;
        }
        
        var $button = $('#clear-logs');
        $button.addClass('loading').prop('disabled', true);
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'access_sso_clear_logs',
                nonce: accessSSOAdmin.nonce
            },
            success: function(response) {
                if (response.success) {
                    showNotice(response.data.message, 'success');
                } else {
                    showNotice(response.data.message || 'Failed to clear logs', 'error');
                }
            },
            error: function(xhr, status, error) {
                showNotice('AJAX error: ' + error, 'error');
            },
            complete: function() {
                $button.removeClass('loading').prop('disabled', false);
            }
        });
    }
    
    function autoSaveSettings() {
        // Debounced auto-save functionality
        clearTimeout(window.autoSaveTimeout);
        window.autoSaveTimeout = setTimeout(function() {
            $('#submit').trigger('click');
        }, 2000);
    }
    
    function validateRoleMapping($textarea) {
        var value = $textarea.val().trim();
        
        if (!value) {
            return; // Empty is valid
        }
        
        try {
            var parsed = JSON.parse(value);
            if (typeof parsed !== 'object' || Array.isArray(parsed)) {
                throw new Error('Must be an object');
            }
            
            $textarea.removeClass('error');
            showNotice('Role mapping JSON is valid', 'success');
        } catch (e) {
            $textarea.addClass('error');
            showNotice('Invalid JSON in role mapping: ' + e.message, 'error');
        }
    }
    
    function updateConnectionStatus() {
        var platformUrl = $('input[name="access_sso_platform_url"]').val();
        
        if (!platformUrl) {
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
                nonce: accessSSOAdmin.nonce,
                platform_url: platformUrl
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
    
    function showSessionsModal(sessions) {
        var modalHtml = '<div id="sessions-modal" class="access-sso-modal">' +
            '<div class="access-sso-modal-content">' +
            '<span class="access-sso-modal-close">&times;</span>' +
            '<h2>Active SSO Sessions</h2>' +
            '<table class="access-sso-log-table">' +
            '<thead>' +
            '<tr>' +
            '<th>User</th>' +
            '<th>Created</th>' +
            '<th>Last Activity</th>' +
            '<th>IP Address</th>' +
            '<th>Actions</th>' +
            '</tr>' +
            '</thead>' +
            '<tbody>';
        
        sessions.forEach(function(session) {
            modalHtml += '<tr>' +
                '<td>' + escapeHtml(session.user_login) + '</td>' +
                '<td class="timestamp">' + escapeHtml(session.created_at) + '</td>' +
                '<td class="timestamp">' + escapeHtml(session.last_activity) + '</td>' +
                '<td>' + escapeHtml(session.ip_address) + '</td>' +
                '<td><button class="button button-small revoke-session" data-session="' + session.session_token + '">Revoke</button></td>' +
                '</tr>';
        });
        
        modalHtml += '</tbody></table></div></div>';
        
        $('body').append(modalHtml);
        $('#sessions-modal').show();
        
        // Handle close
        $('.access-sso-modal-close, #sessions-modal').on('click', function(e) {
            if (e.target === this) {
                $('#sessions-modal').remove();
            }
        });
        
        // Handle session revocation
        $('.revoke-session').on('click', function() {
            var sessionToken = $(this).data('session');
            revokeSession(sessionToken);
        });
    }
    
    function showLogsModal(logs) {
        var modalHtml = '<div id="logs-modal" class="access-sso-modal">' +
            '<div class="access-sso-modal-content">' +
            '<span class="access-sso-modal-close">&times;</span>' +
            '<h2>SSO Event Logs</h2>' +
            '<table class="access-sso-log-table">' +
            '<thead>' +
            '<tr>' +
            '<th>Time</th>' +
            '<th>Event</th>' +
            '<th>User</th>' +
            '<th>IP</th>' +
            '<th>Details</th>' +
            '</tr>' +
            '</thead>' +
            '<tbody>';
        
        logs.forEach(function(log) {
            var eventClass = '';
            if (log.event.includes('success') || log.event.includes('login')) {
                eventClass = 'success';
            } else if (log.event.includes('error') || log.event.includes('failed')) {
                eventClass = 'error';
            } else if (log.event.includes('suspicious')) {
                eventClass = 'warning';
            }
            
            modalHtml += '<tr>' +
                '<td class="timestamp">' + escapeHtml(log.timestamp) + '</td>' +
                '<td class="event ' + eventClass + '">' + escapeHtml(log.event) + '</td>' +
                '<td>' + escapeHtml(log.user_email || 'N/A') + '</td>' +
                '<td>' + escapeHtml(log.ip_address) + '</td>' +
                '<td>' + escapeHtml(JSON.stringify(log.details || '')) + '</td>' +
                '</tr>';
        });
        
        modalHtml += '</tbody></table></div></div>';
        
        $('body').append(modalHtml);
        $('#logs-modal').show();
        
        // Handle close
        $('.access-sso-modal-close, #logs-modal').on('click', function(e) {
            if (e.target === this) {
                $('#logs-modal').remove();
            }
        });
    }
    
    function revokeSession(sessionToken) {
        if (!confirm('Are you sure you want to revoke this session?')) {
            return;
        }
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'access_sso_revoke_session',
                nonce: accessSSOAdmin.nonce,
                session_token: sessionToken
            },
            success: function(response) {
                if (response.success) {
                    showNotice('Session revoked successfully', 'success');
                    $('#sessions-modal').remove();
                    viewActiveSessions(); // Refresh the modal
                } else {
                    showNotice(response.data.message || 'Failed to revoke session', 'error');
                }
            },
            error: function(xhr, status, error) {
                showNotice('AJAX error: ' + error, 'error');
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
        toggleSecretVisibility: toggleSecretVisibility,
        cleanupSessions: cleanupSessions,
        viewActiveSessions: viewActiveSessions,
        viewLogs: viewLogs,
        clearLogs: clearLogs
    };
    
})(jQuery);