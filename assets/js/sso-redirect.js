/* Access Platform SSO Frontend JavaScript */

(function($) {
    'use strict';
    
    $(document).ready(function() {
        
        // Handle SSO login button clicks
        $('.access-sso-login-button').on('click', function(e) {
            var $button = $(this);
            
            // Add loading state
            $button.addClass('loading').text('Redirecting...');
            
            // Allow natural navigation
            return true;
        });
        
        // Check for SSO errors in URL
        var urlParams = new URLSearchParams(window.location.search);
        var error = urlParams.get('sso_error');
        if (error) {
            showError(decodeURIComponent(error));
        }
        
        // Auto-retry failed SSO attempts
        var retryAttempt = urlParams.get('sso_retry');
        if (retryAttempt && parseInt(retryAttempt) < 3) {
            setTimeout(function() {
                retrySSO(parseInt(retryAttempt) + 1);
            }, 2000);
        }
        
    });
    
    function showError(message) {
        var $error = $('<div class="access-sso-error">' +
            '<p><strong>SSO Error:</strong> ' + escapeHtml(message) + '</p>' +
            '<p><a href="#" id="retry-sso">Try again</a> or <a href="' + window.location.pathname + '">use regular login</a></p>' +
            '</div>');
        
        $('#loginform').before($error);
        
        $('#retry-sso').on('click', function(e) {
            e.preventDefault();
            retrySSO(1);
        });
        
    }
    
    function retrySSO(attempt) {
        var $button = $('.access-sso-login-button');
        if ($button.length === 0) {
            return;
        }
        
        var href = $button.attr('href');
        var separator = href.includes('?') ? '&' : '?';
        var retryUrl = href + separator + 'sso_retry=' + attempt;
        
        window.location.href = retryUrl;
    }
    
    function escapeHtml(text) {
        var map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }
    
    // Handle browser back button after SSO login
    window.addEventListener('pageshow', function(event) {
        if (event.persisted && window.location.search.includes('access_sso_callback=1')) {
            // Page was restored from cache after SSO callback
            // Redirect to clean URL
            var cleanUrl = window.location.pathname + window.location.hash;
            window.location.replace(cleanUrl);
        }
    });
    
    // Keyboard accessibility for SSO button
    $('.access-sso-login-button').on('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            $(this).trigger('click');
        }
    });
    
    // Make functions available globally for debugging
    window.accessSSOFrontend = {
        showError: showError,
        retrySSO: retrySSO
    };
    
})(jQuery);
