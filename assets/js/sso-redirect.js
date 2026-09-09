/* Access Platform SSO Frontend JavaScript */

(function($) {
    'use strict';

    var SESSION_STORAGE_TEST_KEY = '__access_sso_storage_test__';
    var COOKIE_TEST_NAME = '__access_sso_cookie_test__';

    /**
     * Browser storage can exist but throw a SecurityError when privacy settings
     * deny access. Test both property access and writes before starting SSO.
     */
    function isSessionStorageAvailable() {
        try {
            window.sessionStorage.setItem(SESSION_STORAGE_TEST_KEY, '1');
            window.sessionStorage.removeItem(SESSION_STORAGE_TEST_KEY);
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * WordPress authentication requires a first-party cookie, independently of
     * whether sessionStorage is available.
     */
    function areCookiesAvailable() {
        try {
            document.cookie = COOKIE_TEST_NAME + '=1; path=/; SameSite=Lax';

            return document.cookie.split('; ').some(function(cookie) {
                return cookie.indexOf(COOKIE_TEST_NAME + '=') === 0;
            });
        } catch (error) {
            return false;
        } finally {
            try {
                document.cookie = COOKIE_TEST_NAME + '=; Max-Age=0; path=/; SameSite=Lax';
            } catch (error) {
                // Cookie access is blocked; there is nothing to clean up.
            }
        }
    }

    function safeSessionStorageGetItem(key) {
        try {
            return window.sessionStorage.getItem(key);
        } catch (error) {
            return null;
        }
    }

    function safeSessionStorageSetItem(key, value) {
        try {
            window.sessionStorage.setItem(key, value);
            return true;
        } catch (error) {
            return false;
        }
    }

    function safeSessionStorageRemoveItem(key) {
        try {
            window.sessionStorage.removeItem(key);
            return true;
        } catch (error) {
            return false;
        }
    }

    // Default to the existing flow if the preflight itself fails unexpectedly.
    var browserSupport = {
        storageAvailable: true,
        cookiesAvailable: true,
        available: true
    };

    try {
        browserSupport.storageAvailable = isSessionStorageAvailable();
        browserSupport.cookiesAvailable = areCookiesAvailable();
        browserSupport.available = browserSupport.storageAvailable && browserSupport.cookiesAvailable;
    } catch (error) {
        console.warn('Access SSO: Browser capability detection failed; continuing with the existing flow.', error);
    }

    function showBrowserStorageWarning() {
        if ($('#access-sso-browser-storage-warning').length) {
            return;
        }

        var $warning = $('<div>', {
            id: 'access-sso-browser-storage-warning',
            class: 'access-sso-browser-storage-warning',
            role: 'alert',
            'aria-live': 'assertive'
        });

        $warning.append($('<h2>').text('Browser privacy settings are preventing sign-in'));
        $warning.append($('<p>').text('This site requires first-party cookies and browser storage to securely keep you signed in.'));
        $warning.append(
            $('<p>').append(
                document.createTextNode('If you are using Brave, change the Cookies setting from '),
                $('<strong>').text('Block all cookies'),
                document.createTextNode(' to '),
                $('<strong>').text('Block third-party cookies'),
                document.createTextNode(', then reload this page.')
            )
        );
        $warning.append($('<p>').text('You can continue blocking third-party cookies, ads, and trackers.'));

        var $reloadButton = $('<button>', {
            type: 'button',
            class: 'button access-sso-reload-button',
            text: 'Reload Page'
        });
        $reloadButton.on('click', function() {
            window.location.reload();
        });
        $warning.append($reloadButton);

        var $target = $('.access-sso-login-wrapper, #loginform, .mepr-login-form, .learndash-login-form, .woocommerce-form-login, .um-login').first();
        if ($target.length) {
            $target.before($warning);
        } else {
            $('body').prepend($warning);
        }
    }

    function blockSSOForUnsupportedBrowser() {
        showBrowserStorageWarning();

        $('.access-sso-login-button')
            .addClass('access-sso-disabled')
            .attr('aria-disabled', 'true')
            .attr('tabindex', '-1');
        $('.access-sso-login-wrapper').addClass('access-sso-disabled');

        // Also catches SSO buttons added later by another integration.
        $(document).on('click.accessSSOBrowserSupport', '.access-sso-login-button', function(event) {
            event.preventDefault();
            event.stopImmediatePropagation();
            showBrowserStorageWarning();
            return false;
        });
    }

    window.AccessSSOBrowserSupport = {
        isAvailable: function() {
            return browserSupport.available;
        },
        storageAvailable: browserSupport.storageAvailable,
        cookiesAvailable: browserSupport.cookiesAvailable,
        showWarning: showBrowserStorageWarning
    };
    
    $(document).ready(function() {
        if (!browserSupport.available) {
            blockSSOForUnsupportedBrowser();
            return;
        }
        
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
        showBrowserStorageWarning: showBrowserStorageWarning,
        retrySSO: retrySSO
    };
    
})(jQuery);
