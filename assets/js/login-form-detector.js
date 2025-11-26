/**
 * Access Platform SSO - Login Form Detector
 * Automatically detects and enhances login forms across the site
 * Supports: MemberPress, LearnDash, WooCommerce, Ultimate Member, and generic WordPress forms
 */

(function() {
    'use strict';

    // Configuration from WordPress
    const config = window.accessSSODetector || {};
    
    // Common login form selectors for various plugins
    const LOGIN_FORM_SELECTORS = {
        // WordPress Core
        wordpress: [
            '#loginform',
            '.login-form',
            'form[name="loginform"]',
            '.wp-login-form'
        ],
        
        // MemberPress - based on official docs: https://memberpress.com/docs/memberpress-login-page/
        // Form uses class .mepr-login-form or .mepr-form with name="mepr-loginform"
        // Wrapped in .mepr-login container
        memberpress: [
            '.mepr-login-form',                          // Main form class
            'form.mepr-form[name="mepr-loginform"]',     // Form with name attribute (hyphenated)
            'form[name="mepr-loginform"]',              // Any form with this name
            '.mepr-login form',                          // Form inside .mepr-login wrapper
            '.mepr-login-widget form',                   // Widget login form
            '#mepr-login-form',                          // ID selector
            '[class*="mepr-login"] form',               // Any mepr-login class variant
            '.mepr_login_form',                          // Underscore variant (older versions)
            'form.mepr-form:has(input.mepr-username)',  // Form with MemberPress username input
            'form:has(input.mepr-username):has(input.mepr-password)' // Form with both MP fields
        ],
        
        // LearnDash
        learndash: [
            '.learndash-login-form',
            '#learndash-login-form',
            '.ld-login-form',
            '.ld-login',
            'form.learndash-wrapper-login',
            '[class*="learndash"] form[action*="login"]',
            '.sfwd-login-form'
        ],
        
        // WooCommerce
        woocommerce: [
            '.woocommerce-form-login',
            'form.woocommerce-form-login',
            '.woocommerce-form--login',
            '#customer_login .woocommerce-form-login',
            '.woocommerce-MyAccount-content form.login'
        ],
        
        // Ultimate Member
        ultimatemember: [
            '.um-form form',
            '.um-login form',
            'form.um-form',
            '.um-login-form'
        ],
        
        // BuddyPress / BuddyBoss
        buddypress: [
            '#bp-login-widget-form',
            '.bp-login-widget-form',
            '#sidebar-login-form',
            'form#bp-login-form'
        ],
        
        // Generic patterns (catch-all)
        generic: [
            'form[action*="wp-login"]',
            'form[action*="login"]',
            'form:has(input[name="log"]):has(input[name="pwd"])',
            'form:has(input[type="password"]):has(input[name*="user"], input[name*="email"], input[name*="log"])',
            '.login-form form',
            '#login-form',
            '.member-login form',
            '.user-login form'
        ]
    };

    // Track forms we've already processed
    const processedForms = new WeakSet();

    /**
     * Build the SSO login URL
     */
    function buildSSOUrl() {
        if (!config.platform_url || !config.site_id) {
            console.warn('Access SSO: Missing platform_url or site_id configuration');
            return null;
        }

        const callbackUrl = config.callback_url || (window.location.origin + '/?access_sso_callback=1');
        
        // Build the SSO URL with all required parameters
        const params = new URLSearchParams({
            site_id: config.site_id,
            callback: callbackUrl,
            redirect_to: callbackUrl,
            return_to: callbackUrl,
            redirect_url: callbackUrl
        });

        return `${config.platform_url}/login?${params.toString()}`;
    }

    /**
     * Create the SSO button element
     */
    function createSSOButton(formType = 'generic') {
        const ssoUrl = buildSSOUrl();
        if (!ssoUrl) return null;

        // Create wrapper
        const wrapper = document.createElement('div');
        wrapper.className = 'access-sso-login-wrapper access-sso-injected';
        wrapper.setAttribute('data-form-type', formType);

        // Create button
        const button = document.createElement('a');
        button.href = ssoUrl;
        button.className = 'access-sso-login-button';
        button.textContent = config.button_text || 'Login with Access Platform';
        button.setAttribute('role', 'button');
        button.setAttribute('aria-label', 'Login with Access Platform Single Sign-On');

        // Create divider
        const divider = document.createElement('div');
        divider.className = 'access-sso-divider';
        const dividerText = document.createElement('span');
        dividerText.textContent = config.divider_text || 'or';
        divider.appendChild(dividerText);

        wrapper.appendChild(button);
        wrapper.appendChild(divider);

        // Add click handler
        button.addEventListener('click', function(e) {
            button.classList.add('loading');
            button.textContent = 'Redirecting...';
            
            // Track the click
            trackSSOClick(formType);
        });

        return wrapper;
    }

    /**
     * Track SSO button clicks for analytics
     */
    function trackSSOClick(formType) {
        console.log('Access SSO: Login button clicked', { formType, url: window.location.href });
        
        // Send to analytics if available
        if (typeof gtag !== 'undefined') {
            gtag('event', 'sso_login_click', {
                form_type: formType,
                page_url: window.location.href
            });
        }

        // Send to WordPress for tracking
        if (config.ajaxurl && config.nonce) {
            fetch(config.ajaxurl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    action: 'access_sso_track_click',
                    nonce: config.nonce,
                    form_type: formType,
                    page_url: window.location.href
                })
            }).catch(() => {}); // Ignore errors, don't block navigation
        }
    }

    /**
     * Inject SSO button into a form
     */
    function injectSSOButton(form, formType) {
        // Skip if already processed
        if (processedForms.has(form)) return false;
        
        // Skip if already has an SSO button
        if (form.querySelector('.access-sso-login-wrapper, .access-sso-injected')) return false;
        
        // Check if parent already has SSO button (for nested forms)
        if (form.closest('.access-sso-login-wrapper')) return false;

        const button = createSSOButton(formType);
        if (!button) return false;

        // Find the best insertion point
        let insertionPoint = null;
        let insertMethod = 'before'; // 'before', 'after', 'prepend'

        // Try to find a submit button or form actions
        const submitButton = form.querySelector(
            'input[type="submit"], button[type="submit"], .submit, .login-submit, ' +
            '.mepr-submit, .ld-login-button, .woocommerce-form-login__submit'
        );
        
        const passwordField = form.querySelector('input[type="password"]');
        const firstInput = form.querySelector('input:not([type="hidden"]):not([type="submit"])');

        if (firstInput) {
            // Insert before the first visible input
            insertionPoint = firstInput.closest('p, div, .form-row, .mepr-form-row, label') || firstInput;
            insertMethod = 'before';
        } else if (passwordField) {
            insertionPoint = passwordField.closest('p, div, .form-row') || passwordField;
            insertMethod = 'before';
        } else if (submitButton) {
            insertionPoint = submitButton.closest('p, div, .form-row') || submitButton;
            insertMethod = 'before';
        } else {
            // Prepend to form
            insertionPoint = form;
            insertMethod = 'prepend';
        }

        // Insert the button
        try {
            if (insertMethod === 'prepend') {
                form.insertBefore(button, form.firstChild);
            } else if (insertMethod === 'before') {
                insertionPoint.parentNode.insertBefore(button, insertionPoint);
            } else {
                insertionPoint.parentNode.insertBefore(button, insertionPoint.nextSibling);
            }
            
            processedForms.add(form);
            console.log('Access SSO: Injected button into', formType, 'form', form);
            return true;
        } catch (e) {
            console.error('Access SSO: Failed to inject button', e);
            return false;
        }
    }

    /**
     * Detect and enhance all login forms on the page
     */
    function detectAndEnhanceForms() {
        let formsEnhanced = 0;

        // Get enabled form types from config
        const enabledTypes = config.enabled_form_types || Object.keys(LOGIN_FORM_SELECTORS);

        // Process each form type
        enabledTypes.forEach(formType => {
            const selectors = LOGIN_FORM_SELECTORS[formType];
            if (!selectors) return;

            selectors.forEach(selector => {
                try {
                    const forms = document.querySelectorAll(selector);
                    forms.forEach(form => {
                        // Ensure it's actually a form or contains a form
                        const targetForm = form.tagName === 'FORM' ? form : form.querySelector('form');
                        if (targetForm && injectSSOButton(targetForm, formType)) {
                            formsEnhanced++;
                        }
                    });
                } catch (e) {
                    // Selector might not be valid in all browsers (e.g., :has())
                    // Silently ignore
                }
            });
        });

        if (formsEnhanced > 0) {
            console.log(`Access SSO: Enhanced ${formsEnhanced} login form(s)`);
        }

        return formsEnhanced;
    }

    /**
     * Watch for dynamically added forms (SPA support, AJAX-loaded content)
     */
    function watchForNewForms() {
        if (!window.MutationObserver) return;

        const observer = new MutationObserver((mutations) => {
            let shouldScan = false;
            
            mutations.forEach(mutation => {
                if (mutation.addedNodes.length > 0) {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Check if added node contains or is a form
                            if (node.tagName === 'FORM' || node.querySelector?.('form')) {
                                shouldScan = true;
                            }
                            // Check for login-related classes
                            if (node.className && typeof node.className === 'string' &&
                                (node.className.includes('login') || 
                                 node.className.includes('mepr') || 
                                 node.className.includes('learndash') ||
                                 node.className.includes('woocommerce'))) {
                                shouldScan = true;
                            }
                        }
                    });
                }
            });

            if (shouldScan) {
                // Debounce the scan
                clearTimeout(watchForNewForms.timeout);
                watchForNewForms.timeout = setTimeout(detectAndEnhanceForms, 100);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    /**
     * Check if current page is excluded from SSO injection
     */
    function isPageExcluded() {
        const excludedRoutes = config.excluded_routes || [];
        if (!excludedRoutes.length) return false;

        const currentPath = window.location.pathname.toLowerCase();
        const currentUrl = window.location.href.toLowerCase();

        for (const route of excludedRoutes) {
            if (!route) continue;
            const pattern = route.toLowerCase().trim();
            
            // Check if it's a regex pattern (starts and ends with /)
            if (pattern.startsWith('/') && pattern.endsWith('/') && pattern.length > 2) {
                try {
                    const regex = new RegExp(pattern.slice(1, -1), 'i');
                    if (regex.test(currentPath) || regex.test(currentUrl)) {
                        console.log('Access SSO: Page excluded by regex pattern:', pattern);
                        return true;
                    }
                } catch (e) {
                    // Invalid regex, treat as string
                }
            }
            
            // Exact path match
            if (currentPath === pattern || currentPath === pattern + '/') {
                console.log('Access SSO: Page excluded by exact match:', pattern);
                return true;
            }
            
            // Starts with match (for path prefixes like /checkout)
            if (pattern.endsWith('*')) {
                const prefix = pattern.slice(0, -1);
                if (currentPath.startsWith(prefix)) {
                    console.log('Access SSO: Page excluded by prefix match:', pattern);
                    return true;
                }
            }
            
            // Contains match
            if (currentPath.includes(pattern) || currentUrl.includes(pattern)) {
                console.log('Access SSO: Page excluded by contains match:', pattern);
                return true;
            }
        }

        return false;
    }

    /**
     * Initialize the detector
     */
    function init() {
        // Don't run if user is already logged in (unless config says otherwise)
        if (!config.show_when_logged_in && document.body.classList.contains('logged-in')) {
            console.log('Access SSO: User already logged in, skipping form detection');
            return;
        }

        // Don't run if disabled
        if (config.disabled) {
            console.log('Access SSO: Form detection disabled');
            return;
        }

        // Don't run on admin pages
        if (document.body.classList.contains('wp-admin')) {
            return;
        }

        // Don't run on excluded pages
        if (isPageExcluded()) {
            console.log('Access SSO: Current page is excluded, skipping form detection');
            return;
        }

        // Run initial detection
        const formsFound = detectAndEnhanceForms();

        // Watch for dynamically added forms
        watchForNewForms();

        // Also run after a short delay (for slow-loading content)
        setTimeout(detectAndEnhanceForms, 1000);
        setTimeout(detectAndEnhanceForms, 3000);

        console.log('Access SSO: Form detector initialized');
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Also run on window load (catches late-loading forms)
    window.addEventListener('load', function() {
        setTimeout(detectAndEnhanceForms, 500);
    });

    // Expose API for manual usage
    window.AccessSSODetector = {
        detect: detectAndEnhanceForms,
        injectInto: function(selector) {
            const form = document.querySelector(selector);
            if (form) {
                return injectSSOButton(form, 'manual');
            }
            return false;
        },
        config: config,
        selectors: LOGIN_FORM_SELECTORS
    };

})();

