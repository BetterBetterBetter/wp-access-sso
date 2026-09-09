/**
 * Access Platform SSO - Account Manage Detector
 *
 * Members billed through Access have no MemberPress subscription to cancel, so
 * the MemberPress account page shows them nothing actionable. This script
 * finds the MemberPress account UI and adds a clear "manage or cancel" button
 * that sends them to Access.
 *
 * Only enqueued for logged-in users with the `access_platform_id` user meta
 * (see access-platform-sso.php). If the PHP `mepr_account_nav` hook already
 * rendered a link, this script only adds the notice above the subscriptions
 * table and never duplicates the button.
 */
(function () {
    'use strict';

    var config = window.accessSSOAccountManage || {};
    if (!config.manage_url) {
        return;
    }

    // Containers that identify the MemberPress account page, most specific first.
    var ACCOUNT_SELECTORS = [
        '#mepr-account-nav',
        '.mepr-account-nav',
        '.mepr_pro_account_nav',
        '#mepr-account-subscriptions',
        '.mepr-account-subscriptions',
        '.mepr-account-table',
        '#mepr-account-home',
        '.mepr-account-home',
        '.mp_wrapper .mepr-nav-item'
    ];

    var NOTICE_ANCHOR_SELECTORS = [
        '#mepr-account-subscriptions',
        '.mepr-account-subscriptions',
        '.mepr-account-table',
        '#mepr-account-home',
        '.mepr-account-home'
    ];

    function firstMatch(selectors) {
        for (var i = 0; i < selectors.length; i++) {
            var el = document.querySelector(selectors[i]);
            if (el) {
                return el;
            }
        }
        return null;
    }

    function buildButton(className) {
        var link = document.createElement('a');
        link.href = config.manage_url;
        link.className = className;
        link.setAttribute('data-access-manage-billing', '1');
        link.textContent = config.button_text || 'Manage or cancel your membership';
        return link;
    }

    function inject() {
        if (!firstMatch(ACCOUNT_SELECTORS)) {
            return false;
        }

        var hasPhpNavLink = Boolean(document.querySelector('[data-access-manage-billing="1"]'));

        // Notice card above the subscriptions list (or account home).
        if (!document.querySelector('.access-manage-billing-notice')) {
            var anchor = firstMatch(NOTICE_ANCHOR_SELECTORS);
            if (anchor) {
                var notice = document.createElement('div');
                notice.className = 'access-manage-billing-notice';
                notice.setAttribute('role', 'note');

                var text = document.createElement('p');
                text.className = 'access-manage-billing-text';
                text.textContent = config.help_text || 'Your billing is handled by your Access account.';
                notice.appendChild(text);
                notice.appendChild(buildButton('access-manage-billing-button'));

                anchor.parentNode.insertBefore(notice, anchor);
            }
        }

        // Nav item, only when PHP did not already render one.
        if (!hasPhpNavLink) {
            var nav = firstMatch(['#mepr-account-nav', '.mepr-account-nav', '.mepr_pro_account_nav']);
            if (nav && !nav.querySelector('[data-access-manage-billing="1"]')) {
                var item = document.createElement('span');
                item.className = 'mepr-nav-item access-manage-billing-nav';
                item.appendChild(buildButton('access-manage-billing-link'));
                nav.appendChild(item);
            }
        }

        return true;
    }

    function init() {
        if (inject()) {
            return;
        }
        // Account content can render after load (tabs, AJAX). Watch briefly.
        if (!('MutationObserver' in window)) {
            return;
        }
        var observer = new MutationObserver(function () {
            if (inject()) {
                observer.disconnect();
            }
        });
        observer.observe(document.body, { childList: true, subtree: true });
        setTimeout(function () { observer.disconnect(); }, 10000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
