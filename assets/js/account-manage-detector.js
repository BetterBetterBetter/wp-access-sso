/**
 * Access Platform SSO - Account Manage Detector
 *
 * Members billed through Access have no MemberPress subscription to cancel, so
 * the MemberPress account page shows them nothing actionable. This script
 * finds the MemberPress account page and adds one banner, directly below the
 * account nav, with a "manage or cancel" button that sends them to Access.
 *
 * Only enqueued for logged-in users with the `access_platform_id` user meta
 * (see access-platform-sso.php). The banner is never placed inside the nav:
 * MemberPress lays the nav out with flex-wrap, and anything injected between
 * its tabs breaks the row.
 */
(function () {
    'use strict';

    var config = window.accessSSOAccountManage || {};
    if (!config.manage_url) {
        return;
    }

    var NAV_SELECTOR = '#mepr-account-nav, .mepr-nav, .mepr-account-nav, .mepr_pro_account_nav';

    // Anything that identifies the MemberPress account page.
    var ACCOUNT_SELECTORS = [
        NAV_SELECTOR,
        '.mepr-account-table',
        '#mepr-account-home',
        '#mepr-account-subscriptions',
        '#mepr-account-payments',
        '.mp_wrapper .mepr-nav-item'
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

    function buildNotice() {
        var notice = document.createElement('div');
        notice.className = 'access-manage-billing-notice';
        notice.setAttribute('role', 'note');

        var text = document.createElement('p');
        text.className = 'access-manage-billing-text';
        text.textContent = config.help_text || 'Your billing is handled by your Access account.';

        var link = document.createElement('a');
        link.href = config.manage_url;
        link.className = 'access-manage-billing-button';
        link.setAttribute('data-access-manage-billing', '1');
        link.textContent = config.button_text || 'Manage or cancel your membership';

        notice.appendChild(text);
        notice.appendChild(link);
        return notice;
    }

    /**
     * Decide where the banner goes. Order of preference:
     *   1. immediately after the account nav (outside it)
     *   2. immediately before the subscriptions/payments table
     *   3. at the top of a known account content container
     */
    function placeNotice(notice) {
        var nav = document.querySelector(NAV_SELECTOR);
        if (nav && nav.parentNode) {
            nav.insertAdjacentElement('afterend', notice);
            return true;
        }

        var table = document.querySelector('.mepr-account-table');
        if (table) {
            // Walk up out of any wrapper that is itself inside the nav.
            var target = table.closest(NAV_SELECTOR) ? null : table;
            if (target && target.parentNode) {
                target.insertAdjacentElement('beforebegin', notice);
                return true;
            }
        }

        var content = firstMatch(['#mepr-account-home', '#mepr-account-subscriptions', '#mepr-account-payments', '.mp_wrapper']);
        if (content && !content.closest(NAV_SELECTOR)) {
            content.insertAdjacentElement('afterbegin', notice);
            return true;
        }

        return false;
    }

    function inject() {
        if (!firstMatch(ACCOUNT_SELECTORS)) {
            return false;
        }
        if (document.querySelector('.access-manage-billing-notice')) {
            return true;
        }
        return placeNotice(buildNotice());
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
