<?php
/**
 * Behavioral test for AccessSSO_Billing_Owner. Run: php tests/billing-owner-test.php
 * Fixtures mirror real TSoL MemberPress subscriptions (2026-09-30).
 */

define('ABSPATH', __DIR__ . '/');
require __DIR__ . '/../includes/class-billing-owner.php';

$failures = 0;
function check($label, $expected, $actual) {
    global $failures;
    if ($expected === $actual) {
        echo "ok   - {$label}\n";
        return;
    }
    $failures++;
    echo "FAIL - {$label}: expected " . var_export($expected, true) . ', got ' . var_export($actual, true) . "\n";
}

$native = array('gateway' => 'r6b3nq-4b', 'subscr_id' => 'sub_1SF61uHha8d7', 'status' => 'active');
$access = array('gateway' => 'manual', 'subscr_id' => 'sub_1Sm2qNHha8d7', 'status' => 'active');

check('legacy member billed by MemberPress Stripe (hyrum, joe, christa) gets no banner', false,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array($native)));
check('Access-billed active member (frederi825) gets the banner', true,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array($access)));
check('Access-billed member who cancelled in Access (wsternitzky) still gets the banner', true,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array(array_merge($access, array('status' => 'cancelled')))));
check('Access bundle subscr_id (ui-safe) counts as Access', true,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array(array_merge($access, array('subscr_id' => 'sub_1TyHM2Hha8d7-3e8c-4a1b')))));
check('Access bundle subscr_id (legacy colon) counts as Access', true,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array(array_merge($access, array('subscr_id' => 'sub_1TyHM2Hha8d7:3e8c-4a1b')))));
check('MemberPress admin manual comp (mp-sub-) is not Access-billed', false,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array(array('gateway' => 'manual', 'subscr_id' => 'mp-sub-6bb2', 'status' => 'active'))));
check('member with both a legacy and an Access subscription gets the banner', true,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array($native, $access)));
check('pending-only Access subscription (abandoned checkout) gets no banner', false,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array(array_merge($access, array('status' => 'pending')))));
check('no subscriptions gets no banner', false,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array()));
check('stdClass rows (e.g. $wpdb OBJECT results) are accepted', true,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array((object) $access)));
$cancelled_access = array_merge($access, array('status' => 'cancelled'));
check('cancelled Access sub + active MemberPress-billed sub: MemberPress now bills them, no banner', false,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array($cancelled_access, $native)));
check('cancelled Access sub + cancelled MemberPress sub: Access is still where they left, banner', true,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array($cancelled_access, array_merge($native, array('status' => 'cancelled')))));
check('cancelled Access sub + paused (suspended) MemberPress-billed sub: still MemberPress-billed, no banner', false,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array($cancelled_access, array_merge($native, array('status' => 'suspended')))));
check('suspended (paused) Access sub keeps the banner even with an active MemberPress sub', true,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array(array_merge($access, array('status' => 'suspended')), $native)));
check('gateway match is exact (no partial "manual" matches)', false,
    AccessSSO_Billing_Owner::has_access_billed_subscription(array(array_merge($access, array('gateway' => 'manual-test')))));

exit($failures === 0 ? 0 : 1);
