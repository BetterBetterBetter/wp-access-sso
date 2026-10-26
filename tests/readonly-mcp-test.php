<?php
/**
 * Behavioral test for the pure parts of AccessSSO_Readonly_MCP.
 * Run: php tests/readonly-mcp-test.php
 * Transaction shapes mirror real TSoL MemberPress rows (sanitized mirror, 2026-10-26).
 */

define('ABSPATH', __DIR__ . '/');
function add_action() {}
require __DIR__ . '/../includes/class-readonly-mcp.php';

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

$now = strtotime('2026-10-26 12:00:00 UTC');
$active = function ($row) use ($now) { return AccessSSO_Readonly_MCP::is_transaction_active($row, $now); };

check('complete lifetime transaction (0000 expiry) grants access', true, $active(array('status' => 'complete', 'expires_at' => '0000-00-00 00:00:00')));
check('complete transaction with null expiry grants access', true, $active(array('status' => 'complete', 'expires_at' => null)));
check('complete transaction expiring in the future grants access', true, $active(array('status' => 'complete', 'expires_at' => '2026-11-01 00:00:00')));
check('confirmed (trial) transaction in the future grants access', true, $active(array('status' => 'confirmed', 'expires_at' => '2026-10-27 00:00:00')));
check('complete transaction already expired grants nothing', false, $active(array('status' => 'complete', 'expires_at' => '2026-10-01 00:00:00')));
check('refunded lifetime transaction grants nothing', false, $active(array('status' => 'refunded', 'expires_at' => '0000-00-00 00:00:00')));
check('pending transaction grants nothing', false, $active(array('status' => 'pending', 'expires_at' => null)));

$memberships = AccessSSO_Readonly_MCP::build_memberships(
    array(array('id' => '7', 'product_id' => '100371', 'status' => 'active', 'created_at' => '2026-01-01 00:00:00')),
    array(
        array('id' => '1', 'product_id' => '100371', 'subscription_id' => '7', 'status' => 'complete', 'created_at' => '2026-10-01', 'expires_at' => '2026-11-01 00:00:00'),
        array('id' => '2', 'product_id' => '102090', 'subscription_id' => '0', 'status' => 'complete', 'created_at' => '2025-05-01', 'expires_at' => '0000-00-00 00:00:00'),
        array('id' => '3', 'product_id' => '555', 'subscription_id' => '0', 'status' => 'failed', 'created_at' => '2025-05-01', 'expires_at' => null),
    ),
    $now
);
check('recurring subscription and one-time purchase both listed; failed one-time ignored', 2, count($memberships));
check('subscription is active through its paid transaction', true, $memberships[0]['active']);
check('subscription expiry comes from its latest transaction', '2026-11-01 00:00:00', $memberships[0]['expiresAt']);
check('one-time lifetime purchase is listed as active', true, $memberships[1]['active']);
check('one-time lifetime purchase is flagged lifetime', true, $memberships[1]['lifetime']);
check('one-time lifetime purchase reports no expiry', null, $memberships[1]['expiresAt']);
check('one-time purchase is tagged with its source', 'one_time', $memberships[1]['source']);

$lapsed = AccessSSO_Readonly_MCP::build_memberships(
    array(array('id' => '9', 'product_id' => '100371', 'status' => 'cancelled', 'created_at' => '2025-01-01')),
    array(array('id' => '4', 'product_id' => '100371', 'subscription_id' => '9', 'status' => 'complete', 'created_at' => '2025-09-01', 'expires_at' => '2025-10-01 00:00:00')),
    $now
);
check('cancelled subscription whose last period ended is inactive', false, $lapsed[0]['active']);

$line = AccessSSO_Readonly_MCP::redact_log_line('Stripe error for jane.doe@gmail.com using sk_live_51HabcXYZ and whsec_abc123 token=abc');
check('Stripe secret key is redacted', false, strpos($line, 'sk_live_') !== false);
check('Stripe webhook secret is redacted', false, strpos($line, 'whsec_') !== false);
check('customer email is masked but domain kept', true, strpos($line, '[email]@gmail.com') !== false && strpos($line, 'jane.doe') === false);
check('token value is redacted', true, strpos($line, 'token=[REDACTED]') !== false);

check('no ability runs without a signed request or an admin', false, AccessSSO_Readonly_MCP::can_run_abilities());

exit($failures > 0 ? 1 : 0);
