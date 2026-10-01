<?php
/**
 * Decides who bills a member's MemberPress subscriptions: Access or MemberPress.
 */

if (!defined('ABSPATH')) {
    exit;
}

class AccessSSO_Billing_Owner {
    // Access provisions every MemberPress subscription with the manual gateway and
    // the Stripe subscription id (optionally suffixed with a product) as subscr_id.
    // MemberPress's own Stripe gateway bills legacy members, and its admin comps
    // use manual gateway with mp-sub- ids, so both fail this test.
    const ACCESS_GATEWAY = 'manual';
    const ACCESS_SUBSCR_ID_PREFIX = 'sub_';

    public static function is_access_billed_subscription($subscription) {
        $subscription = (array) $subscription;
        $gateway = isset($subscription['gateway']) ? (string) $subscription['gateway'] : '';
        $subscr_id = isset($subscription['subscr_id']) ? (string) $subscription['subscr_id'] : '';
        $status = isset($subscription['status']) ? (string) $subscription['status'] : '';

        return $gateway === self::ACCESS_GATEWAY
            && strpos($subscr_id, self::ACCESS_SUBSCR_ID_PREFIX) === 0
            && $status !== 'pending';
    }

    public static function has_access_billed_subscription(array $subscriptions) {
        foreach ($subscriptions as $subscription) {
            if (self::is_access_billed_subscription($subscription)) {
                return true;
            }
        }
        return false;
    }
}
