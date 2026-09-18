<?php
declare(strict_types=1);

require_once __DIR__ . '/../private/functions.php';

$failures = [];

function expect_same(string $label, $expected, $actual): void {
    global $failures;
    if ($actual !== $expected) {
        $failures[] = $label . ': expected ' . var_export($expected, true)
            . ', got ' . var_export($actual, true);
    }
}

$defaults = cidr_guardrails([
    'ipv4_warning_prefix' => '24',
    'ipv4_hard_prefix' => '0',
    'ipv6_warning_prefix' => '64',
    'ipv6_hard_prefix' => '0',
]);

$cases = [
    '203.0.113.7'   => 'allow',
    '10.0.0.0/25'  => 'allow',
    '10.0.0.0/24'  => 'warn',
    '10.0.0.0/1'   => 'warn',
    '10.0.0.0/0'   => 'reject',
    '2001:db8::1'   => 'allow',
    '2001:db8::/65' => 'allow',
    '2001:db8::/64' => 'warn',
    '2001:db8::/1'  => 'warn',
    '2001:db8::/0'  => 'reject',
];
foreach ($cases as $input => $status) {
    expect_same("policy {$input}", $status, ip_ban_policy($input, $defaults)['status']);
}
expect_same('non-canonical IPv4 /0 rejected', 'reject', ip_ban_policy('203.0.113.7/0', $defaults)['status']);
expect_same('non-canonical IPv6 /0 rejected', 'reject', ip_ban_policy('2001:db8::1/0', $defaults)['status']);
expect_same('legacy /0 remains normalizable for removal', '203.0.113.7/0', normalize_ip_or_cidr('203.0.113.7/0'));

$malformed = cidr_guardrails([
    'ipv4_warning_prefix' => 'garbage',
    'ipv4_hard_prefix' => '-1',
    'ipv6_warning_prefix' => '999',
    'ipv6_hard_prefix' => '80',
]);
expect_same('malformed IPv4 warning defaults', 24, $malformed['ipv4_warning_prefix']);
expect_same('malformed IPv4 hard preserves /0 floor', 0, $malformed['ipv4_hard_prefix']);
expect_same('IPv6 warning clamps to family maximum', 128, $malformed['ipv6_warning_prefix']);
expect_same('valid IPv6 hard retained', 80, $malformed['ipv6_hard_prefix']);
$conflict = cidr_guardrails([
    'ipv4_warning_prefix' => '8',
    'ipv4_hard_prefix' => '16',
    'ipv6_warning_prefix' => '32',
    'ipv6_hard_prefix' => '64',
]);
expect_same('IPv4 warning cannot conflict with hard cutoff', 16, $conflict['ipv4_warning_prefix']);
expect_same('IPv6 warning cannot conflict with hard cutoff', 64, $conflict['ipv6_warning_prefix']);

$bulk = ip_ban_preflight(['203.0.113.5', '10.0.0.0/24', '0.0.0.0/0', 'bad'], $defaults);
expect_same('mixed bulk has two writable entries', 2, count($bulk['entries']));
expect_same('mixed bulk detects warning before writes', ['10.0.0.0/24'], $bulk['warnings']);
expect_same('mixed bulk detects hard reject before writes', ['0.0.0.0/0'], $bulk['rejected']);
expect_same('mixed bulk detects invalid before writes', ['bad'], $bulk['invalid']);

expect_same('exact API override accepted', true, broad_subnet_override_requested(['confirm_broad_subnets' => 'yes']));
foreach (['1', 'true', 'YES', 'yes '] as $override) {
    expect_same("inexact API override {$override} rejected", false,
        broad_subnet_override_requested(['confirm_broad_subnets' => $override]));
}
expect_same('missing API override rejected', false, broad_subnet_override_requested([]));

$_SESSION = [];
$confirmation_preflight = ip_ban_preflight(['10.0.0.0/24'], $defaults);
$payload = [
    'ip' => '10.0.0.0/24',
    'reason' => 'test',
    'duration' => '1h',
    'warnings' => $confirmation_preflight['warnings'],
    'guardrails' => $defaults,
];
expect_same('exact confirmation remains current', true,
    broad_add_confirmation_is_current($payload, $confirmation_preflight, $defaults));
$changed_guardrails = $defaults;
$changed_guardrails['ipv4_warning_prefix'] = 20;
expect_same('changed guardrails make confirmation stale', false,
    broad_add_confirmation_is_current($payload, $confirmation_preflight, $changed_guardrails));
$changed_preflight = ip_ban_preflight(['10.0.0.0/25'], $defaults);
expect_same('altered warnings make confirmation stale', false,
    broad_add_confirmation_is_current($payload, $changed_preflight, $defaults));
$token = broad_add_confirmation_issue($payload);
expect_same('one-use confirmation accepts issued token', $payload, broad_add_confirmation_consume($token));
expect_same('one-use confirmation rejects replay', null, broad_add_confirmation_consume($token));
$token = broad_add_confirmation_issue($payload);
expect_same('confirmation rejects bypass token', null, broad_add_confirmation_consume($token . 'x'));
expect_same('failed confirmation also consumes token', null, broad_add_confirmation_consume($token));
$token = broad_add_confirmation_issue($payload);
$_SESSION['broad_add_confirmation']['expires'] = time() - 1;
expect_same('expired confirmation rejected', null, broad_add_confirmation_consume($token));

$valid = [
    '203.0.113.7'       => '203.0.113.7',
    '10.0.0.0/8'       => '10.0.0.0/8',
    '2001:0db8::1'      => '2001:db8::1',
    '2001:db8::/32'     => '2001:db8::/32',
    '255.255.255.255/1' => '255.255.255.255/1',
    'ffff::/1'          => 'ffff::/1',
];
foreach ($valid as $input => $normalized) {
    expect_same("normalize {$input}", $normalized, normalize_ip_or_cidr($input));
}

expect_same('IPv4 ACL match', true, ip_in_cidr('10.1.2.3', '10.0.0.0/8'));
expect_same('IPv6 ACL match', true, ip_in_cidr('2001:db8::1', '2001:db8::/32'));
foreach (['10.0.0.0/-1', '10.0.0.0/33', '10.0.0.0/nope'] as $cidr) {
    expect_same("reject ACL {$cidr}", false, ip_in_cidr('10.1.2.3', $cidr));
}
expect_same('reject IPv6 ACL /129', false, ip_in_cidr('2001:db8::1', '2001:db8::/129'));

if ($failures) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "validation checks passed\n";
