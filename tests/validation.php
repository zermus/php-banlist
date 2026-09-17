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

foreach (['0.0.0.0/0', '203.0.113.7/0', '::/0', '2001:db8::1/0'] as $cidr) {
    expect_same("reject {$cidr}", null, normalize_ip_or_cidr($cidr));
}

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
