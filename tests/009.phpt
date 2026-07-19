--TEST--
signature verification test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php

$ffi = rnp_ffi_create('GPG', 'GPG');

$key1 = rnp_op_generate_key($ffi, 'testuserid1', 'RSA');
echo strlen($key1)."\n";

$key2 = rnp_op_generate_key($ffi, 'testuserid2', 'DSA');
echo strlen($key2)."\n";

$data = "testdatatosign";
$corrupted_data = $data;
$corrupted_data[3] = 1;

$verify_stats = rnp_op_verify($ffi, rnp_op_sign($ffi, $data, array($key1)));

echo $verify_stats['verification_status']."\n";
var_dump($verify_stats['file_name']);
var_dump($verify_stats['file_mtime']);
echo $verify_stats['mode']."\n";
echo $verify_stats['cipher']."\n";
var_dump($verify_stats['valid_integrity']);
var_dump(count($verify_stats['signatures']));

$sig = $verify_stats['signatures'][0];

echo $sig['verification_status']."\n";
var_dump($sig['creation_time'] > 0);
var_dump($sig['expiration_time']);
echo $sig['hash']."\n";
echo strlen($sig['signing_key'])."\n";
echo $sig['signature_type']."\n";
echo $sig['alg']."\n";
echo strlen($sig['keyid'])."\n";
var_dump($sig['key_fprint'] === $sig['signing_key']);
var_dump($sig['features']);
var_dump($sig['key_flags']);
var_dump($sig['key_expiration']);
var_dump($sig['primary_uid']);
var_dump($sig['trust_level']);
var_dump($sig['trust_amount']);
var_dump(strlen($sig['revoker']));
var_dump(strlen($sig['revocation_code']));
var_dump(strlen($sig['revocation_reason']));
var_dump(strlen($sig['key_server']));
var_dump($sig['key_server_prefs']);
var_dump(count($sig['preferred_algs']));
var_dump(count($sig['preferred_hashes']));
var_dump(count($sig['preferred_zalgs']));
var_dump(count($sig['errors']));
var_dump(count($sig['subpackets']) > 0);

$creation_subpkt_found = false;
foreach ($sig['subpackets'] as $subpkt) {
	if ($subpkt['type'] === 2 && $subpkt['hashed'] === true && $subpkt['critical'] === false &&
	    strlen($subpkt['data']) === 4) {
		$creation_subpkt_found = true;
	}
}
var_dump($creation_subpkt_found);

var_dump(count($verify_stats['recipients']));
var_dump($verify_stats['used_recipient']);
var_dump(count($verify_stats['symencs']));
var_dump($verify_stats['used_symenc']);

$signed_data = rnp_op_sign($ffi, $data, array($key1, $key2));
$verify_stats = rnp_op_verify($ffi, $signed_data);
var_dump(count($verify_stats));
var_dump(count($verify_stats, COUNT_RECURSIVE));

echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][1]['verification_status']."\n";


$signed_data = rnp_op_sign_cleartext($ffi, $data, array($key1, $key2));
$verify_stats = rnp_op_verify($ffi, $signed_data);
echo $verify_stats['signatures'][0]['signature_type']."\n";
echo $verify_stats['signatures'][0]['verification_status']."\n";


$signatures = rnp_op_sign_detached($ffi, $data, array($key1, $key2));

$verify_stats = rnp_op_verify_detached($ffi, $data, $signatures);
var_dump(count($verify_stats['signatures']));
echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][1]['verification_status']."\n";

$verify_stats = rnp_op_verify_detached($ffi, $corrupted_data, $signatures);
var_dump(count($verify_stats['signatures']));

echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][1]['verification_status']."\n";
var_dump(count($verify_stats['signatures'][0]['errors']) > 0);


$signature = rnp_op_sign($ffi, $data, array($key1, $key2));
$detached_signature = rnp_op_sign_detached($ffi, $data, array($key1, $key2));
rnp_ffi_destroy($ffi);

$ffi = rnp_ffi_create('GPG', 'GPG');

// test without loaded keys

$verify_stats = rnp_op_verify($ffi, $signature);

echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][0]['signing_key']."\n";
echo strlen($verify_stats['signatures'][0]['key_fprint'])."\n";
echo strlen($verify_stats['signatures'][0]['keyid'])."\n";

$verify_stats = rnp_op_verify_detached($ffi, $data, $detached_signature);

echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][0]['signing_key']."\n";

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
40
40
Success
string(0) ""
int(0)
none
none
bool(false)
int(1)
Success
bool(true)
int(0)
%s
40
binary
RSA
16
bool(true)
int(0)
int(0)
int(0)
bool(false)
int(0)
int(0)
int(0)
int(0)
int(0)
int(0)
int(0)
int(0)
int(0)
int(0)
int(0)
bool(true)
bool(true)
int(0)
NULL
int(0)
NULL
int(11)
int(103)
Success
Success
text
Success
int(2)
Success
Success
int(2)
Invalid signature
Invalid signature
bool(true)
Key not found
Not found
40
16
Key not found
Not found
