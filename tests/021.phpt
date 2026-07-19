--TEST--
key certification signatures test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php

$ffi = rnp_ffi_create('GPG', 'GPG');

$key_a = rnp_op_generate_key($ffi, 'alice', 'RSA');
$key_b = rnp_op_generate_key($ffi, 'bob', 'RSA');

// fresh key has no direct-key signatures
var_dump(count(rnp_key_get_signatures($ffi, $key_a)));

// direct-key self-signature with customized options
$op = rnp_key_direct_signature_create($ffi, $key_a, null, array(
	'hash' => 'SHA512',
	'creation_time' => time(),
	'key_flags' => RNP_KEY_USAGE_CERTIFY | RNP_KEY_USAGE_SIGN,
	'features' => RNP_KEY_FEATURE_MDC,
	'preferred_algs' => array('AES256', 'AES192'),
	'preferred_hashes' => array('SHA512'),
	'preferred_zalgs' => array('ZIP'),
	'key_server' => 'hkp://keys.test',
	'key_server_prefs' => RNP_KEY_SERVER_NO_MODIFY,
	'revoker' => $key_b,
));
var_dump(get_class($op));
var_dump(rnp_key_signature_sign($op));

// already signed signature cannot be signed again
try {
	rnp_key_signature_sign($op);
} catch (Throwable $e) {
	echo $e->getMessage()."\n";
}

// read the signature back
$sigs = rnp_key_get_signatures($ffi, $key_a);
var_dump(count($sigs));
$sig = $sigs[0];
echo $sig['signature_type']."\n";
echo $sig['alg']."\n";
echo $sig['hash']."\n";
var_dump($sig['keyid'] === substr($key_a, -16));
var_dump($sig['key_fprint'] === $key_a);
var_dump($sig['creation_time'] > 0);
var_dump($sig['key_flags'] === (RNP_KEY_USAGE_CERTIFY | RNP_KEY_USAGE_SIGN));
var_dump($sig['features'] === RNP_KEY_FEATURE_MDC);
echo $sig['key_server']."\n";
var_dump($sig['key_server_prefs'] === RNP_KEY_SERVER_NO_MODIFY);
echo implode(',', $sig['preferred_algs'])."\n";
echo implode(',', $sig['preferred_hashes'])."\n";
echo implode(',', $sig['preferred_zalgs'])."\n";
var_dump($sig['revoker'] === $key_b);
echo $sig['validity_status']."\n";
var_dump(count($sig['errors']));
var_dump(count($sig['subpackets']) > 0);
var_dump(strlen($sig['data']) > 0);

// designated revoker shows up in the key info
$key_info = rnp_key_get_info($ffi, $key_a);
var_dump($key_info['version']);
var_dump(count($key_info['revokers']));
var_dump($key_info['revokers'][0] === $key_b);

// third-party certification of bob's userid by alice
$op = rnp_key_certification_create($ffi, $key_a, $key_b, 'bob', RNP_CERTIFICATION_GENERIC, array(
	'hash' => 'SHA256',
	'trust_level' => 1,
	'trust_amount' => 60,
));
var_dump(rnp_key_signature_sign($op));

$sigs = rnp_uid_get_signatures($ffi, $key_b, 'bob');
var_dump(count($sigs));
$found = false;
foreach ($sigs as $sig) {
	if ($sig['key_fprint'] === $key_a) {
		$found = true;
		echo $sig['signature_type']."\n";
		var_dump($sig['trust_level']);
		var_dump($sig['trust_amount']);
		echo $sig['validity_status']."\n";
	}
}
var_dump($found);

// self-certification, default type
$op = rnp_key_certification_create($ffi, $key_b, $key_b, 'bob');
var_dump(rnp_key_signature_sign($op));
$sigs = rnp_uid_get_signatures($ffi, $key_b, 'bob');
$found = false;
foreach ($sigs as $sig) {
	if ($sig['key_fprint'] === $key_b && $sig['signature_type'] === 'certification (positive)') {
		$found = true;
	}
}
var_dump($found);

// remove non-self signatures from bob's key
var_dump(rnp_key_remove_signatures($ffi, $key_b, RNP_KEY_SIGNATURE_NON_SELF_SIG));
$sigs = rnp_uid_get_signatures($ffi, $key_b, 'bob');
$found = false;
foreach ($sigs as $sig) {
	if ($sig['key_fprint'] === $key_a) {
		$found = true;
	}
}
var_dump($found);

// revocation signature
$key_c = rnp_op_generate_key($ffi, 'carol', 'RSA');
$op = rnp_key_revocation_signature_create($ffi, $key_c, null, array(
	'revocation_code' => 'retired',
	'revocation_reason' => 'no longer used',
));
var_dump(rnp_key_signature_sign($op));
$key_info = rnp_key_get_info($ffi, $key_c);
var_dump($key_info['is_revoked']);
var_dump($key_info['is_retired']);
$sigs = rnp_key_get_signatures($ffi, $key_c);
$sig = $sigs[count($sigs) - 1];
echo $sig['signature_type']."\n";
echo $sig['revocation_code']."\n";
echo $sig['revocation_reason']."\n";

// error cases
var_dump(rnp_key_certification_create($ffi, $key_a, $key_b, 'nosuchuid'));
var_dump(rnp_key_direct_signature_create($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'));
var_dump(rnp_key_revocation_signature_create($ffi, $key_a, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'));
var_dump(rnp_uid_get_signatures($ffi, $key_b, 'nosuchuid'));
var_dump(rnp_key_get_signatures($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'));
var_dump(rnp_key_remove_signatures($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 0));

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
int(0)
string(15) "RnpKeySignature"
bool(true)
rnp_key_signature_sign(): Attempt to sign already signed signature!
int(1)
direct
RSA
SHA512
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
hkp://keys.test
bool(true)
AES256,AES192
SHA512
ZIP
bool(true)
Success
int(0)
bool(true)
bool(true)
int(4)
int(1)
bool(true)
bool(true)
int(2)
certification (generic)
int(1)
int(60)
Success
bool(true)
bool(true)
bool(true)
bool(true)
bool(false)
bool(true)
bool(true)
bool(true)
key revocation
retired
no longer used
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
