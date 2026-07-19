--TEST--
verify introspection: flags, signature errors, recipients and symencs
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php

function password_callback(string $key_fp, string $pgp_context, string &$password)
{
	$password = "pass123";

	return true;
}

$ffi = rnp_ffi_create('GPG', 'GPG');

$key1 = rnp_op_generate_key($ffi, 'testuserid1', 'RSA', 'RSA');
$key2 = rnp_op_generate_key($ffi, 'testuserid2', 'DSA', 'RSA');

$data = "testdatatosign";
$corrupted_data = $data;
$corrupted_data[3] = 1;

// verify flags: require all signatures to be valid
$signed_data = rnp_op_sign($ffi, $data, array($key1, $key2));
$verify_stats = rnp_op_verify($ffi, $signed_data, RNP_VERIFY_REQUIRE_ALL_SIGS);
echo $verify_stats['verification_status']."\n";

$detached = rnp_op_sign_detached($ffi, $data, array($key1, $key2));
$verify_stats = rnp_op_verify_detached($ffi, $data, $detached, RNP_VERIFY_REQUIRE_ALL_SIGS);
echo $verify_stats['verification_status']."\n";

// invalid signatures: per-signature error codes are reported
$verify_stats = rnp_op_verify_detached($ffi, $corrupted_data, $detached);
echo $verify_stats['signatures'][0]['verification_status']."\n";
var_dump(count($verify_stats['signatures'][0]['errors']) > 0);
var_dump(count($verify_stats['signatures'][1]['errors']) > 0);

// subpacket enumeration
$sig = $verify_stats['signatures'][0];
var_dump(count($sig['subpackets']) > 0);
$types = array();
$first = true;
foreach ($sig['subpackets'] as $subpkt) {
	$types[] = $subpkt['type'];
	if ($first) {
		var_dump(is_bool($subpkt['hashed']));
		var_dump(is_bool($subpkt['critical']));
		var_dump(is_string($subpkt['data']));
		$first = false;
	}
}
var_dump(in_array(2, $types, true));
var_dump(in_array(16, $types, true));
var_dump(in_array(33, $types, true));

// recipients and symencs enumeration on encrypted and signed data
$message = "secret message";
$encrypted = rnp_op_encrypt($ffi, $message, array($key1, $key2), array('add_signature' => true));
$verify_stats = rnp_op_verify($ffi, $encrypted);
echo $verify_stats['verification_status']."\n";
echo $verify_stats['mode']."\n";
var_dump($verify_stats['valid_integrity']);
var_dump(count($verify_stats['recipients']));
foreach ($verify_stats['recipients'] as $recipient) {
	echo strlen($recipient['keyid'])."\n";
	echo $recipient['alg']."\n";
}
$keyids = array_column($verify_stats['recipients'], 'keyid');
var_dump(is_array($verify_stats['used_recipient']));
var_dump(in_array($verify_stats['used_recipient']['keyid'], $keyids, true));
echo $verify_stats['used_recipient']['alg']."\n";
var_dump(count($verify_stats['symencs']));
var_dump($verify_stats['used_symenc']);

// recipient + password: both a recipient and a symenc are present
$encrypted = rnp_op_encrypt($ffi, $message, array($key1), array('add_signature' => true, 'password' => 'pass123'));
$verify_stats = rnp_op_verify($ffi, $encrypted);
echo $verify_stats['verification_status']."\n";
var_dump(count($verify_stats['recipients']));
var_dump(count($verify_stats['symencs']));
$symenc = $verify_stats['symencs'][0];
echo $symenc['cipher']."\n";
echo $symenc['aead_alg']."\n";
echo $symenc['hash_alg']."\n";
echo $symenc['s2k_type']."\n";
var_dump($symenc['s2k_iterations'] > 0);
var_dump(is_array($verify_stats['used_recipient']));
var_dump($verify_stats['used_symenc']);

// decryption via password: symenc is the used decryption method
$ffi2 = rnp_ffi_create('GPG', 'GPG');
$public_key = rnp_key_export($ffi, $key1, RNP_KEY_EXPORT_PUBLIC);
var_dump(rnp_import_keys($ffi2, $public_key, RNP_LOAD_SAVE_PUBLIC_KEYS) !== false);
rnp_ffi_set_pass_provider($ffi2, 'password_callback');
$verify_stats = rnp_op_verify($ffi2, $encrypted);
echo $verify_stats['verification_status']."\n";
var_dump($verify_stats['used_recipient']);
var_dump(is_array($verify_stats['used_symenc']));
echo $verify_stats['used_symenc']['cipher']."\n";
echo $verify_stats['used_symenc']['s2k_type']."\n";

rnp_ffi_destroy($ffi);
rnp_ffi_destroy($ffi2);
?>
--EXPECTF--
Success
Success
Invalid signature
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
Success
cfb-mdc
bool(true)
int(2)
16
RSA
16
RSA
bool(true)
bool(true)
RSA
int(0)
NULL
Success
int(1)
int(1)
AES256
None
SHA256
Iterated and salted
bool(true)
bool(true)
NULL
bool(true)
Success
NULL
bool(true)
AES256
Iterated and salted
