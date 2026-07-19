--TEST--
key revocation and uid introspection on fixture keys test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php
require_once "testkeys.inc";

$ffi = rnp_ffi_create('GPG', 'GPG');

// generate and revoke a key
$key = rnp_op_generate_key($ffi, 'revoketest', 'RSA');

var_dump(rnp_key_revoke($ffi, $key, 0, array('code' => 'retired', 'reason' => 'superseded')));

$info = rnp_key_get_info($ffi, $key);
var_dump($info['is_revoked']);
var_dump($info['is_retired']);

// exported revocation parses as a key revocation signature packet
$revocation = rnp_key_export_revocation($ffi, $key, RNP_KEY_EXPORT_ARMORED);
var_dump(strncmp($revocation, '-----BEGIN PGP ', 15));
$dump = rnp_dump_packets($revocation, 0);
var_dump(strpos($dump, 'Key revocation signature') !== false);

rnp_ffi_destroy($ffi);

// uid introspection on fixture keys
$ffi = rnp_ffi_create('GPG', 'GPG');
rnp_load_keys($ffi, 'GPG', $keyring1_pubring, RNP_LOAD_SAVE_PUBLIC_KEYS);

$key_fp = 'E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A';

$uid_info = rnp_uid_get_info($ffi, $key_fp, 'key0-uid0');
echo $uid_info['data']."\n";
var_dump($uid_info['type'] === RNP_USER_ID);
var_dump($uid_info['is_primary']);
var_dump($uid_info['is_valid']);
var_dump($uid_info['is_revoked']);
var_dump($uid_info['signature_count']);
var_dump($uid_info['revocation_signature']);

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
int(0)
bool(true)
key0-uid0
bool(true)
bool(false)
bool(true)
bool(false)
int(1)
NULL
