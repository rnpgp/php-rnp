--TEST--
key removal test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php
require_once "testkeys.inc";

$ffi = rnp_ffi_create('GPG', 'GPG');

//non-existent key fingerprint
var_dump(rnp_key_remove($ffi, '0000000000000000000000000000000000000000', 0));

rnp_load_keys($ffi, 'GPG', $keyring1_pubring, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS);

$keys_by_fp = rnp_list_keys($ffi, "fingerprint");

var_dump(count($keys_by_fp));

var_dump(rnp_key_remove($ffi, 'E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A', RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SUBKEYS));

$keys_by_fp = rnp_list_keys($ffi, "fingerprint");

var_dump(count($keys_by_fp));

rnp_ffi_destroy($ffi);
?>
--EXPECT--
bool(false)
int(7)
bool(true)
int(3)
