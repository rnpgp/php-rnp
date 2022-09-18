--TEST--
locate key test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php
require_once "testkeys.inc";

$ffi = rnp_ffi_create('GPG', 'GPG');

//empty FFI
var_dump(rnp_locate_key($ffi, "userid", "nonexisting@test.com"));
var_dump(rnp_locate_key($ffi, "keyid", "7BC6709B15C23A4A"));
var_dump(rnp_locate_key($ffi, "fingerprint", "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A"));
var_dump(rnp_locate_key($ffi, "grip", "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA"));

var_dump(rnp_load_keys($ffi, 'GPG', $keyring1_pubring, RNP_LOAD_SAVE_PUBLIC_KEYS));

var_dump(rnp_locate_key($ffi, "userid", "key0-uid0"));
var_dump(rnp_locate_key($ffi, "keyid", "7BC6709B15C23A4A"));
var_dump(rnp_locate_key($ffi, "fingerprint", "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A"));
var_dump(rnp_locate_key($ffi, "grip", "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA"));

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
bool(false)
bool(false)
bool(false)
bool(false)
bool(true)
string(40) "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A"
string(40) "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A"
string(40) "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A"
string(40) "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A"
