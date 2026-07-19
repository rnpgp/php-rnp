--TEST--
user id management test (add_uid, uid info, uid remove)
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php

$ffi = rnp_ffi_create('GPG', 'GPG');

$key = rnp_op_generate_key($ffi, 'first-uid', 'RSA');

$info = rnp_key_get_info($ffi, $key);
var_dump(count($info['uids']));

$uid = $info['uids'][0];
echo $uid['data']."\n";
var_dump($uid['type'] === RNP_USER_ID);
var_dump($uid['is_primary']);
var_dump($uid['is_valid']);
var_dump($uid['is_revoked']);
var_dump($uid['signature_count']);

// add a second user id with options
var_dump(rnp_key_add_uid($ffi, $key, 'second-uid', array('hash' => 'SHA512')));

$info = rnp_key_get_info($ffi, $key);
var_dump(count($info['uids']));
echo $info['uids'][1]['data']."\n";
var_dump($info['uids'][1]['is_primary']);

// single uid introspection
$uid_info = rnp_uid_get_info($ffi, $key, 'second-uid');
echo $uid_info['data']."\n";
var_dump($uid_info['type'] === RNP_USER_ID);
var_dump($uid_info['is_valid']);
var_dump($uid_info['is_revoked']);
var_dump($uid_info['signature_count']);
var_dump($uid_info['revocation_signature']);

// add a primary user id
var_dump(rnp_key_add_uid($ffi, $key, 'primary-uid', array('primary' => true)));
$uid_info = rnp_uid_get_info($ffi, $key, 'primary-uid');
var_dump($uid_info['is_primary']);

// remove user ids
var_dump(rnp_uid_remove($ffi, $key, 'second-uid'));
$info = rnp_key_get_info($ffi, $key);
var_dump(count($info['uids']));
var_dump(rnp_uid_remove($ffi, $key, 'second-uid'));

// error cases
var_dump(rnp_key_add_uid($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'some-uid'));
var_dump(rnp_uid_get_info($ffi, $key, 'nosuchuid'));
var_dump(rnp_uid_remove($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'some-uid'));

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
int(1)
first-uid
bool(true)
bool(false)
bool(true)
bool(false)
int(1)
bool(true)
int(2)
second-uid
bool(false)
second-uid
bool(true)
bool(true)
bool(false)
int(1)
NULL
bool(true)
bool(true)
bool(true)
int(2)
bool(false)
bool(false)
bool(false)
bool(false)
