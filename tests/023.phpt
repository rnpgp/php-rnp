--TEST--
key protect/lock/unlock/unprotect and expiration test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php

function password_callback(string $key_fp, string $pgp_context, string &$password)
{
	$password = 'pw123';

	return true;
}

$ffi = rnp_ffi_create('GPG', 'GPG');

$key = rnp_op_generate_key($ffi, 'protecttest', 'RSA');

$info = rnp_key_get_info($ffi, $key);
var_dump($info['have_secret']);
var_dump($info['is_protected']);
var_dump($info['is_locked']);
var_dump($info['expiration'] > 0);

// protect with a password and explicit options
var_dump(rnp_key_protect($ffi, $key, 'pw123', array('cipher' => 'AES256', 'hash' => 'SHA256', 'iterations' => 1024)));

$info = rnp_key_get_info($ffi, $key);
var_dump($info['is_protected']);
var_dump($info['is_locked']);

// unlock with a wrong password must fail
var_dump(rnp_key_unlock($ffi, $key, 'wrongpw'));
var_dump(rnp_key_unlock($ffi, $key, 'pw123'));

$info = rnp_key_get_info($ffi, $key);
var_dump($info['is_locked']);

var_dump(rnp_key_lock($ffi, $key));

$info = rnp_key_get_info($ffi, $key);
var_dump($info['is_locked']);

// unlock via the pass provider (no explicit password)
rnp_ffi_set_pass_provider($ffi, 'password_callback');
var_dump(rnp_key_unlock($ffi, $key));

// unprotect removes the password protection
var_dump(rnp_key_unprotect($ffi, $key, 'pw123'));

$info = rnp_key_get_info($ffi, $key);
var_dump($info['is_protected']);

// set/get expiration
var_dump(rnp_key_set_expiration($ffi, $key, 3600));
$info = rnp_key_get_info($ffi, $key);
var_dump($info['expiration']);
var_dump(rnp_key_set_expiration($ffi, $key, 0));
$info = rnp_key_get_info($ffi, $key);
var_dump($info['expiration']);

// error cases
var_dump(rnp_key_protect($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'pw123'));
var_dump(rnp_key_unprotect($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'pw123'));
var_dump(rnp_key_lock($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'));
var_dump(rnp_key_unlock($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'pw123'));
var_dump(rnp_key_set_expiration($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 3600));

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
bool(true)
bool(false)
bool(false)
bool(true)
bool(true)
bool(true)
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)
bool(true)
bool(true)
bool(true)
bool(false)
bool(true)
int(3600)
bool(true)
int(0)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
