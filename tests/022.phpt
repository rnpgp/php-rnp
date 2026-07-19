--TEST--
request password test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php

function password_callback(string $key_fp, string $pgp_context, string &$password)
{
	echo strlen($key_fp)."\n";
	echo $pgp_context."\n";
	$password = "secret123";

	return true;
}

$ffi = rnp_ffi_create('GPG', 'GPG');

// no password provider set
var_dump(rnp_request_password($ffi, null, 'test-context'));

rnp_ffi_set_pass_provider($ffi, 'password_callback');

var_dump(rnp_request_password($ffi, null, 'test-context'));

$key = rnp_op_generate_key($ffi, 'passtest', 'RSA');
var_dump(rnp_request_password($ffi, $key, 'key-context'));

// non-existent key
var_dump(rnp_request_password($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'test-context'));

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
bool(false)
0
test-context
string(9) "secret123"
40
key-context
string(9) "secret123"
bool(false)
