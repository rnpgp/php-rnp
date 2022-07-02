--TEST--
generate keys test
--EXTENSIONS--
rnp
--FILE--
<?php

function password_callback(string $key_fp, string $pgp_context, string &$password)
{
	$password = "password";

	return true;
}

$ffi = rnp_ffi_create('GPG', 'GPG');

$key_fp = rnp_op_generate_key($ffi, 'testuserid', 'RSA');
echo strlen($key_fp)."\n";

$output = '/tmp/'.$key_fp.'.gpg';
var_dump(rnp_save_keys_to_path($ffi, 'GPG', $output, RNP_LOAD_SAVE_SECRET_KEYS));
var_dump(unlink($output));

$key_fp = rnp_op_generate_key($ffi, 'testuserid_subkey', 'RSA', 'RSA');
echo strlen($key_fp)."\n";

$key_fp = rnp_op_generate_key($ffi, 'testuserid_options', 'RSA', 'RSA',
			      array('bits' => 4096,
			            'hash' => 'SHA224',
				    'expiration' => 60 * 60 * 24 * 7,
				    'password' => 'password')
				);

echo strlen($key_fp)."\n";

var_dump(rnp_ffi_set_pass_provider($ffi, 'password_callback'));

$key_fp = rnp_op_generate_key($ffi, 'testuserid_options_askpassword', 'RSA', 'RSA',
			      array('bits' => 3072,
			            'hash' => 'SHA512',
				    'expiration' => 60 * 60 * 24 * 7,
				    'request_password' => true)
				);

echo strlen($key_fp)."\n";

rnp_ffi_destroy($ffi);
?>
--EXPECT--
40
bool(true)
bool(true)
40
40
bool(true)
40
