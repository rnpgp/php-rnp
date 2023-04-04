--TEST--
encrypt/decrypt test
--EXTENSIONS--
rnp
--SKIPIF--
<?php
if (!strcasecmp(rnp_backend_string(), "openssl")) die("skip OpenSSL backend");
?>
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php

function password_callback(string $key_fp, string $pgp_context, string &$password)
{
        $password = "password";

        return true;
}

require_once('checkdump.inc');

$ffi = rnp_ffi_create('GPG', 'GPG');

$key1 = rnp_op_generate_key($ffi, 'testuserid1', 'RSA', 'RSA');
echo strlen($key1)."\n";

$key2 = rnp_op_generate_key($ffi, 'testuserid2', 'DSA', 'RSA');
echo strlen($key2)."\n";

$message = "test message for encryption";

// no keys, no password
var_dump(rnp_op_encrypt($ffi, $message, array()));

$encrypted_message = rnp_op_encrypt($ffi, $message, array($key1, $key2));

$decrypted_message = rnp_decrypt($ffi, $encrypted_message);

var_dump(($message === $decrypted_message));

//options

//NOWRAP test...
$options = array('flags' => RNP_ENCRYPT_NOWRAP);

$signed_message = rnp_op_sign($ffi, $message, array($key1, $key2));

$encrypted_message = rnp_op_encrypt($ffi, $signed_message, array($key1, $key2), $options);

$decrypted_message = rnp_decrypt($ffi, $encrypted_message);

var_dump(($message === $decrypted_message));


$options = array(
		'compression_alg' => 'ZIP',
		'compression_level' => 6,
		'armor' => true,
		'hash' => 'SHA224',
		'creation_time' => 1234337,
		'expiration_time' => 2147483647,
		'file_name' => 'testfilename',
		'file_mtime' => 321337,
		'add_signature' => true,
		'password' => 'password',
		'cipher' => 'CAMELLIA192',
		'kek_cipher' => 'CAMELLIA192',
		'aead' => 'EAX',
		'aead_bits' => 0,
		//'flags' => RNP_ENCRYPT_NOWRAP
		);

$encrypted_message = rnp_op_encrypt($ffi, $message, array($key1, $key2), $options);

rnptest_checkdump($encrypted_message, "armored input", 1);
rnptest_checkdump($encrypted_message, "aead algorithm: 1 (EAX)", 2);
rnptest_checkdump($encrypted_message, "12 (Camellia-192)", 2);

$verify_results = rnp_op_verify($ffi, $encrypted_message);

var_dump(is_array($verify_results));

var_dump($verify_results['signatures'][0]['creation_time']);
var_dump($verify_results['signatures'][0]['expiration_time']);
var_dump($verify_results['signatures'][0]['hash']);

var_dump($verify_results['file_name']);
var_dump($verify_results['file_mtime']);

rnp_ffi_destroy($ffi);
$ffi = rnp_ffi_create('GPG', 'GPG');

//empty $ffi with no keys..
var_dump(rnp_decrypt($ffi, $encrypted_message));

$verify_results = rnp_op_verify($ffi, $encrypted_message);
var_dump($verify_results);

//password decryption
rnp_ffi_set_pass_provider($ffi, 'password_callback');

$decrypted_message = rnp_decrypt($ffi, $encrypted_message);

var_dump(($message === $decrypted_message));

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
40
40
bool(false)
bool(true)
bool(true)
armored input
aead algorithm: 1 (EAX)
12 (Camellia-192)
bool(true)
int(1234337)
int(2147483647)
string(6) "SHA224"
string(12) "testfilename"
int(321337)
bool(false)
bool(false)
bool(true)
