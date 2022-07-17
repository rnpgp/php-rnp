--TEST--
signature test
--EXTENSIONS--
rnp
--FILE--
<?php

require_once('checkdump.inc');

$ffi = rnp_ffi_create('GPG', 'GPG');

$key1 = rnp_op_generate_key($ffi, 'testuserid1', 'RSA');
echo strlen($key1)."\n";

$key2 = rnp_op_generate_key($ffi, 'testuserid2', 'DSA');
echo strlen($key2)."\n";

$data = "testdatatosign";

// 1) rnp_op_sign() tests

// empty keys array, should fail
var_dump(rnp_op_sign($ffi, $data, array()));

rnptest_checkdump(rnp_op_sign($ffi, $data, array($key1)), "One-pass signature packet", 1);

// multiple keys
rnptest_checkdump(rnp_op_sign($ffi, $data, array($key1, $key2)), "One-pass signature packet", 2);

//options
$options = array(
		'compression_alg' => 'ZIP',
		'compression_level' => 6,
		'armor' => true,
		'hash' => 'SHA224',
		'creation_time' => 1234337,
		'expiration_time' => 2147483647,
		'file_name' => 'testfilename',
		'file_mtime' => 321337
		);

$signature = rnp_op_sign($ffi, $data, array($key1), $options);

// verify options are set as expected
rnptest_checkdump($signature, "armored input", 1);
rnptest_checkdump($signature, "Compressed data packet", 1);
rnptest_checkdump($signature, "ZIP", 1);
rnptest_checkdump($signature, "SHA224", 2);
rnptest_checkdump($signature, "signature creation time: 1234337", 1);
rnptest_checkdump($signature, "signature expiration time: 2147483647", 1);
rnptest_checkdump($signature, "filename: testfilename", 1);
rnptest_checkdump($signature, "timestamp: 321337", 1);

// 2) rnp_op_sign_cleartext() tests

// empty keys array, should fail
var_dump(rnp_op_sign_cleartext($ffi, $data, array()));

$signature = rnp_op_sign_cleartext($ffi, $data, array($key1));

rnptest_checkdump($signature, "cleartext signed data", 1);
rnptest_checkdump($signature, "armored input", 1);
rnptest_checkdump($signature, "Signature of a canonical text document", 1);

// multiple keys

rnptest_checkdump(rnp_op_sign_cleartext($ffi, $data, array($key1, $key2)),
		  "Signature of a canonical text document", 2);

// options
$options = array(
		'hash' => 'SHA224',
		'creation_time' => 1234337,
		'expiration_time' => 2147483647,
		);

$signature = rnp_op_sign_cleartext($ffi, $data, array($key1), $options);

rnptest_checkdump($signature, "SHA224", 1);
rnptest_checkdump($signature, "signature creation time: 1234337", 1);
rnptest_checkdump($signature, "signature expiration time: 2147483647", 1);

// 3) rnp_op_sign_detached() tests

// empty keys array, should fail
var_dump(rnp_op_sign_detached($ffi, $data, array()));

rnptest_checkdump(rnp_op_sign_detached($ffi, $data, array($key1)),
		  "Signature of a binary document", 1);

// multiple keys

rnptest_checkdump(rnp_op_sign_detached($ffi, $data, array($key1, $key2)),
		  "Signature of a binary document", 2);

//options
$options = array(
		'armor' => true,
		'hash' => 'SHA224',
		'creation_time' => 1234337,
		'expiration_time' => 2147483647,
		);

$signature = rnp_op_sign_detached($ffi, $data, array($key1), $options);

rnptest_checkdump($signature, "armored input", 1);
rnptest_checkdump($signature, "SHA224", 1);
rnptest_checkdump($signature, "signature creation time: 1234337", 1);
rnptest_checkdump($signature, "signature expiration time: 2147483647", 1);

rnp_ffi_destroy($ffi);
?>
--EXPECT--
40
40
bool(false)
One-pass signature packet
One-pass signature packet
armored input
Compressed data packet
ZIP
SHA224
signature creation time: 1234337
signature expiration time: 2147483647
filename: testfilename
timestamp: 321337
bool(false)
cleartext signed data
armored input
Signature of a canonical text document
Signature of a canonical text document
SHA224
signature creation time: 1234337
signature expiration time: 2147483647
bool(false)
Signature of a binary document
Signature of a binary document
armored input
SHA224
signature creation time: 1234337
signature expiration time: 2147483647
