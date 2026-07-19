--TEST--
operation metadata options test (file info, expiration, aead bits)
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
require_once('checkdump.inc');

$ffi = rnp_ffi_create('GPG', 'GPG');

$key = rnp_op_generate_key($ffi, 'metatest', 'RSA', 'RSA');

// literal data file name and modification time
$data = "some data to sign";
$signed = rnp_op_sign($ffi, $data, array($key), array(
	'file_name' => 'testfname',
	'file_mtime' => 1234567,
	'expiration_time' => 3600,
));

rnptest_checkdump($signed, 'filename: testfname', 1);
rnptest_checkdump($signed, 'timestamp: 1234567', 1);

// signature expiration time is reflected in the signature info
$verify_stats = rnp_op_verify($ffi, $signed);
var_dump($verify_stats['signatures'][0]['expiration_time']);

// aead bits are visible in the packet dump
$encrypted = rnp_op_encrypt($ffi, $data, array($key), array('aead' => 'EAX', 'aead_bits' => 12));

rnptest_checkdump($encrypted, 'aead algorithm: 1 (EAX)', 1);
rnptest_checkdump($encrypted, 'chunk size: 12', 1);

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
filename: testfname
timestamp: 1234567
int(3600)
aead algorithm: 1 (EAX)
chunk size: 12
