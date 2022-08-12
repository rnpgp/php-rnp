--TEST--
signature verification test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php

$ffi = rnp_ffi_create('GPG', 'GPG');

$key1 = rnp_op_generate_key($ffi, 'testuserid1', 'RSA');
echo strlen($key1)."\n";

$key2 = rnp_op_generate_key($ffi, 'testuserid2', 'DSA');
echo strlen($key2)."\n";

$data = "testdatatosign";
$corrupted_data = $data;
$corrupted_data[3] = 1;

var_dump(rnp_op_verify($ffi, rnp_op_sign($ffi, $data, array($key1))));

$signed_data = rnp_op_sign($ffi, $data, array($key1, $key2));
var_dump(count(rnp_op_verify($ffi, $signed_data)));
var_dump(count(rnp_op_verify($ffi, $signed_data), COUNT_RECURSIVE));

$verify_stats = rnp_op_verify($ffi, $signed_data);

echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][1]['verification_status']."\n";


$signed_data = rnp_op_sign_cleartext($ffi, $data, array($key1, $key2));
$verify_stats = rnp_op_verify($ffi, $signed_data);
echo $verify_stats['signatures'][0]['signature_type']."\n";
echo $verify_stats['signatures'][0]['verification_status']."\n";


$signatures = rnp_op_sign_detached($ffi, $data, array($key1, $key2));

$verify_stats = rnp_op_verify_detached($ffi, $data, $signatures);
var_dump(count($verify_stats['signatures']));
echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][1]['verification_status']."\n";

$verify_stats = rnp_op_verify_detached($ffi, $corrupted_data, $signatures);
var_dump(count($verify_stats['signatures']));

echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][1]['verification_status']."\n";


$signature = rnp_op_sign($ffi, $data, array($key1, $key2));
$detached_signature = rnp_op_sign_detached($ffi, $data, array($key1, $key2));
rnp_ffi_destroy($ffi);

$ffi = rnp_ffi_create('GPG', 'GPG');

// test without loaded keys

$verify_stats = rnp_op_verify($ffi, $signature);

echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][0]['signing_key']."\n";

$verify_stats = rnp_op_verify_detached($ffi, $data, $detached_signature);

echo $verify_stats['signatures'][0]['verification_status']."\n";
echo $verify_stats['signatures'][0]['signing_key']."\n";

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
40
40
array(7) {
  ["verification_status"]=>
  string(7) "Success"
  ["file_name"]=>
  string(0) ""
  ["file_mtime"]=>
  int(0)
  ["mode"]=>
  string(4) "none"
  ["cipher"]=>
  string(4) "none"
  ["valid_integrity"]=>
  bool(false)
  ["signatures"]=>
  array(1) {
    [0]=>
    array(6) {
      ["verification_status"]=>
      string(7) "Success"
      ["creation_time"]=>
      int(%d)
      ["expiration_time"]=>
      int(0)
      ["hash"]=>
      string(6) "%s"
      ["signing_key"]=>
      string(40) "%s"
      ["signature_type"]=>
      string(6) "binary"
    }
  }
}
int(7)
int(21)
Success
Success
text
Success
int(2)
Success
Success
int(2)
Invalid signature
Invalid signature
Key not found
Not found
Key not found
Not found
