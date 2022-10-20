--TEST--
key revocation test
--EXTENSIONS--
rnp
--FILE--
<?php

//revoke, no options
$ffi = rnp_ffi_create('GPG', 'GPG');

$key_fp = rnp_op_generate_key($ffi, 'test_revoke', 'RSA');
echo strlen($key_fp)."\n";

var_dump(rnp_key_revoke($ffi, $key_fp, 0));

var_dump(rnp_key_get_info($ffi, $key_fp)['is_revoked']);

rnp_ffi_destroy($ffi);

// export revocation, no options
$ffi = rnp_ffi_create('GPG', 'GPG');

$key_fp = rnp_op_generate_key($ffi, 'test_export_revocation', 'RSA');
echo strlen($key_fp)."\n";

$exported_rev_sign = rnp_key_export_revocation($ffi, $key_fp, RNP_KEY_EXPORT_ARMORED);

var_dump(rnp_import_signatures($ffi, $exported_rev_sign, 0));

var_dump(rnp_key_get_info($ffi, $key_fp)['is_revoked']);

rnp_ffi_destroy($ffi);

//revoke, set options
$ffi = rnp_ffi_create('GPG', 'GPG');

$key_fp = rnp_op_generate_key($ffi, 'test_revoke_with_options', 'RSA');
echo strlen($key_fp)."\n";

$options = array('hash' => 'SHA224', 'code' => 'retired', 'reason' => 'REASON');

var_dump(rnp_key_revoke($ffi, $key_fp, 0, $options));

var_dump(rnp_key_get_info($ffi, $key_fp)['is_revoked']);
var_dump(rnp_key_get_info($ffi, $key_fp)['is_retired']);

rnp_ffi_destroy($ffi);

// export revocation, set options
$ffi = rnp_ffi_create('GPG', 'GPG');

$key_fp = rnp_op_generate_key($ffi, 'test_export_revocation_with_options', 'RSA');
echo strlen($key_fp)."\n";

$options = array('hash' => 'SHA224', 'code' => 'retired', 'reason' => 'REASON');

$exported_rev_sign = rnp_key_export_revocation($ffi, $key_fp, RNP_KEY_EXPORT_ARMORED, $options);

var_dump(rnp_import_signatures($ffi, $exported_rev_sign, 0));

var_dump(rnp_key_get_info($ffi, $key_fp)['is_revoked']);
var_dump(rnp_key_get_info($ffi, $key_fp)['is_retired']);

rnp_ffi_destroy($ffi);

?>
--EXPECTF--
40
bool(true)
bool(true)
40
string(144) "{
  "sigs":[
    {
      "public":"new",
      "secret":"new",
      "signer fingerprint":"%s"
    }
  ]
}"
bool(true)
40
bool(true)
bool(true)
bool(true)
40
string(144) "{
  "sigs":[
    {
      "public":"new",
      "secret":"new",
      "signer fingerprint":"%s"
    }
  ]
}"
bool(true)
bool(true)
