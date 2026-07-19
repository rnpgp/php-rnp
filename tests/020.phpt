--TEST--
security profile rules test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php

$ffi = rnp_ffi_create('GPG', 'GPG');

$key = rnp_op_generate_key($ffi, 'sectest', 'RSA');

$data = "some data to sign";
$signature = rnp_op_sign_detached($ffi, $data, array($key), array('hash' => 'SHA1'));

// SHA1 data signatures are considered insecure by the default rules
$verify_stats = rnp_op_verify_detached($ffi, $data, $signature);
echo $verify_stats['signatures'][0]['verification_status']."\n";

// override the rule, marking SHA1 as secure
var_dump(rnp_add_security_rule($ffi, RNP_FEATURE_HASH_ALG, 'SHA1', RNP_SECURITY_OVERRIDE, 0, RNP_SECURITY_DEFAULT));

$rule = rnp_get_security_rule($ffi, RNP_FEATURE_HASH_ALG, 'SHA1', 0);
echo $rule['flags']."\n";
echo $rule['from']."\n";
echo $rule['level']."\n";

$verify_stats = rnp_op_verify_detached($ffi, $data, $signature);
echo $verify_stats['signatures'][0]['verification_status']."\n";

// remove the override rule, default rules apply again
var_dump(rnp_remove_security_rule($ffi, RNP_FEATURE_HASH_ALG, 'SHA1', RNP_SECURITY_DEFAULT, RNP_SECURITY_OVERRIDE, 0));

$verify_stats = rnp_op_verify_detached($ffi, $data, $signature);
echo $verify_stats['signatures'][0]['verification_status']."\n";
var_dump(count($verify_stats['signatures'][0]['errors']) > 0);

// error cases
var_dump(rnp_add_security_rule($ffi, RNP_FEATURE_HASH_ALG, 'NOSUCHALG', 0, 0, RNP_SECURITY_DEFAULT));
var_dump(rnp_get_security_rule($ffi, RNP_FEATURE_HASH_ALG, 'NOSUCHALG', 0));

// ffi timestamp override
var_dump(rnp_set_timestamp($ffi, 1500000000));
var_dump(rnp_set_timestamp($ffi, 0));

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
Invalid signature
bool(true)
1
0
2
Success
int(1)
Invalid signature
bool(true)
bool(false)
bool(false)
bool(true)
bool(true)
