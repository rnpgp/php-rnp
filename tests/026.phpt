--TEST--
armor helpers and calculate iterations test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php
require_once "testkeys.inc";

$ffi = rnp_ffi_create('GPG', 'GPG');
rnp_load_keys($ffi, 'GPG', $keyring1_pubring, RNP_LOAD_SAVE_PUBLIC_KEYS);

$key_fp = 'E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A';
$armored = rnp_key_export($ffi, $key_fp, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_ARMORED);

// dearmor strips the armor, enarmor restores it
$binary = rnp_dearmor($armored);
var_dump(strlen($binary) > 0);
var_dump(trim(rnp_enarmor($binary, 'public key')) === trim($armored));

// NULL type guesses the contents
var_dump(trim(rnp_enarmor($binary)) === trim($armored));

$lines = explode("\n", rnp_enarmor($binary, 'public key'));
echo trim($lines[0])."\n";

rnp_ffi_destroy($ffi);

// signature armor roundtrip
$ffi = rnp_ffi_create('GPG', 'GPG');
$key = rnp_op_generate_key($ffi, 'armortest', 'RSA');
$signature = rnp_op_sign_detached($ffi, 'some data', array($key));

$armored_sig = rnp_enarmor($signature, 'signature');
$lines = explode("\n", $armored_sig);
echo trim($lines[0])."\n";
var_dump(rnp_dearmor($armored_sig) === $signature);

// error cases
var_dump(rnp_enarmor($binary, 'nosuchtype'));
var_dump(rnp_dearmor('not armored data'));

// s2k iterations calculation
$iterations_low = rnp_calculate_iterations('SHA256', 10);
$iterations_high = rnp_calculate_iterations('SHA256', 500);
var_dump($iterations_low > 0);
var_dump($iterations_high >= $iterations_low);
var_dump(rnp_calculate_iterations('NOSUCHHASH', 100));

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
-----BEGIN PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP SIGNATURE-----
bool(true)
bool(false)
bool(false)
bool(true)
bool(true)
bool(false)
