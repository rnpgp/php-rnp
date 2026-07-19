--TEST--
JSON introspection dumps test
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

// key information as a decoded array
$key_json = rnp_key_to_json($ffi, $key_fp);
var_dump($key_json['fingerprint'] === $key_fp);
var_dump($key_json['keyid'] === substr($key_fp, -16));
echo $key_json['type']."\n";
var_dump(in_array('key0-uid0', $key_json['userids'], true));
var_dump($key_json['revoked']);
var_dump($key_json['expiration']);

$key_json = rnp_key_to_json($ffi, $key_fp, RNP_JSON_PUBLIC_MPIS);
var_dump(isset($key_json['public key']['mpis']));

// key packets as a decoded array
$packets = rnp_key_packets_to_json($ffi, $key_fp);
var_dump(count($packets));
echo $packets[0]['header']['tag.str']."\n";

// packet stream dump as a decoded array
$armored = rnp_key_export($ffi, $key_fp, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_ARMORED);
$dump = rnp_dump_packets_to_json($armored, 0);
echo $dump[0]['header']['tag.str']."\n";

$dump = rnp_dump_packets_to_json($armored, RNP_JSON_DUMP_MPI);
var_dump($dump[0]['material']['n.bits']);

rnp_ffi_destroy($ffi);

// signature packet dump in the signature listing
$ffi = rnp_ffi_create('GPG', 'GPG');
$key = rnp_op_generate_key($ffi, 'sigtest', 'RSA');
$sigs = rnp_uid_get_signatures($ffi, $key, 'sigtest');
$sig_json = $sigs[0]['json'];
echo $sig_json[0]['header']['tag.str']."\n";
echo $sig_json[0]['type.str']."\n";
echo $sig_json[0]['hash algorithm.str']."\n";
var_dump($sig_json[0]['version']);

// secret key packets
$packets = rnp_key_packets_to_json($ffi, $key, true);
echo $packets[0]['header']['tag.str']."\n";

// error cases
var_dump(rnp_key_to_json($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'));
var_dump(rnp_key_packets_to_json($ffi, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'));

rnp_ffi_destroy($ffi);
?>
--EXPECTF--
bool(true)
bool(true)
RSA
bool(true)
bool(false)
int(0)
bool(true)
int(7)
Public Key
Public Key
int(1024)
Signature
Positive User ID certification
SHA256
int(4)
Secret Key
bool(false)
bool(false)
