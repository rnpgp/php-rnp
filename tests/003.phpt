--TEST--
Supported features test
--EXTENSIONS--
rnp
--FILE--
<?php
var_dump(rnp_supported_features(''));

var_dump(extension_loaded('json'));

var_dump(is_array(json_decode(rnp_supported_features('symmetric algorithm'))));

var_dump(is_array(json_decode(rnp_supported_features('aead algorithm'))));

var_dump(is_array(json_decode(rnp_supported_features('protection mode'))));

var_dump(is_array(json_decode(rnp_supported_features('public key algorithm'))));

var_dump(is_array(json_decode(rnp_supported_features('hash algorithm'))));

var_dump(is_array(json_decode(rnp_supported_features('compression algorithm'))));

var_dump(is_array(json_decode(rnp_supported_features('elliptic curve'))));

?>
--EXPECT--
bool(false)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
