--TEST--
Load/save keys test
--EXTENSIONS--
rnp
--FILE--
<?php

require_once "testkeys.inc";

$ffi = rnp_ffi_create('GPG', 'GPG');
var_dump(rnp_load_keys($ffi, 'GPG', $keyring1_pubring, RNP_LOAD_SAVE_PUBLIC_KEYS));
$output = '';
var_dump(rnp_save_keys($ffi, 'GPG', $output, RNP_LOAD_SAVE_PUBLIC_KEYS));
rnp_ffi_destroy($ffi);
echo strlen($output)."\n";
$ffi = rnp_ffi_create('GPG', 'GPG');
var_dump(rnp_load_keys($ffi, 'GPG', $output, RNP_LOAD_SAVE_PUBLIC_KEYS));
?>
--EXPECT--
bool(true)
bool(true)
3492
bool(true)
