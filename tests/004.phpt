--TEST--
Create/destroy ffi object test
--EXTENSIONS--
rnp
--FILE--
<?php
var_dump(rnp_ffi_create('GPG', 'GPG'));
var_dump(rnp_ffi_create('KBX', 'G10'));
var_dump(rnp_ffi_create('invalid', 'GPG'));
var_dump(rnp_ffi_create('GPG', 'invalid'));

$ffi = rnp_ffi_create('GPG', 'GPG');
rnp_ffi_destroy($ffi);
?>
--EXPECTF--
object(RnpFFI)#1 (0) {
}
object(RnpFFI)#1 (0) {
}
bool(false)
bool(false)
