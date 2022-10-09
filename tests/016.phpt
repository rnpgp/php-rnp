--TEST--
import keys test
--EXTENSIONS--
rnp
--FILE--
<?php

require_once "testkeys.inc";

$ffi = rnp_ffi_create('GPG', 'GPG');

var_dump(rnp_import_keys($ffi, "", RNP_LOAD_SAVE_PUBLIC_KEYS));

var_dump(rnp_import_keys($ffi, $keyring1_pubring, RNP_LOAD_SAVE_PUBLIC_KEYS));

?>
--EXPECT--
bool(false)
string(864) "{
  "keys":[
    {
      "public":"new",
      "secret":"none",
      "fingerprint":"e95a3cbf583aa80a2ccc53aa7bc6709b15c23a4a"
    },
    {
      "public":"new",
      "secret":"none",
      "fingerprint":"e332b27caf4742a11baa677f1ed63ee56fadc34d"
    },
    {
      "public":"new",
      "secret":"none",
      "fingerprint":"c5b15209940a7816a7af3fb51d7e8a5393c997a8"
    },
    {
      "public":"new",
      "secret":"none",
      "fingerprint":"5cd46d2a0bd0b8cfe0b130ae8a05b89fad5aded1"
    },
    {
      "public":"new",
      "secret":"none",
      "fingerprint":"be1c4ab951f4c2f6b604c7f82fcadf05ffa501bb"
    },
    {
      "public":"new",
      "secret":"none",
      "fingerprint":"a3e94de61a8cb229413d348e54505a936a4a970e"
    },
    {
      "public":"new",
      "secret":"none",
      "fingerprint":"57f8ed6e5c197db63c60ffaf326ef111425d14a5"
    }
  ]
}"
