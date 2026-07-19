--TEST--
key info test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php
require_once "testkeys.inc";

$ffi = rnp_ffi_create('GPG', 'GPG');

//non-existent key fingerprint
var_dump(rnp_key_get_info($ffi, '0000000000000000000000000000000000000000'));

rnp_load_keys($ffi, 'GPG', $keyring1_pubring, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS);

$keys_by_fp = rnp_list_keys($ffi, "fingerprint");

foreach ($keys_by_fp as $key => $value) {
        echo "key ".$key."\n";
        var_dump(rnp_key_get_info($ffi, $value));
}

rnp_ffi_destroy($ffi);
?>
--EXPECT--
bool(false)
key E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A
array(15) {
  ["uids"]=>
  array(3) {
    [0]=>
    array(6) {
      ["data"]=>
      string(9) "key0-uid0"
      ["type"]=>
      int(1)
      ["is_primary"]=>
      bool(false)
      ["is_valid"]=>
      bool(true)
      ["is_revoked"]=>
      bool(false)
      ["signature_count"]=>
      int(1)
    }
    [1]=>
    array(6) {
      ["data"]=>
      string(9) "key0-uid1"
      ["type"]=>
      int(1)
      ["is_primary"]=>
      bool(false)
      ["is_valid"]=>
      bool(true)
      ["is_revoked"]=>
      bool(false)
      ["signature_count"]=>
      int(1)
    }
    [2]=>
    array(6) {
      ["data"]=>
      string(9) "key0-uid2"
      ["type"]=>
      int(1)
      ["is_primary"]=>
      bool(false)
      ["is_valid"]=>
      bool(true)
      ["is_revoked"]=>
      bool(false)
      ["signature_count"]=>
      int(1)
    }
  }
  ["subkeys"]=>
  array(3) {
    [0]=>
    string(40) "E332B27CAF4742A11BAA677F1ED63EE56FADC34D"
    [1]=>
    string(40) "C5B15209940A7816A7AF3FB51D7E8A5393C997A8"
    [2]=>
    string(40) "5CD46D2A0BD0B8CFE0B130AE8A05B89FAD5ADED1"
  }
  ["is_primary"]=>
  bool(true)
  ["is_sub"]=>
  bool(false)
  ["is_valid"]=>
  bool(true)
  ["is_revoked"]=>
  bool(false)
  ["is_expired"]=>
  bool(false)
  ["have_secret"]=>
  bool(false)
  ["have_public"]=>
  bool(true)
  ["valid_till"]=>
  int(-1)
  ["expiration"]=>
  int(0)
  ["bits"]=>
  int(1024)
  ["alg"]=>
  string(3) "RSA"
  ["version"]=>
  int(4)
  ["revokers"]=>
  array(0) {
  }
}
key E332B27CAF4742A11BAA677F1ED63EE56FADC34D
array(13) {
  ["is_primary"]=>
  bool(false)
  ["is_sub"]=>
  bool(true)
  ["is_valid"]=>
  bool(true)
  ["is_revoked"]=>
  bool(false)
  ["is_expired"]=>
  bool(false)
  ["have_secret"]=>
  bool(false)
  ["have_public"]=>
  bool(true)
  ["valid_till"]=>
  int(-1)
  ["expiration"]=>
  int(0)
  ["bits"]=>
  int(1024)
  ["alg"]=>
  string(3) "RSA"
  ["version"]=>
  int(4)
  ["revokers"]=>
  array(0) {
  }
}
key C5B15209940A7816A7AF3FB51D7E8A5393C997A8
array(13) {
  ["is_primary"]=>
  bool(false)
  ["is_sub"]=>
  bool(true)
  ["is_valid"]=>
  bool(false)
  ["is_revoked"]=>
  bool(false)
  ["is_expired"]=>
  bool(true)
  ["have_secret"]=>
  bool(false)
  ["have_public"]=>
  bool(true)
  ["valid_till"]=>
  int(1511197051)
  ["expiration"]=>
  int(10627200)
  ["bits"]=>
  int(1024)
  ["alg"]=>
  string(3) "DSA"
  ["version"]=>
  int(4)
  ["revokers"]=>
  array(0) {
  }
}
key 5CD46D2A0BD0B8CFE0B130AE8A05B89FAD5ADED1
array(13) {
  ["is_primary"]=>
  bool(false)
  ["is_sub"]=>
  bool(true)
  ["is_valid"]=>
  bool(true)
  ["is_revoked"]=>
  bool(false)
  ["is_expired"]=>
  bool(false)
  ["have_secret"]=>
  bool(false)
  ["have_public"]=>
  bool(true)
  ["valid_till"]=>
  int(-1)
  ["expiration"]=>
  int(0)
  ["bits"]=>
  int(1024)
  ["alg"]=>
  string(3) "RSA"
  ["version"]=>
  int(4)
  ["revokers"]=>
  array(0) {
  }
}
key BE1C4AB951F4C2F6B604C7F82FCADF05FFA501BB
array(15) {
  ["uids"]=>
  array(3) {
    [0]=>
    array(6) {
      ["data"]=>
      string(9) "key1-uid0"
      ["type"]=>
      int(1)
      ["is_primary"]=>
      bool(false)
      ["is_valid"]=>
      bool(true)
      ["is_revoked"]=>
      bool(false)
      ["signature_count"]=>
      int(1)
    }
    [1]=>
    array(6) {
      ["data"]=>
      string(9) "key1-uid2"
      ["type"]=>
      int(1)
      ["is_primary"]=>
      bool(false)
      ["is_valid"]=>
      bool(true)
      ["is_revoked"]=>
      bool(false)
      ["signature_count"]=>
      int(1)
    }
    [2]=>
    array(6) {
      ["data"]=>
      string(9) "key1-uid1"
      ["type"]=>
      int(1)
      ["is_primary"]=>
      bool(false)
      ["is_valid"]=>
      bool(true)
      ["is_revoked"]=>
      bool(false)
      ["signature_count"]=>
      int(1)
    }
  }
  ["subkeys"]=>
  array(2) {
    [0]=>
    string(40) "A3E94DE61A8CB229413D348E54505A936A4A970E"
    [1]=>
    string(40) "57F8ED6E5C197DB63C60FFAF326EF111425D14A5"
  }
  ["is_primary"]=>
  bool(true)
  ["is_sub"]=>
  bool(false)
  ["is_valid"]=>
  bool(true)
  ["is_revoked"]=>
  bool(false)
  ["is_expired"]=>
  bool(false)
  ["have_secret"]=>
  bool(false)
  ["have_public"]=>
  bool(true)
  ["valid_till"]=>
  int(3577233754)
  ["expiration"]=>
  int(2076663808)
  ["bits"]=>
  int(1024)
  ["alg"]=>
  string(3) "DSA"
  ["version"]=>
  int(4)
  ["revokers"]=>
  array(0) {
  }
}
key A3E94DE61A8CB229413D348E54505A936A4A970E
array(13) {
  ["is_primary"]=>
  bool(false)
  ["is_sub"]=>
  bool(true)
  ["is_valid"]=>
  bool(true)
  ["is_revoked"]=>
  bool(false)
  ["is_expired"]=>
  bool(false)
  ["have_secret"]=>
  bool(false)
  ["have_public"]=>
  bool(true)
  ["valid_till"]=>
  int(3577233754)
  ["expiration"]=>
  int(2076663808)
  ["bits"]=>
  int(1024)
  ["alg"]=>
  string(7) "ELGAMAL"
  ["version"]=>
  int(4)
  ["revokers"]=>
  array(0) {
  }
}
key 57F8ED6E5C197DB63C60FFAF326EF111425D14A5
array(13) {
  ["is_primary"]=>
  bool(false)
  ["is_sub"]=>
  bool(true)
  ["is_valid"]=>
  bool(true)
  ["is_revoked"]=>
  bool(false)
  ["is_expired"]=>
  bool(false)
  ["have_secret"]=>
  bool(false)
  ["have_public"]=>
  bool(true)
  ["valid_till"]=>
  int(3577233754)
  ["expiration"]=>
  int(0)
  ["bits"]=>
  int(1024)
  ["alg"]=>
  string(7) "ELGAMAL"
  ["version"]=>
  int(4)
  ["revokers"]=>
  array(0) {
  }
}