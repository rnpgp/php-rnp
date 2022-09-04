--TEST--
Dump packets test
--EXTENSIONS--
rnp
--FILE--
<?php

require_once "testkeys.inc";

var_dump(rnp_dump_packets('', 0));
//wrong flags
var_dump(rnp_dump_packets($keyring1_pubring, 255));
var_dump(rnp_dump_packets_to_json('', 0));
//wrong flags
var_dump(rnp_dump_packets_to_json($keyring1_pubring, 255));

var_dump(substr_count(rnp_dump_packets($keyring1_pubring, 0), "Public key packet") == 2);
var_dump(substr_count(rnp_dump_packets($keyring1_pubring, RNP_DUMP_MPI), "rsa e: 17 bits, 010001") == 3);
var_dump(substr_count(rnp_dump_packets($keyring1_pubring, RNP_DUMP_RAW), "packet header") == 35);
var_dump(substr_count(rnp_dump_packets($keyring1_pubring, RNP_DUMP_GRIP), "grip:") == 7);

var_dump(is_array(json_decode(rnp_dump_packets_to_json($keyring1_pubring, 0), true)));
var_dump(is_array(json_decode(rnp_dump_packets_to_json($keyring1_pubring, RNP_JSON_DUMP_MPI), true)));
var_dump(is_array(json_decode(rnp_dump_packets_to_json($keyring1_pubring, RNP_JSON_DUMP_RAW), true)));
var_dump(is_array(json_decode(rnp_dump_packets_to_json($keyring1_pubring, RNP_JSON_DUMP_GRIP), true)));
?>
--EXPECT--
bool(false)
bool(false)
bool(false)
bool(false)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
