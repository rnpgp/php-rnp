--TEST--
Dump packets test
--EXTENSIONS--
rnp
--FILE--
<?php

require_once "testkeys.inc";

var_dump(rnp_dump_packets('', 0));
var_dump(rnp_dump_packets_to_json('', 0));

var_dump(rnp_dump_packets($keyring1_pubring, 0));
var_dump(is_array(json_decode(rnp_dump_packets_to_json($keyring1_pubring, 0), true)));
?>
--EXPECT--
bool(false)
bool(false)
string(13418) ":armored input
:off 0: packet header 0x988d (tag 6, len 141)
Public key packet
    version: 4
    creation time: 1500569820 (Thu Jul 20 20:57:00 2017)
    public key algorithm: 1 (RSA (Encrypt or Sign))
    public key material:
        rsa n: 1024 bits
        rsa e: 17 bits
    keyid: 0x7bc6709b15c23a4a
:off 143: packet header 0xb409 (tag 13, len 9)
UserID packet
    id: key0-uid0
:off 154: packet header 0x88b9 (tag 2, len 185)
Signature packet
    version: 4
    type: 19 (Positive User ID certification)
    public key algorithm: 1 (RSA (Encrypt or Sign))
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500569820 (Thu Jul 20 20:57:00 2017)
        :type 27, len 1
        key flags: 0x03 ( certify sign )
        :type 11, len 6
        preferred symmetric algorithms: AES-256, AES-192, AES-128, CAST5, TripleDES, IDEA (9, 8, 7, 3, 2, 1)
        :type 21, len 5
        preferred hash algorithms: SHA256, SHA1, SHA384, SHA512, SHA224 (8, 2, 9, 10, 11)
        :type 22, len 3
        preferred compression algorithms: ZLib, BZip2, ZIP (2, 3, 1)
        :type 30, len 1
        features: 0x01 ( mdc )
        :type 23, len 1
        key server preferences
        no-modify: 1
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x7bc6709b15c23a4a
    lbits: 0x1ba7
    signature material:
        rsa s: 1024 bits
:off 341: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 345: packet header 0xb409 (tag 13, len 9)
UserID packet
    id: key0-uid1
:off 356: packet header 0x88b9 (tag 2, len 185)
Signature packet
    version: 4
    type: 19 (Positive User ID certification)
    public key algorithm: 1 (RSA (Encrypt or Sign))
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500569836 (Thu Jul 20 20:57:16 2017)
        :type 27, len 1
        key flags: 0x03 ( certify sign )
        :type 11, len 6
        preferred symmetric algorithms: AES-256, AES-192, AES-128, CAST5, TripleDES, IDEA (9, 8, 7, 3, 2, 1)
        :type 21, len 5
        preferred hash algorithms: SHA256, SHA1, SHA384, SHA512, SHA224 (8, 2, 9, 10, 11)
        :type 22, len 3
        preferred compression algorithms: ZLib, BZip2, ZIP (2, 3, 1)
        :type 30, len 1
        features: 0x01 ( mdc )
        :type 23, len 1
        key server preferences
        no-modify: 1
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x7bc6709b15c23a4a
    lbits: 0x0a16
    signature material:
        rsa s: 1023 bits
:off 543: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 547: packet header 0xb409 (tag 13, len 9)
UserID packet
    id: key0-uid2
:off 558: packet header 0x88b9 (tag 2, len 185)
Signature packet
    version: 4
    type: 19 (Positive User ID certification)
    public key algorithm: 1 (RSA (Encrypt or Sign))
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500569846 (Thu Jul 20 20:57:26 2017)
        :type 27, len 1
        key flags: 0x03 ( certify sign )
        :type 11, len 6
        preferred symmetric algorithms: AES-256, AES-192, AES-128, CAST5, TripleDES, IDEA (9, 8, 7, 3, 2, 1)
        :type 21, len 5
        preferred hash algorithms: SHA256, SHA1, SHA384, SHA512, SHA224 (8, 2, 9, 10, 11)
        :type 22, len 3
        preferred compression algorithms: ZLib, BZip2, ZIP (2, 3, 1)
        :type 30, len 1
        features: 0x01 ( mdc )
        :type 23, len 1
        key server preferences
        no-modify: 1
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x7bc6709b15c23a4a
    lbits: 0x5e6b
    signature material:
        rsa s: 1024 bits
:off 745: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 749: packet header 0xb88d (tag 14, len 141)
Public subkey packet
    version: 4
    creation time: 1500569820 (Thu Jul 20 20:57:00 2017)
    public key algorithm: 1 (RSA (Encrypt or Sign))
    public key material:
        rsa n: 1024 bits
        rsa e: 17 bits
    keyid: 0x1ed63ee56fadc34d
:off 892: packet header 0x889f (tag 2, len 159)
Signature packet
    version: 4
    type: 24 (Subkey Binding Signature)
    public key algorithm: 1 (RSA (Encrypt or Sign))
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500569820 (Thu Jul 20 20:57:00 2017)
        :type 27, len 1
        key flags: 0x0c ( encrypt_comm encrypt_storage )
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x7bc6709b15c23a4a
    lbits: 0x649e
    signature material:
        rsa s: 1024 bits
:off 1053: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 1057: packet header 0xb901a2 (tag 14, len 418)
Public subkey packet
    version: 4
    creation time: 1500569851 (Thu Jul 20 20:57:31 2017)
    public key algorithm: 17 (DSA)
    public key material:
        dsa p: 1024 bits
        dsa q: 160 bits
        dsa g: 1023 bits
        dsa y: 1021 bits
    keyid: 0x1d7e8a5393c997a8
:off 1478: packet header 0x88ed (tag 2, len 237)
Signature packet
    version: 4
    type: 24 (Subkey Binding Signature)
    public key algorithm: 1 (RSA (Encrypt or Sign))
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500569851 (Thu Jul 20 20:57:31 2017)
        :type 27, len 1
        key flags: 0x02 ( sign )
        :type 9, len 4
        key expiration time: 10627200 seconds (123 days)
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x7bc6709b15c23a4a
        :type 32, len 70
        embedded signature:
            version: 4
            type: 25 (Primary Key Binding Signature)
            public key algorithm: 17 (DSA)
            hash algorithm: 2 (SHA1)
            hashed subpackets:
                :type 2, len 4
                signature creation time: 1500569851 (Thu Jul 20 20:57:31 2017)
            unhashed subpackets:
                :type 16, len 8
                issuer key ID: 0x1d7e8a5393c997a8
            lbits: 0xef3d
            signature material:
                dsa r: 159 bits
                dsa s: 159 bits
    lbits: 0xba6a
    signature material:
        rsa s: 1022 bits
:off 1717: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 1721: packet header 0xb88d (tag 14, len 141)
Public subkey packet
    version: 4
    creation time: 1500569896 (Thu Jul 20 20:58:16 2017)
    public key algorithm: 1 (RSA (Encrypt or Sign))
    public key material:
        rsa n: 1024 bits
        rsa e: 17 bits
    keyid: 0x8a05b89fad5aded1
:off 1864: packet header 0x889f (tag 2, len 159)
Signature packet
    version: 4
    type: 24 (Subkey Binding Signature)
    public key algorithm: 1 (RSA (Encrypt or Sign))
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500569896 (Thu Jul 20 20:58:16 2017)
        :type 27, len 1
        key flags: 0x0c ( encrypt_comm encrypt_storage )
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x7bc6709b15c23a4a
    lbits: 0x4c80
    signature material:
        rsa s: 1024 bits
:off 2025: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 2029: packet header 0x9901a2 (tag 6, len 418)
Public key packet
    version: 4
    creation time: 1500569946 (Thu Jul 20 20:59:06 2017)
    public key algorithm: 17 (DSA)
    public key material:
        dsa p: 1024 bits
        dsa q: 160 bits
        dsa g: 1021 bits
        dsa y: 1021 bits
    keyid: 0x2fcadf05ffa501bb
:off 2450: packet header 0xb409 (tag 13, len 9)
UserID packet
    id: key1-uid0
:off 2461: packet header 0x8874 (tag 2, len 116)
Signature packet
    version: 4
    type: 19 (Positive User ID certification)
    public key algorithm: 17 (DSA)
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 27, len 1
        key flags: 0x03 ( certify sign )
        :type 9, len 4
        key expiration time: 2076663808 seconds (24035 days)
        :type 30, len 1
        features: 0x01 ( mdc )
        :type 23, len 1
        key server preferences
        no-modify: 1
        :type 11, len 2
        preferred symmetric algorithms: AES-192, CAST5 (8, 3)
        :type 21, len 2
        preferred hash algorithms: SHA1, SHA224 (2, 11)
        :type 22, len 2
        preferred compression algorithms: ZIP, Uncompressed (1, 0)
        :type 2, len 4
        signature creation time: 1501372449 (Sun Jul 30 03:54:09 2017)
        :type 24, len 17
        preferred key server: hkp://pgp.mit.edu
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x2fcadf05ffa501bb
    lbits: 0x8d08
    signature material:
        dsa r: 159 bits
        dsa s: 155 bits
:off 2579: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 2583: packet header 0xb409 (tag 13, len 9)
UserID packet
    id: key1-uid2
:off 2594: packet header 0x8869 (tag 2, len 105)
Signature packet
    version: 4
    type: 19 (Positive User ID certification)
    public key algorithm: 17 (DSA)
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500570153 (Thu Jul 20 21:02:33 2017)
        :type 27, len 1
        key flags: 0x03 ( certify sign )
        :type 9, len 4
        key expiration time: 2076663808 seconds (24035 days)
        :type 11, len 6
        preferred symmetric algorithms: AES-256, AES-192, AES-128, CAST5, TripleDES, IDEA (9, 8, 7, 3, 2, 1)
        :type 21, len 5
        preferred hash algorithms: SHA256, SHA1, SHA384, SHA512, SHA224 (8, 2, 9, 10, 11)
        :type 22, len 3
        preferred compression algorithms: ZLib, BZip2, ZIP (2, 3, 1)
        :type 30, len 1
        features: 0x01 ( mdc )
        :type 23, len 1
        key server preferences
        no-modify: 1
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x2fcadf05ffa501bb
    lbits: 0xd12d
    signature material:
        dsa r: 159 bits
        dsa s: 158 bits
:off 2701: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 2705: packet header 0xb409 (tag 13, len 9)
UserID packet
    id: key1-uid1
:off 2716: packet header 0x8869 (tag 2, len 105)
Signature packet
    version: 4
    type: 19 (Positive User ID certification)
    public key algorithm: 17 (DSA)
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500570147 (Thu Jul 20 21:02:27 2017)
        :type 27, len 1
        key flags: 0x03 ( certify sign )
        :type 9, len 4
        key expiration time: 2076663808 seconds (24035 days)
        :type 11, len 6
        preferred symmetric algorithms: AES-256, AES-192, AES-128, CAST5, TripleDES, IDEA (9, 8, 7, 3, 2, 1)
        :type 21, len 5
        preferred hash algorithms: SHA256, SHA1, SHA384, SHA512, SHA224 (8, 2, 9, 10, 11)
        :type 22, len 3
        preferred compression algorithms: ZLib, BZip2, ZIP (2, 3, 1)
        :type 30, len 1
        features: 0x01 ( mdc )
        :type 23, len 1
        key server preferences
        no-modify: 1
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x2fcadf05ffa501bb
    lbits: 0xc9b1
    signature material:
        dsa r: 159 bits
        dsa s: 156 bits
:off 2823: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 2827: packet header 0xb9010d (tag 14, len 269)
Public subkey packet
    version: 4
    creation time: 1500569946 (Thu Jul 20 20:59:06 2017)
    public key algorithm: 16 (Elgamal (Encrypt-Only))
    public key material:
        eg p: 1024 bits
        eg g: 3 bits
        eg y: 1021 bits
    keyid: 0x54505a936a4a970e
:off 3099: packet header 0x884f (tag 2, len 79)
Signature packet
    version: 4
    type: 24 (Subkey Binding Signature)
    public key algorithm: 17 (DSA)
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500569946 (Thu Jul 20 20:59:06 2017)
        :type 27, len 1
        key flags: 0x0c ( encrypt_comm encrypt_storage )
        :type 9, len 4
        key expiration time: 2076663808 seconds (24035 days)
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x2fcadf05ffa501bb
    lbits: 0xe016
    signature material:
        dsa r: 157 bits
        dsa s: 156 bits
:off 3180: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

:off 3184: packet header 0xb9010d (tag 14, len 269)
Public subkey packet
    version: 4
    creation time: 1500570165 (Thu Jul 20 21:02:45 2017)
    public key algorithm: 16 (Elgamal (Encrypt-Only))
    public key material:
        eg p: 1024 bits
        eg g: 3 bits
        eg y: 1023 bits
    keyid: 0x326ef111425d14a5
:off 3456: packet header 0x8849 (tag 2, len 73)
Signature packet
    version: 4
    type: 24 (Subkey Binding Signature)
    public key algorithm: 17 (DSA)
    hash algorithm: 2 (SHA1)
    hashed subpackets:
        :type 2, len 4
        signature creation time: 1500570165 (Thu Jul 20 21:02:45 2017)
        :type 27, len 1
        key flags: 0x0c ( encrypt_comm encrypt_storage )
    unhashed subpackets:
        :type 16, len 8
        issuer key ID: 0x2fcadf05ffa501bb
    lbits: 0x07e6
    signature material:
        dsa r: 159 bits
        dsa s: 158 bits
:off 3531: packet header 0xb002 (tag 12, len 2)
Skipping unhandled pkt: 12

"
bool(true)
