--TEST--
autocrypt key export test
--EXTENSIONS--
rnp
--CAPTURE_STDIO--
STDIN STDOUT
--FILE--
<?php
require_once "testkeys.inc";

$ffi = rnp_ffi_create('GPG', 'GPG');

//non-existent key fingerprint
var_dump(rnp_key_export_autocrypt($ffi, '0000000000000000000000000000000000000000', '', '', 0));

rnp_load_keys($ffi, 'GPG', $keyring1_pubring, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS);

var_dump(rnp_key_export_autocrypt($ffi, 'E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A', '', "key0-uid0", RNP_KEY_EXPORT_BASE64));

rnp_ffi_destroy($ffi);
?>
--EXPECT--
bool(false)
string(860) "xo0EWXDg3AEEAMedwkPY1lO/5eJSo7T/t2+7/bZk15AMDZ5yitSvL81l6wY9QtkAvf40dxrF8CMwDlDIi+X8w1syR/t4i44ZZYu3+LA1vRUnGXD2pAGRizjU2v7ZoR2ovEciOC2bWOEiFJdk9J15tDeLy191ney3TsYZ9bdYoBBra3UpJqFgtVWJABEBAAHNCWtleTAtdWlkMMK5BBMBAgAjBQJZcODcAhsDBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQe8ZwmxXCOkobpwQAukuqm19euXuEE/cM3vMS/W5XoQ5Mutsuq9sE7f4SbTInLaAwot6sWfqLh/pal78dN0NoazadNFOGLVqaidM1vPcHnFW4iMkmnY9imNA1H2nIYXywWlacYJuJdCM0OzwM/VLLPXSzy/iNLCehGNgbSrtPdRcfwcIwgnu+rPSf/JDOjQRZcOEoAQQA6THC3fTRsTHdOUOTWTEUSuY9EKJeDug3FGSulfNDBbgA5qR364DEax7CYciJeCKn+0Uw+HNTIoDpWyOqV+5O+inP0MT5+VwatxYeqEcP3mfNXpkZUeQsxJswbnsvSIrKLjxny3V9kR2J/ycE+YuvWOyd1P4evBvIbUg/BrAg+vsAEQEAAcKfBBgBAgAJBQJZcOEoAhsMAAoJEHvGcJsVwjpKTIAEALOhKe7VP9fLQSObAaD7OcqXkivFbTgcaYdghVkUed5puDh8/v/ZP5uJEps/oa9k5i7ivbXBcCcyP2G/aMCGBVEVg/Bth3jqb7Eqr1cUBfgFs2ntFxMYUIMi8ut5TlmYoIhPvlq1oe6v+soc4siKypc4xXUitECMdYupwHnA+ORO"
