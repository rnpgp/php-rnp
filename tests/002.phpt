--TEST--
RNP version & backend version API test
--EXTENSIONS--
rnp
--FILE--
<?php
$rnpv = rnp_version_string();
echo "RNP version: ".$rnpv."\n";

$rnpvf = rnp_version_string_full();
echo "RNP version full: ".$rnpvf."\n";

if (strlen($rnpvf) >= strlen($rnpv))
{
  echo "Full version string is longer than short one.\n";
}
else
{
  echo "Error! Full version string is shorter!\n";
}

echo "RNP backend: ".rnp_backend_string()."\n";
echo "RNP backen version: ".rnp_backend_version()."\n";
?>
--EXPECTF--
RNP version: %s
RNP version full: %s
Full version string is longer than short one.
RNP backend: %s
RNP backen version: %s

