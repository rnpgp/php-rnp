<?php

//check presence of a specified substring in
// a dump of PGP packets
function rnptest_checkdump($input, $substr, $expected_count)
{
	$dump = rnp_dump_packets($input, 0);

	if (!is_string($dump)) {
		echo "Error! Failed to dump PGP packets!\n";
		return;
	}

	$actual_count = substr_count($dump, $substr);

	if ($actual_count != intval($expected_count)) {
		echo "Error! Substring '".$substr."' was found ".
			$actual_count." times instead of ".$expected_count."\n";
		return;
	}

	//print the substring in case of success
	echo $substr."\n";
}

?>
