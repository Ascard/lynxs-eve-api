<?php

$txt['lea_getchar'] = 'Get Characters';

require_once("Sources/LEAC.php");
$leac = new LEAC;
$chars = $leac -> get_api_characters($_GET['userid'], $_GET['api']);

if(!empty($chars))
{
	echo '<select name="lea_charid" id="lea_charid" >';
	foreach($chars as $char)
	{
		echo '<option value="'.$char['charid'].'">'.$char['name'].'</option>';
	}
}
else
{
	$error = $leac -> get_error($leac->data);
	echo 'Error '.$error[0].' ('.$error[1].')<Br><select name="lea_char"><option value="-">-</option>';
}
echo '</select> <button type="button" onclick="javascript: getchars()">'.$txt['lea_getchar'].'</button>';
?>