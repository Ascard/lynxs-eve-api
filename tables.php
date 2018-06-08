<?php
	/*******************************************************************************
	 * This is a simplified script to add settings into SMF.
	 *
	 * ATTENTION: If you are trying to INSTALL this package, please access
	 * it directly, with a URL like the following:
	 * http://www.yourdomain.tld/forum/add_settings.php (or similar.)
	 *
	 * ================================================================================
	 *
	 * This script can be used to add new settings into the database for use
	 * with SMF's $modSettings array.  It is meant to be run either from the
	 * package manager or directly by URL.
	 *******************************************************************************/
	
	// Set the below to true to overwrite already existing settings with the defaults. (not recommended.)
	$overwrite_old_settings = false;
	
	// List settings here in the format: setting_key => default_value.  Escape any "s. (" => \")
	$mod_settings = array(
		'example_setting' => '1',
		'example_setting2' => '0',
	);
	
	/******************************************************************************/
	
	// If SSI.php is in the same place as this file, and SMF isn't defined, this is being run standalone.
	if (file_exists(dirname(__FILE__) . '/SSI.php') && !defined('SMF'))
		require_once(dirname(__FILE__) . '/SSI.php');
	// Hmm... no SSI.php and no SMF?
	elseif (!defined('SMF'))
		die('<b>Error:</b> Cannot install - please verify you put this in the same place as SMF\'s index.php.');
	
	
	function lea_check_table($table, $columns) {
		$fields = lea_select("EXPLAIN " . $table, MYSQL_ASSOC, FALSE);
		
		if (!empty($fields)) {
			foreach ($fields AS $field) {
				$fcolumns[$field['Field']] = TRUE;
			}
		} else
			Return (array(FALSE, FALSE));
		
		foreach ($columns as $c => $vars) {
			if (!isset($fcolumns[$c]))
				$missing[] = $c;
		}
		if (!empty($missing)) {
			Return (array(FALSE, $missing));
		} else
			Return (array(TRUE));
	}
	
	function lea_select($sql, $result_form = MYSQL_NUM, $error = TRUE)//MYSQL_ASSOC = field names
	{
		$data = "";
		$result = mysqli_query($sql);
		
		if (!$result) {
			//echo $sql;
			if ($error)
				echo "<BR>" . mysqli_error() . "<BR>";
			return false;
		}
		
		if (empty($result)) {
			return false;
		}
		
		while ($row = mysql_fetch_array($result, $result_form)) {
			$data[] = $row;
		}
		
		mysql_free_result($result);
		return $data;
	}
	
	function lea_query($sql) {
		$return = mysqli_query($sql);
		
		if (!$return) {
			//echo $sql;
			echo mysqli_error();
			return false;
		} else {
			return true;
		}
	}
	
	$info[1]['old'] = 'eve_api';
	$info[1]['name'] = 'lea_tokens';
	$info[1]['primary'] = 'id_member, character_hash';
	$tables[1]["id_member"] = "INT";
	$tables[1]["character_hash"] = "VARCHAR(32)  DEFAULT NULL"; // CharacterOwnerHash
	$tables[1]["access_token"] = "VARCHAR(96)  DEFAULT NULL";
	$tables[1]["refresh_token"] = "VARCHAR(96)  DEFAULT NULL";
	$tables[1]["expires"] = "INT(10)      DEFAULT NULL";
	$tables[1]["status"] = "VARCHAR(20)  DEFAULT NULL"; // выпилить ?
	$tables[1]["matched"] = "VARCHAR(20)  DEFAULT NULL"; // выпилить ?
	$tables[1]["errorid"] = "INT(5)       DEFAULT NULL"; // выпилить ?
	$tables[1]["error"] = "VARCHAR(254) DEFAULT NULL";
	$tables[1]["status_change"] = "INT          DEFAULT NULL"; // выпилить ?
	
	$info[2]['old'] = 'eve_characters';
	$info[2]['name'] = 'lea_characters';
	$info[2]['primary'] = 'userid, charid';
	$tables[2]["userid"] = "INT DEFAULT NULL";
	$tables[2]["charid"] = "INT DEFAULT NULL";
	$tables[2]["name"] = "VARCHAR(50) DEFAULT NULL";
	$tables[2]["corpid"] = "INT DEFAULT NULL";
	$tables[2]["corp"] = "VARCHAR(50) DEFAULT NULL";
	$tables[2]["corp_ticker"] = "VARCHAR(20) DEFAULT NULL";
	$tables[2]["allianceid"] = "INT DEFAULT NULL";
	$tables[2]["alliance"] = "VARCHAR(50) DEFAULT NULL";
	$tables[2]["alliance_ticker"] = "VARCHAR(20) DEFAULT NULL";
	
	$info[3]['old'] = 'eve_rules';
	$info[3]['name'] = 'lea_rules';
	$info[3]['primary'] = 'ruleid';
	$tables[3]["ruleid"] = "INT DEFAULT NULL AUTO_INCREMENT";
	$tables[3]["name"] = "VARCHAR(50) DEFAULT NULL";
	$tables[3]["main"] = "INT(1) DEFAULT 0";
	$tables[3]["andor"] = "VARCHAR(3) DEFAULT 'AND'";
	$tables[3]["group"] = "INT DEFAULT NULL";
	$tables[3]["enabled"] = "INT(1) DEFAULT 0";
	
	$info[4]['old'] = 'eve_conditions';
	$info[4]['name'] = 'lea_conditions';
	$info[4]['primary'] = 'id';
	$tables[4]["id"] = "INT DEFAULT NULL AUTO_INCREMENT";
	$tables[4]["ruleid"] = "INT DEFAULT NULL";
	$tables[4]["isisnt"] = "VARCHAR(4) DEFAULT 'is'";
	$tables[4]["type"] = "VARCHAR(50) DEFAULT NULL";
	$tables[4]["value"] = "VARCHAR(250) DEFAULT NULL";
	$tables[4]["extra"] = "VARCHAR(250) DEFAULT NULL";
	
	$info[5]['old'] = 'eve_groups';
	$info[5]['name'] = 'lea_groups';
	$info[5]['primary'] = 'id';
	$tables[5]["id"] = "INT DEFAULT NULL";
	$tables[5]["main"] = "INT(1) DEFAULT 1";
	$tables[5]["additional"] = "INT(1) DEFAULT 1";
	
	$info[6]['name'] = 'lea_cache';
	$info[6]['primary'] = 'address, post';
	$tables[6]["address"] = "VARCHAR(100) DEFAULT NULL";
	$tables[6]["post"] = "VARCHAR(233) DEFAULT NULL";
	$tables[6]["time"] = "INT DEFAULT 0";
	$tables[6]["xml"] = "MEDIUMTEXT";
	
	$info[7]['name'] = 'lea_ts_rules';
	$info[7]['primary'] = 'id';
	$tables[7]["id"] = "INT DEFAULT NULL AUTO_INCREMENT";
	$tables[7]["smf"] = "INT DEFAULT 0";
	$tables[7]["ts"] = "INT DEFAULT 0";
	$tables[7]["tst"] = "VARCHAR(1) DEFAULT NULL";
	$tables[7]["nf"] = "VARCHAR(255) DEFAULT NULL";
	
	$info[8]['name'] = 'lea_ts_users';
	$info[8]['primary'] = 'id';
	$tables[8]["id"] = "INT";
	$tables[8]["tsid"] = "VARCHAR(255)";
	$tables[8]["dbid"] = "INT";
	$tables[8]["name"] = "VARCHAR(255)";
	$tables[8]["warnstart"] = "INT";
	$tables[8]["lastwarn"] = "INT";
	
	$info[9]['name'] = 'lea_ts_groups';
	$info[9]['primary'] = 'id';
	$tables[9]["id"] = "VARCHAR(11) DEFAULT NULL";
	$tables[9]["value"] = "INT(1) DEFAULT 1";
	
	$info[10]['name'] = 'lea_member_characters';
	$info[10]['primary'] = 'id_member, character_id';
	$info[10]['unique'] = 'character_hash';
	$tables[10]["id_member"] = "VARCHAR(11) NOT NULL DEFAULT ''";
	$tables[10]["character_id"] = "INT(11)     NOT NULL";
	$tables[10]["character_hash"] = "VARCHAR(32) NULL DEFAULT NULL"; // CharacterOwnerHash
	$tables[10]["is_main"] = "BOOLEAN     NOT NULL";
	
	Global $db_prefix;
	
	require("esam_upgrade.php");
	
	$esaminfo['old'] = 'eve_api';
	$esaminfo['name'] = 'lea_api';
	$esaminfo['esam'] = 'esam_api';
	$checkold = esamup_check_table($db_prefix . $esaminfo['old']);
	$check = esamup_check_table($db_prefix . $esaminfo['name']);
	$esam = esamup_check_table($db_prefix . $esaminfo['esam']);
	if (!$checkold && !$check && $esam) // lea never installed, esam has
	{
		$esamupgrade = TRUE;
	}
	
	foreach ($tables as $i => $table) {
		$checkold = lea_check_table($db_prefix . $info[$i]['old'], $table);
		$check = lea_check_table($db_prefix . $info[$i]['name'], $table);
		if (($checkold[0] || (!$checkold[0] && $checkold[1])) && !$check[0] && !$check[1]) // if old table exists regardless of if needs changing and new doesnt then rename
			lea_query("RENAME TABLE " . $db_prefix . $info[$i]['old'] . " TO " . $db_prefix . $info[$i]['name']);
		$check = lea_check_table($db_prefix . $info[$i]['name'], $table);
		if (!$check[0]) {
			if ($check[1]) {
				foreach ($check[1] as $f) {
					lea_query("ALTER TABLE " . $db_prefix . $info[$i]['name'] . " ADD " . $f . " " . $table[$f]);
				}
			} else {
				$sql = "CREATE TABLE " . $db_prefix . $info[$i]['name'] . " (";
				foreach ($table as $c => $d)
					$sql .= " `" . $c . "` " . $d . ",";
				$sql .= " PRIMARY KEY (" . $info[$i]['primary'] . "))";
				$sql .= isset($info[$i]['unique']) ? ', UNIQUE KEY `idx_' . time() . '` (`' + info[$i]['unique'] + '`)' : '';
				lea_query($sql);
			}
		}
		$check = lea_check_table($db_prefix . $info[$i]['name'], $table);
		if (!$check[0]) {
			if ($check[1]) {
				echo '<b>Error:</b> Database modifications failed!';
				$msg = "These Columns are missing: ";
				$msg .= implode(", ", $check[1]);
				echo $msg;
			} else
				echo '<b>Error:</b> Database modifications failed!';
		}
	}
	
	if ($esamupgrade) {
		run_upgrade();
	}
	
	// try to chmod the xmlhttp file as this is an issue for some
	chmod($boarddir . "/LEA_xmlhttp.php", 0644);
?>