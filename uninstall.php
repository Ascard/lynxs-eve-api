<?php
	// If SSI.php is in the same place as this file, and SMF isn't defined...
	if (file_exists(dirname(__FILE__) . '/SSI.php') && !defined('SMF'))
		require_once(dirname(__FILE__) . '/SSI.php');
	
	// Hmm... no SSI.php and no SMF?
	elseif (!defined('SMF'))
		die('<b>Error:</b> Cannot uninstall - please verify you put this in the same place as SMF\'s index.php.');
	global $smcFunc, $db_prefix, $sourcedir;
	
	remove_integration_function('integrate_pre_include', '$sourcedir/LEA.php', true);
	remove_integration_function('integrate_actions', 'sso_callback');