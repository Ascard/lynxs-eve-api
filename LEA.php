<?php
	// Orlangure - 1149560158 - dPnzp2oEnP172TE+dyJ9lg0OiBQ=
	// Riland    - 784070564  - QU9ub5P/++dfajAkBSrbzEFJsGQ=
	
	if (!defined('SMF'))
		die('Hacking attempt...');
	
	global $lea, $db_prefix, $sourcedir, $modSettings, $user_info, $context, $txt, $smcFunc, $settings, $forum_copyright;
	loadLanguage('LEA');
	
	require_once($sourcedir . '/LEAC.php');
	
	class LEA extends LEAC {
		var $corps;
		
		function __construct(&$db_prefix, &$sourcedir, &$modSettings, &$user_info, &$context, &$txt, &$smcFunc, &$settings) {
			//	$this -> db_prefix = &$db_prefix;
			$this->sourcedir = &$sourcedir;
			$this->modSettings = &$modSettings;
			$this->user_info = &$user_info;
			$this->context = &$context;
			$this->txt = &$txt;
			$this->smcFunc = &$smcFunc;
			$this->settings = &$settings;
			
			$this->version = "1.2.1";
			
			$permissions["lea_view_own"] = 1;
			$permissions["lea_view_any"] = 0;
			$permissions["lea_edit_own"] = 1;
			$permissions["lea_edit_any"] = 0;
			
			$groups = array();
			
			// Get all the non-postcount based groups.
			$request = $this->smcFunc['db_query']('', "
		  SELECT ID_GROUP
		  FROM {db_prefix}membergroups
		  WHERE min_posts = {int:minposts}",
				array('minposts' => -1));
			$request = $this->db_select($request);
			
			// Get all the non-postcount based groups.
			$tgroupsq = $this->smcFunc['db_query']('', "
		  SELECT id
		  FROM {db_prefix}lea_groups");
			$tgroupsq = $this->db_select($tgroupsq);
			if (!empty($tgroupsq)) {
				foreach ($tgroupsq as $g) {
					$tgroups[$g[0]] = TRUE;
				}
			}
			
			// Add -1 to this array if you want to give guests the same permission
			$request[] = array(0);
			foreach ($request as $g) {
				if (!isset($tgroups[$g[0]])) {
					$groups[] = $g[0];
				} else {
					unset($tgroups[$g[0]]);
				}
			}
			foreach ($permissions as $p => $v) {
				if ($v == 1)
					$psql[] = $p;
			}
			
			if (!empty($groups)) {
				foreach ($groups as $g) {
					if ($g == 1)
						$v = 0;
					else
						$v = 1;
					// Give them all their new permission.
					$request = $this->smcFunc['db_query']('', "
					INSERT IGNORE INTO {db_prefix}permissions
						(permission, ID_GROUP, add_deny)
					VALUES
						('" . implode("', $g, 1),
						('", $psql) . "', $g, 1)");
					$request = $this->smcFunc['db_query']('', "
					INSERT INTO {db_prefix}lea_groups
						(id, main, additional) VALUES ($g, $v, $v)");
				}
			}
			if (!empty($tgroups)) {
				foreach ($tgroups as $g => $v) {
					$request = $this->smcFunc['db_query']('', "DELETE FROM {db_prefix}lea_groups WHERE id = $g");
				}
			}
			
			$dsets['lea_api_server'] = 'https://api.eve-online.com';
			$dsets['lea_lastpull'] = 0;
			$dsets['lea_nf'] = '[#ct#] #name#';
			$dsets['lea_tf'] = '#ct#';
			
			foreach ($dsets as $s => $v) {
				if (empty($this->settings[$s])) {
					$request = $this->smcFunc['db_query']('', "
				  INSERT IGNORE INTO {db_prefix}settings
					 (variable, value)
				  VALUES
					  ('" . $s . "', '" . $v . "')");
					$this->settings[$s] = $v;
				}
			}
			$this->server = $this->settings['lea_api_server'];
			$this->undefined();
			
			$this->initSSOProvider();
		}
		
		public function sso_callback() {
			global $scripturl;
			
			// If we don't have an authorization code then get one
			if (!isset($_GET['code'])) {
				
				// Fetch the authorization URL from the provider; this returns the
				// urlAuthorize option and generates and applies any necessary parameters
				// (e.g. state).
				$scope = [
					'esi-skills.read_skills.v1',
					'esi-skills.read_skillqueue.v1',
					'esi-wallet.read_character_wallet.v1',
					'esi-assets.read_assets.v1',
					'esi-corporations.track_members.v1',
					'esi-characterstats.read.v1'
				];
				$authorizationUrl = $this->provider->getAuthorizationUrl(array(
					"scope" => $scope,
					"state" => isset($_GET['returnaction']) ? 'returnaction=' . urlencode($_GET['returnaction']) : null
				));
				
				// Get the state generated for you and store it to the session.
				$_SESSION['oauth2state'] = $this->provider->getState();
				
				// Redirect the user to the authorization URL.
				header('Location: ' . $authorizationUrl);
				exit;
				
				// Check given state against previously stored one to mitigate CSRF attack
			} elseif (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
				if (isset($_SESSION['oauth2state'])) {
					unset($_SESSION['oauth2state']);
				}
				exit('Invalid state');
			} else {
				try {
					// Try to get an access token using the authorization code grant.
					$accessToken = $this->provider->getAccessToken('authorization_code', [
						'code' => $_GET['code']
					]);
					
					// We have an access token, which we may use in authenticated
					// requests against the service provider's API.
					// echo 'Access Token:    ' . $accessToken->getToken() . "<br>";
					// echo 'Refresh Token:   ' . $accessToken->getRefreshToken() . "<br>";
					// echo 'Expired in:      ' . $accessToken->getExpires() . "<br>";
					// echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";
					
					// Using the access token, we may look up details about the
					// resource owner.
					$resourceOwner = $this->provider->getResourceOwner($accessToken);
					
					// var_export($resourceOwner->toArray());
					
					// The provider provides a way to get an authenticated API request for
					// the service, using the access token; it returns an object conforming
					// to Psr\Http\Message\RequestInterface.
					// $request = $this->provider->getAuthenticatedRequest('GET', 'http://brentertainment.com/oauth2/lockdin/resource', $accessToken);
					
					$characterHash = urlencode($resourceOwner->getCharacterOwnerHash());
					$_SESSION[$characterHash] = array(
						'token' => $accessToken,
						'character' => $resourceOwner->toArray()
					);
					
					parse_str(html_entity_decode($_GET["state"]), $queryArray);
					$action = "?action=" . (isset($queryArray['returnaction']) ? $queryArray['returnaction'] : 'register');
					
					header('Location: ' . $scripturl . $action . "&characterHash=" . $characterHash . "&sesc=" . $_SESSION['session_value']);
					exit;
					
				} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
					// Failed to get the access token or user details.
					exit($e->getMessage());
				}
			}
		}
		
		function login() {
			global $txt, $context, $user_settings;
			
			$authInfo = $_SESSION[urlencode($_GET["characterHash"])];
			if (isset($authInfo) && $authInfo["character"]["CharacterOwnerHash"] == $_GET["characterHash"]) {
				$member_id = $this->getMemberByCharacterHash($authInfo["character"]["CharacterOwnerHash"]);
				
				$request = $this->smcFunc['db_query']('', '
				        SELECT passwd, id_member, id_group, lngfile, is_activated, email_address, additional_groups, member_name, password_salt, openid_uri, passwd_flood
				        FROM {db_prefix}members
				        WHERE id_member = {int:id_member}',
					array(
						'id_member' => $member_id,
					)
				);
				$user_settings = $this->smcFunc['db_fetch_assoc']($request);
				
				if (!checkActivation())
					return;
				DoLogin();
			} else {
				$context['login_errors'] = array($txt['invalid_userid']);
				return false;
			}
		}
		
		function getMemberByCharacterHash($characterHash) {
			$member = $this->smcFunc['db_query']('', "SELECT id_member FROM {db_prefix}lea_member_characters WHERE character_hash={string:character_hash}", array('character_hash' => $characterHash));
			$member = $this->smcFunc['db_fetch_assoc']($member);
			return isset($member["id_member"]) ? $member["id_member"] : null;
		}
		
		function getToken($memberId) {
			$token = $this->smcFunc['db_query']('', "SELECT ID_MEMBER, character_hash, access_token, refresh_token, expires FROM {db_prefix}lea_tokens WHERE ID_MEMBER='{int:id}'", array('id' => $memberId));
			$token = $this->smcFunc['db_fetch_assoc']($token);
			if (isset($token)) {
				$token = new League\OAuth2\Client\Token\AccessToken($token);
				return $token;
			}
			return null;
		}
		
		/**
		 * @param $memberID    SMF user id
		 * @param $token       ESI token
		 * @param [$character] character info
		 */
		private function saveToken($memberID, $token, $character = null) {
			$this->query("REPLACE INTO {db_prefix}lea_tokens "
				. "(ID_MEMBER, character_hash, access_token, refresh_token, expires, status, status_change)"
				. " VALUES "
				. "('{int:ID_MEMBER}', {string:character_hash}, {string:access_token}, {string:refresh_token}, '{int:expires}', {string:status}, {int:status_change})",
				array(
					'ID_MEMBER' => $memberID,
					'character_hash' => isset($character["CharacterOwnerHash"]) ? $character["CharacterOwnerHash"] : $_POST["lea_user_id"],
					'access_token' => $token->getToken(),
					'refresh_token' => $token->getRefreshToken(),
					'expires' => $token->getExpires(),
					'status' => 'checked',
					'status_change' => time()
				)
			);
		}
		
		function refreshToken($memberId) {
			$existingAccessToken = $this->getToken($memberId);
			
			if ($existingAccessToken->hasExpired()) {
				$newAccessToken = $this->provider->getAccessToken('refresh_token', [
					'refresh_token' => $existingAccessToken->getRefreshToken()
				]);
				
				// Purge old access token and store new access token to your data store.
			}
		}
		
		function initSSOProvider() {
			$this->provider = new jbs1\OAuth2\Client\Provider\EveOnline([
				'clientId' => 'db2172dd95a142a090180f3625a29d0d',             // The client ID assigned to you by the provider
				'clientSecret' => 'fcQah6SYrg8weSV0nrLCfMbkTUdpDO23reGZYh0d', // The client password assigned to you by the provider
				'redirectUri' => 'http://localhost/Forum/index.php?action=sso_callback',
			]);
		}
		
		function undefined() {
			$ms[] = 'lea_enable';
			$ms[] = 'lea_userid';
			$ms[] = 'lea_api';
			$ms[] = 'lea_charid';
			$ms[] = 'lea_groupass_unknown';
			$ms[] = 'lea_avatar_enabled';
			$ms[] = 'lea_avatar_locked';
			$ms[] = 'lea_regreq';
			$ms[] = 'lea_ts_enable';
			$ms[] = 'lea_avatar_size';
			foreach ($ms as $s) {
				if (!isset($this->modSettings[$s]))
					$this->modSettings[$s] = NULL;
			}
		}
		
		function updateMemberCharacters($memberID = NULL, $force = FALSE) {
			if (!$this->modSettings["lea_enable"])
				Return;
			
			$this->file = "\n\n\nDate: " . gmdate("F jS, Y H:i", time()) . "\n";
			
			$this->alliance_list(); // TODO
			$this->get_standings(); // TODO
			
			if (!function_exists('curl_init'))
				die("Update Functions Require cURL extension for PHP");
			
			if (!empty($memberID)) {
				$this->updateSingleCharacter($memberID);
			} else {
				// $this->updateAllCharacters($force); // TODO
			}
		}
		
		function get_standings() { // TODO
			//$sfile = $this->sourcedir . "/../cache/eve_standings.php";
			//if (file_exists($sfile)) {
			//    require($sfile);
			//    if ($time > (time() - (60 * 60 * 24))) {
			//        $this->blues = $blues;
			//        $this->reds = $reds;
			//        Return;
			//    }
			//    unset($corps);
			//}
			////$post = array('userID' => $this -> modSettings["lea_userid"], 'apiKey' => $this -> modSettings["lea_api"], 'characterID' => $this -> modSettings["lea_charid"]);
			//$data = $this->standings($this->modSettings["lea_userid"], $this->modSettings["lea_api"], $this->modSettings["lea_charid"]);
			//$this->blues = $data[0];
			//$this->reds = $data[1];
			//$count = $data[2];
			//
			//if ($count > 0) {
			//    $file = '<?php' . "\n\n";
			//    $file .= '$time = ' . time() . ';' . "\n\n";
			//    foreach ($this->blues as $c => $a) {
			//        $file .= '$blues[' . $c . '] = array(\'' . str_replace("'", "\'", $a[0]) . '\', ' . $a[1] . ', ' . $a[2] . ');' . "\n";
			//    }
			//    foreach ($this->reds as $c => $a) {
			//        $file .= '$reds[' . $c . '] = array(\'' . str_replace("'", "\'", $a[0]) . '\', ' . $a[1] . ', ' . $a[2] . ');' . "\n";
			//    }
			/*    $file .= '?>';*/
			//    $fp = fopen($sfile, 'w');
			//    fwrite($fp, $file);
			//    fclose($fp);
			//}
		}
		
		function updateSingleCharacter($memberID) {
			if (isset($this->modSettings["lea_groupass_unknown"]))
				$mongroups[$this->modSettings["lea_groupass_unknown"]] = TRUE;
			else
				$mongroups[0] = TRUE;
			
			$txt = $this->txt;
			
			// prevent undefined errors
			$character['main'] = NULL;
			$character['additional'] = NULL;
			$ignore = FALSE;
			
			$mongroups = $this->getGroups($mongroups);
			
			if (is_numeric($memberID)) {
				$smf_member = $this->smcFunc['db_query']('', "SELECT ID_MEMBER, ID_GROUP, additional_groups FROM {db_prefix}members WHERE ID_MEMBER = {int:id}", array('id' => $memberID));
				$smf_member = $this->db_select($smf_member);
			}
			
			if (empty($smf_member)) {
				$smf_member = $this->smcFunc['db_query']('', "SELECT ID_MEMBER, ID_GROUP, additional_groups FROM {db_prefix}members WHERE member_name = {string:user}", array('user' => $memberID));
				$smf_member = $this->db_select($smf_member);
			}
			
			if (!empty($smf_member)) {
				$group = $smf_member[0][1];
				$agroups = array();
				
				if (!empty($smf_member[0][2])) {
					$smf_member[0][2] = explode(',', $smf_member[0][2]);
					foreach ($smf_member[0][2] as $g)
						$agroups[$g] = $g;
				}
				
				//	remove all monitored groups
				if (!empty($mongroups)) {
					foreach ($mongroups as $g => $m) {
						if ($m[1] == 1)
							unset($agroups[$g]);
					}
				}
				$smf_member_id = $smf_member[0][0];
				if (!isset($mongroups[$group]) || $mongroups[$group][0] == 0) {
					$ignore = TRUE;
					$matched[0] = 'Not Monitored';
					$character['main'] = 'Not Monitored';
				}
				
				// $token = $this->smcFunc['db_query']('', "SELECT character_hash, access_token, refresh_token, status FROM {db_prefix}lea_tokens WHERE ID_MEMBER = {int:id}", array('id' => $id));
				// $token = $this->db_select($token);
				$token = $this->getToken($smf_member_id);
				$characters = $this->getMemberCharacters($smf_member_id);
				
				if (!empty($token) && !empty($characters)) {
					$mainmatch = FALSE;
					
					foreach ($characters as $char) {
						$error = FALSE;
						$matched = array('none', array());
						
						$chars = $this->get_character_info($char["character_id"], $token);
						
						if (empty($chars)) { // TODO
							// $error = $this->get_error($this->data);
							// $this->query("UPDATE {db_prefix}lea_tokens SET status = 'API Error', errorid = '" . $error[0] . "', error = '" . $error[1] . "', status_change = " . time() . " WHERE ID_MEMBER = " . $smf_member_id . " AND character_hash = " . $char);
							// if (($error[0] >= 500 && $error[0] < 600) || ($error[0] >= 900 && $error[0] < 1000)) { // Api System is Down
							//     return $character;
							// } else {
							//     $chars[] = array('name' => NULL, 'charid' => NULL, 'corpname' => NULL, 'corpid' => NULL, 'ticker' => NULL, 'allianceid' => NULL, 'alliance' => NULL);
							// }
							// $error = TRUE;
						}
						
						if (!empty($chars)) {
							// TODO
							//if (!$error)
							//    $this->query("UPDATE {db_prefix}lea_tokens SET status = 'OK', status_change = " . time() . " WHERE ID_MEMBER = {int:id} AND character_hash = {int:character_hash}",
							//        array('id' => $smf_member_id, 'character_hash' => $char));
							//// get main rules
							//$rules = $this->smcFunc['db_query']('', "SELECT ruleid, `group`, andor FROM {db_prefix}lea_rules WHERE main = 1 AND enabled = 1 ORDER BY ruleid");
							//$rules = $this->db_select($rules);
							//if (!empty($rules) && !$ignore) {
							//    foreach ($rules as $rule) {
							//        $andor = $rule[2];
							//        foreach ($chars as $char) {
							//            if (empty($this->matchedchar))
							//                $this->matchedchar = $char; // just to make sure we get 1
							//
							//            $conditions = $this->smcFunc['db_query']('', "SELECT type, value, extra, isisnt FROM {db_prefix}lea_conditions WHERE ruleid = {int:id}",
							//                array('id' => $rule[0]));
							//            $conditions = $this->db_select($conditions);
							//            if (!empty($conditions)) {
							//                $match = TRUE;
							//                foreach ($conditions as $cond) {
							//                    //echo "<pre>"; var_dump($cond);die;
							//                    //	$this -> chars[] = $char;
							//                    Switch ($cond[0]) {
							//                        case 'corp':
							//                            if ($cond[3] == 'is' && $char['corpid'] == $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && $char['corpid'] != $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $match = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'alliance':
							//                            if ($cond[3] == 'is' && $char['allianceid'] == $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && $char['allianceid'] != $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $match = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'blue':
							//                            if ($cond[3] == 'is' && (isset($this->blues[$char['corpid']]) || isset($this->blues[$char['allianceid']]))) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && (!isset($this->blues[$char['corpid']]) && !isset($this->blues[$char['allianceid']]))) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $match = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'red':
							//                            if ($cond[3] == 'is' && (isset($this->reds[$char['corpid']]) || isset($this->reds[$char['allianceid']]))) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && (!isset($this->reds[$char['corpid']]) && !isset($this->reds[$char['allianceid']]))) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $match = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'error':
							//                            if ($cond[3] == 'is' && $error) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            }
							//                            if ($cond[3] == 'isnt' && !$error) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $match = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'skill':
							//                            if ($cond[3] == 'is') {
							//                                $skills = $this->skill_list($char, $tokens, $char['charid']);
							//                                if (strstr($cond[1], '%')) {
							//                                    $cond[1] = str_replace('%', '(.+)', $cond[1]);
							//                                    foreach ($skills as $skill => $level) {
							//                                        if (preg_match("/" . $cond[1] . "/i", $skill) && $level >= $cond[2]) {
							//                                            if ($andor == 'OR')
							//                                                Break 3;
							//                                            Break 2;
							//                                        }
							//                                    }
							//                                }
							//                                if (isset($skills[strtolower($cond[1])]) && $skills[strtolower($cond[1])] >= $cond[2]) {
							//                                    if ($andor == 'OR')
							//                                        Break 2;
							//                                    Break;
							//                                } else {
							//                                    $match = FALSE;
							//                                    Break 2;
							//                                }
							//                            } elseif ($cond[3] == 'isnt') {
							//                                $skills = $this->skill_list($char, $tokens, $char['charid']);
							//                                if (strstr($cond[1], '%')) {
							//                                    $cond[1] = str_replace('%', '(.+)', $cond[1]);
							//                                    if (!empty($skills)) {
							//                                        foreach ($skills as $skill => $level) {
							//                                            if (preg_match("/" . $cond[1] . "/i", $skill) && $level >= $cond[2]) {
							//                                                $skillmatch = TRUE;
							//                                            }
							//                                        }
							//                                    }
							//                                    if (!$skillmatch) {
							//                                        if ($andor == 'OR')
							//                                            Break 3;
							//                                        Break 2;
							//                                    }
							//                                }
							//                                if (!(isset($skills[strtolower($cond[1])]) && $skills[strtolower($cond[1])] >= $cond[2])) {
							//                                    if ($andor == 'OR')
							//                                        Break 2;
							//                                    Break;
							//                                } else {
							//                                    $match = FALSE;
							//                                    Break 2;
							//                                }
							//                            }
							//                        case 'role':
							//                            $roles = $this->roles($char, $tokens, $char['charid']);
							//                            if ($cond[3] == 'is' && isset($roles['role' . strtolower($cond[1])])) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && !isset($roles['role' . strtolower($cond[1])])) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $match = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'title':
							//                            $titles = $this->titles($char, $tokens, $char['charid']);
							//                            if ($cond[3] == 'is' && isset($titles[strtolower($cond[1])])) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && !isset($titles[strtolower($cond[1])])) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $match = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'militia':
							//                            $militia = $this->militia($char, $tokens, $char['charid']);
							//                            if ($cond[3] == 'is' && $militia == $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && $militia != $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $match = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'valid':
							//                            if ($cond[3] == 'is') {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $match = FALSE;
							//                                Break 2;
							//                            }
							//                        Default:
							//                            $match = FALSE;
							//                            Break 2;
							//                    }
							//                }
							//                if ($match) {
							//                    $this->matchedchar = $char;
							//                    $this->query("UPDATE {db_prefix}members SET ID_GROUP = {int:idg} WHERE ID_MEMBER = {int:id}",
							//                        array('idg' => $rule[1], 'id' => $smf_member_id));
							//                    if (!$error)
							//                        $this->query("UPDATE {db_prefix}lea_tokens SET status = 'red', status_change = {int:time} WHERE ID_MEMBER = {int:id} AND status = 'OK'",
							//                            array('time' => time(), 'id' => $smf_member_id));
							//                    $matched[0] = $rule[0];
							//                    $character['main'] = $rule[0];
							//                    $mainmatch = TRUE;
							//                    Break 2;
							//                }
							//            }
							//        }
							//    }
							//}
							//// get additional
							//$rules = $this->smcFunc['db_query']('', "SELECT ruleid, `group`, andor FROM {db_prefix}lea_rules WHERE main = 0 AND enabled = 1 ORDER BY ruleid");
							//$rules = $this->db_select($rules);
							//if (!empty($rules)) {
							//    foreach ($rules as $rule) {
							//        //if(isset($agroups[$rule[1]])) // group already assigned no point checking
							//        //	Break;
							//        $andor = $rule[2];
							//        foreach ($chars as $char) {
							//            $conditions = $this->smcFunc['db_query']('', "SELECT type, value, extra, isisnt FROM {db_prefix}lea_conditions WHERE ruleid = {int:ruleid}", array('ruleid' => $rule[0]));
							//            $conditions = $this->db_select($conditions);
							//            if (!empty($conditions)) {
							//                $amatch = TRUE;
							//                foreach ($conditions as $cond) {
							//                    //	$this -> chars[] = $char;
							//                    Switch ($cond[0]) {
							//                        case 'corp':
							//                            if ($cond[3] == 'is' && $char['corpid'] == $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && $char['corpid'] != $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $amatch = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'alliance':
							//                            if ($cond[3] == 'is' && $char['allianceid'] == $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && $char['allianceid'] != $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $amatch = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'blue':
							//                            if ($cond[3] == 'is' && (isset($this->blues[$char['corpid']]) || isset($this->blues[$char['allianceid']]))) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && (!isset($this->blues[$char['corpid']]) && !isset($this->blues[$char['allianceid']]))) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $amatch = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'red':
							//                            if ($cond[3] == 'is' && (isset($this->reds[$char['corpid']]) || isset($this->reds[$char['allianceid']]))) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && (!isset($this->reds[$char['corpid']]) && !isset($this->reds[$char['allianceid']]))) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $amatch = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'error':
							//                            if ($cond[3] == 'is' && $error) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            }
							//                            if ($cond[3] == 'isnt' && !$error) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $amatch = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'skill':
							//                            //	echo "<pre>"; var_dump($cond);die;
							//                            if ($cond[3] == 'is') {
							//                                $skills = $this->skill_list($char, $tokens, $char['charid']);
							//                                if (strstr($cond[1], '%')) {
							//                                    $cond[1] = str_replace('%', '(.+)', $cond[1]);
							//                                    if (!empty($skills)) {
							//                                        foreach ($skills as $skill => $level) {
							//                                            if (preg_match("/" . $cond[1] . "/i", $skill) && $level >= $cond[2]) {
							//                                                if ($andor == 'OR')
							//                                                    Break 3;
							//                                                Break 2;
							//                                            }
							//                                        }
							//                                    }
							//                                }
							//                                if (isset($skills[strtolower($cond[1])]) && $skills[strtolower($cond[1])] >= $cond[2]) {
							//                                    if ($andor == 'OR')
							//                                        Break 2;
							//                                    Break;
							//                                } else {
							//                                    $amatch = FALSE;
							//                                    Break 2;
							//                                }
							//                            } elseif ($cond[3] == 'isnt') {
							//                                $skills = $this->skill_list($char, $tokens, $char['charid']);
							//                                if (strstr($cond[1], '%')) {
							//                                    $cond[1] = str_replace('%', '(.+)', $cond[1]);
							//                                    foreach ($skills as $skill => $level) {
							//                                        if (preg_match("/" . $cond[1] . "/i", $skill) && $level >= $cond[2]) {
							//                                            $skillmatch = TRUE;
							//                                        }
							//                                    }
							//                                    if (!$skillmatch) {
							//                                        if ($andor == 'OR')
							//                                            Break 3;
							//                                        Break 2;
							//                                    }
							//                                }
							//                                if (!(isset($skills[strtolower($cond[1])]) && $skills[strtolower($cond[1])] >= $cond[2])) {
							//                                    if ($andor == 'OR')
							//                                        Break 2;
							//                                    Break;
							//                                } else {
							//                                    $amatch = FALSE;
							//                                    Break 2;
							//                                }
							//                            }
							//                        case 'role':
							//                            $roles = $this->roles($char, $tokens, $char['charid']);
							//                            if ($cond[3] == 'is' && isset($roles['role' . strtolower($cond[1])])) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && !isset($roles['role' . strtolower($cond[1])])) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $amatch = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'title':
							//                            $titles = $this->titles($char, $tokens, $char['charid']);
							//                            if ($cond[3] == 'is' && isset($titles[strtolower($cond[1])])) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && !isset($titles[strtolower($cond[1])])) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $amatch = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'militia':
							//                            $militia = $this->militia($char, $tokens, $char['charid']);
							//                            if ($cond[3] == 'is' && $militia == $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } elseif ($cond[3] == 'isnt' && $militia != $cond[1]) {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $amatch = FALSE;
							//                                Break 2;
							//                            }
							//                        case 'valid':
							//                            if ($cond[3] == 'is') {
							//                                if ($andor == 'OR')
							//                                    Break 2;
							//                                Break;
							//                            } else {
							//                                $amatch = FALSE;
							//                                Break 2;
							//                            }
							//                        Default:
							//                            $amatch = FALSE;
							//                            Break 2;
							//                    }
							//                }
							//                if ($amatch) {
							//                    $agroups[$rule[1]] = $rule[1];
							//                    $matched[1][] = $rule[0];
							//                    Break;
							//                }
							//            }
							//        }
							//    }
							//}
							//$character['additional'] = $matched[1];
							//$matched[1] = implode(',', $matched[1]);
							//$matched = implode(';', $matched);
							//if (!$error)
							//    $this->query("UPDATE {db_prefix}lea_tokens SET status = 'checked', matched = '" . $matched . "', status_change = " . time() . " WHERE ID_MEMBER = " . $smf_member_id . " AND character_hash = " . $char);
							//else
							//    $this->query("UPDATE {db_prefix}lea_tokens SET matched = '" . $matched . "', status_change = " . time() . " WHERE ID_MEMBER = " . $smf_member_id . " AND character_hash = " . $char);
							// TODO
						}
					}
					
					// doesnt match any rule, remove group
					//if (!$mainmatch && !$ignore) {// TODO
					//    $this->query("UPDATE {db_prefix}members SET ID_GROUP = 0 WHERE ID_MEMBER = {int:id}", array('id' => $smf_member_id));
					//    if (!$error) {
					//        $this->query("UPDATE {db_prefix}lea_tokens SET status = 'nomatch', status_change = {int:time} WHERE ID_MEMBER = {int:id} AND status = 'OK'", array('time' => time(), 'id' => $smf_member_id));
					//    }
					//    $character['main'] = $txt['lea_nomatch'];
					//}
				} else {// TODO
					// no api on account, if monitored group change to unknown group
					//if (!$ignore) {
					//    if ($this->modSettings["lea_groupass_unknown"])
					//        $group = $this->modSettings["lea_groupass_unknown"];
					//    else
					//        $group = 0;
					//    $this->query("UPDATE {db_prefix}members SET ID_GROUP = {int:group} WHERE ID_MEMBER = {int:id}", array('id' => $smf_member_id, 'group' => $group));
					//    $character['main'] = $txt['lea_noapi'];
					//}
				}
				$agroups = implode(',', $agroups);
				// change additional groups
				$this->query("UPDATE {db_prefix}members SET additional_groups = '" . $agroups . "' WHERE ID_MEMBER = {int:id}", array('id' => $smf_member_id));
				return $character;
			}
		}
		
		/**
		 * @param int $memberId SMF user id
		 * @param boolean $main get only main character
		 * @return array list of characters
		 */
		function getMemberCharacters($memberId, $main = false) {
			if ($main === true) {
				$characters = $this->smcFunc['db_query']('', "SELECT id_member, character_id, is_main FROM {db_prefix}lea_member_characters WHERE id_member='{int:id_member}' AND is_main={int:main}",
					array('id_member' => $memberId, 'main' => '1'));
			} else {
				$characters = $this->smcFunc['db_query']('', "SELECT id_member, character_id, is_main FROM {db_prefix}lea_member_characters WHERE id_member='{int:id_member}'",
					array('id_member' => $memberId));
			}
			$characters = $this->db_fetch_all($characters);
			
			return $characters;
		}
		
		function get_character_info($userid, $tokens) { // TODO
			//$charlist = NULL;
			//$chars = $this->get_api_characters($userid, $tokens);
			//if (!empty($chars)) {
			//    $charlist = array();
			//    foreach ($chars as $char) {
			//        $charlist[] = $char;
			//        $this->chars[$char['name']] = $char;
			//        $this->query("
			//        REPLACE INTO {db_prefix}lea_characters
			//            (userid, charid, name, corpid, corp, corp_ticker, allianceid, alliance, alliance_ticker)
			//        VALUES
			//        ('" . $this->real_escape_string($userid) . "', '"
			//            . $this->real_escape_string($char['charid']) . "', '"
			//            . $this->real_escape_string($char['name']) . "', '"
			//            . $this->real_escape_string($char['corpid']) . "', '"
			//            . $this->real_escape_string($char['corpname']) . "', '"
			//            . $this->real_escape_string($char['ticker']) . "', '"
			//            . $char['allianceid'] . "', '"
			//            . $this->real_escape_string($char['alliance']) . "', '"
			//            . $this->real_escape_string($char['aticker']) . "')");
			//    }
			//}
			//Return $charlist;
		}
		
		function get_char_list($id = FALSE, $format = FALSE) {
			$ID_MEMBER = $this->user_info['id'];
			// Did we get the user by name...
			if (isset($_REQUEST['user']))
				$memberResult = loadMemberData($_REQUEST['user'], true, 'profile');
			// ... or by ID_MEMBER?
            elseif (!empty($_REQUEST['u']))
				$memberResult = loadMemberData((int)$_REQUEST['u'], false, 'profile');
			// If it was just ?action=profile, edit your own profile.
			else
				$memberResult = loadMemberData($ID_MEMBER, false, 'profile');
			$memID = $memberResult[0];
			
			$user = $this->smcFunc['db_query']('', "SELECT character_hash FROM {db_prefix}lea_tokens WHERE id_member = {int:id}", array('id' => $memID));
			$user = $this->db_select($user);
			if (!empty($user)) {
				foreach ($user as $acc) {
					$chars = $this->get_acc_chars($acc[0]);
					if (!empty($chars)) {
						foreach ($chars as $cid => $char) {
							if ($format) {
								//	$ticker = $this -> corp_info($corp);
								if (!empty($char[1]))
									$char[0] = $this->format_name($memID, $char[0]);
							}
							
							if ($id)
								$charlist[$cid] = $char[0];
							else
								$charlist[$char[0]] = $char[0];
						}
					}
				}
			}
			Return $charlist;
		}
		
		function getAllCharactersForMember($memberId = FALSE) {
			if (!$memberId) {
				$ID_MEMBER = $this->user_info['id'];
				// Did we get the user by name...
				if (isset($_REQUEST['user']))
					$memberResult = loadMemberData($_REQUEST['user'], true, 'profile');
				// ... or by ID_MEMBER?
                elseif (!empty($_REQUEST['u']))
					$memberResult = loadMemberData((int)$_REQUEST['u'], false, 'profile');
				// If it was just ?action=profile, edit your own profile.
				else
					$memberResult = loadMemberData($ID_MEMBER, false, 'profile');
				$memberId = $memberResult[0];
			}
			$user = $this->smcFunc['db_query']('', "SELECT character_hash FROM {db_prefix}lea_tokens WHERE id_member = {int:id}", array('id' => $memberId));
			$user = $this->db_select($user);
			if (!empty($user)) {
				$all = array();
				foreach ($user as $acc) {
					$chars = $this->get_acc_chars($acc[0]);
					foreach ($chars as $i => $c)
						$all[$i] = $c;
				}
			}
			return $all;
		}
		
		function get_acc_chars($userid) {
			$charlist = NULL;
			$chars = $this->smcFunc['db_query']('', "SELECT charid, name, corp_ticker, corp, alliance, alliance_ticker FROM {db_prefix}lea_characters WHERE userid = {int:id}", array('id' => $userid));
			$chars = $this->db_select($chars);
			if (!empty($chars)) {
				foreach ($chars as $char) {
					$charlist[$char[0]] = array($char[1], $char[2], $char[3], $char[4], $char[5]);
				}
			}
			Return $charlist;
		}
		
		function skill_list($id, $api, $charid) {
			$skills = NULL;
			require_once($this->sourcedir . '/LEA_SkillDump.php');
			$skilllist = getSkillArray();
			$post = array('keyID' => $id, 'vCode' => $api, 'characterID' => $charid);
			$xml = $this->get_xml('charsheet', $post);
			$xml = new SimpleXMLElement($xml);
			if (!empty($xml->result->rowset[0])) {
				foreach ($xml->result->rowset[0] as $skill) {
					//echo "<pre>";var_dump($skill["typeID"]); echo '<hr>';
					$skills[strtolower($skilllist[(string)$skill["typeID"]])] = (string)$skill["level"];
				}
			}
			return $skills;
		}
		
		function roles($id, $api, $charid) {
			$roles = NULL;
			$post = array('keyID' => $id, 'vCode' => $api, 'characterID' => $charid);
			$xml = $this->get_xml('charsheet', $post);
			//	$xml = file_get_contents('me.xml');
			$xml = new SimpleXMLElement($xml);
			$rg = array(2, 3, 4, 5);
			foreach ($rg as $i) {
				if (!empty($xml->result->rowset[$i])) {
					foreach ($xml->result->rowset[$i] as $role) {
						$roles[strtolower((string)$role["roleName"])] = TRUE;
					}
				}
			}
			return $roles;
		}
		
		function titles($id, $api, $charid) {
			$post = array('userID' => $id, 'apiKey' => $api, 'characterID' => $charid);
			$xml = $this->get_xml('charsheet', $post);
			//	$xml = file_get_contents('me.xml');
			$xml = new SimpleXMLElement($xml);
			if (!empty($xml->result->rowset[6])) {
				foreach ($xml->result->rowset[6] as $title) {
					$titles[strtolower((string)$title["titleName"])] = TRUE;
				}
			}
			return $titles;
		}
		
		function militia($id, $api, $charid) {
			$post = array('userID' => $id, 'apiKey' => $api, 'characterID' => $charid);
			$xml = $this->get_xml('facwar', $post);
			$xml = new SimpleXMLElement($xml);
			$faction = $xml->result->factionName;
			return $faction;
		}
		
		function updateAllCharacters($force = FALSE) {
			//if($apiecho)
			//	echo "checking all...\n<br>";
			$next = $this->settings['lea_nextpull'];
			if ($next > time() && $force === FALSE)
				Return;
			$time = time() - 3600;
			$this->smcFunc['db_query']('', "DELETE FROM {db_prefix}lea_cache WHERE time < " . $time);
			if ($force !== FALSE && $force !== NULL)
				$lastid = $force;
			else
				$lastid = $this->settings['lea_lastpull'];
			$limit = time() + 25;
			$users = $this->smcFunc['db_query']('', "SELECT id_member, member_name, ID_GROUP FROM {db_prefix}members WHERE id_member > $lastid Order by id_member");
			$users = $this->db_select($users);
			if (!empty($users)) {
				$this->log .= '<table border=1><tr><td><b>Name</b></td><td><b>Main Group</b></td><td><b>Additional Groups</b></td></tr>';
				foreach ($users as $user) {
					$this->log .= '<tr><td>' . $user[1] . '</td>';
					$cr = $this->updateSingleCharacter($user[0]);
					if (is_array($cr['additional'])) {
						foreach ($cr['additional'] as &$c) {
							if (is_numeric($c))
								$c = $this->get_rule_name($c);
						}
						$cr['additional'] = implode(', ', $cr['additional']);
					}
					if (is_numeric($cr['main']))
						$cr['main'] = $this->get_rule_name($cr['main']);
					$this->log .= '<td>' . $cr['main'] . '</td><td>' . $cr['additional'] . '</td></tr>';
					if (time() > $limit) {
						$blastid = $user[0];
						Break;
					}
				}
				$this->log .= '</table>';
			}
			
			if (!empty($blastid)) // maxed user pull record last id ready for next
			{
				$next = time() + 45;
				$this->lastid = $blastid;
			} else {
				if (!empty($users))
					$this->lastid = $users[count($users) - 1][0];
				else
					$this->lastid = $lastid;
				$lastid = 0;
				$next = time() + 3600;
			}
			$this->smcFunc['db_query']('', "
		  REPLACE INTO {db_prefix}settings
			 (variable, value)
		  VALUES
			  ('lea_lastpull', $lastid)");
			$this->smcFunc['db_query']('', "
		  REPLACE INTO {db_prefix}settings
			 (variable, value)
		  VALUES
			  ('lea_nextpull', $lastid)");
			//	$fp = fopen("api.log", 'a');
			//	fwrite($fp, $this -> file);
			//	fclose($fp);
		}
		
		function get_rule_name($id) {
			//$id = (int)$id;
			$name = $this->smcFunc['db_query']('', "SELECT name FROM {db_prefix}lea_rules WHERE ruleid = {int:id}", array('id' => $id));
			$name = $this->db_select($name);
			if (!empty($name))
				Return $name[0][0];
		}
		
		function get_cache($url, $post) {
			$time = time() - 3600;
			$db = $this->smcFunc['db_query']('', "SELECT xml FROM {db_prefix}lea_cache WHERE address = '" . $this->real_escape_string($url) . "' AND post = '" . $this->real_escape_string($post) . "' AND time > " . $time);
			$db = $this->db_select($db);
			if (!empty($db))
				return $db[0][0];
			else
				Return FALSE;
		}
		
		function set_cache($url, $post, $xml) {
			$this->query("
			REPLACE INTO {db_prefix}lea_cache
				(address, post, time, xml)
			VALUES
				('$url', '" . $this->real_escape_string($post) . "', " . time() . ", '" . $this->real_escape_string($xml) . "')");
		}
		
		function db_select($result) {
			$data = [];
			
			if (!$result) {
				return false;
			}
			
			if (empty($result)) {
				return false;
			}
			
			while ($row = $this->smcFunc['db_fetch_row']($result)) {
				$data[] = $row;
			}
			
			$this->smcFunc['db_free_result']($result);
			return $data;
		}
		
		function db_fetch_all($result) {
			$data = [];
			
			if (!$result) {
				return false;
			}
			
			if (empty($result)) {
				return false;
			}
			
			while ($row = $this->smcFunc['db_fetch_assoc']($result)) {
				$data[] = $row;
			}
			
			$this->smcFunc['db_free_result']($result);
			return $data;
		}
		
		function selectold($sql, $params = NULL) {
			$data = "";
			//	$result = mysql_query($sql);
			$result = $this->smcFunc['db_query']('', $sql, $params);
			if (!$result) {
				return false;
			}
			
			if (empty($result)) {
				return false;
			}
			
			while ($row = $this->smcFunc['db_fetch_row']($result)) {
				$data[] = $row;
			}
			
			$this->smcFunc['db_free_result']($result);
			return $data;
		}
		
		function query($sql, $params = NULL) {
			$return = $this->smcFunc['db_query']('', $sql, $params);
			
			if (!$return) {
				echo $sql;
				echo "<BR>" . $this->smcFunc['db_error'] . "<BR>";
				return false;
			} else {
				return true;
			}
		}
		
		function xmlparse($xml, $tag) {
			$tmp = explode("<" . $tag . ">", $xml);
			if (isset($tmp[1]))
				$tmp = explode("</" . $tag . ">", $tmp[1]);
			else
				return NULL;
			return $tmp[0];
		}
		
		function rowset($xml, $tag) {
			$tmp = explode('<rowset name="' . $tag . '" key="toID" columns="toID,toName,standing">', $xml);
			if (!empty($tmp[1]))
				$tmp = explode("</rowset>", $tmp[1]);
			return $tmp[0];
		}
		
		function parse($xml) {
			$chars = NULL;
			$xml = explode("<row ", $xml);
			unset($xml[0]);
			if (!empty($xml)) {
				foreach ($xml as $char) {
					$char = explode('name="', $char, 2);
					$char = explode('" characterID="', $char[1], 2);
					$name = $char[0];
					$char = explode('" corporationName="', $char[1], 2);
					$charid = $char[0];
					$char = explode('" corporationID="', $char[1], 2);
					$corpname = $char[0];
					$char = explode('" />', $char[1], 2);
					$corpid = $char[0];
					$chars[] = array('name' => $name, 'charid' => $charid, 'corpname' => $corpname, 'corpid' => $corpid);
				}
			}
			return $chars;
		}
		
		function alliance_list($update = TRUE) { // TODO
			//$sfile = $this->sourcedir . "/../cache/eve_corplist.php";
			//if (file_exists($sfile)) {
			//    require($sfile);
			//    if (count($corps) > 5 && $time > (time() - (60 * 60 * 24))) {
			//        $this->corps = $corps;
			//        Return $time;
			//    }
			//    unset($corps);
			//}
			//if (!$update)
			//    Return;
			//$data = $this->get_xml('alliances');
			////$data = $this -> rowset2($data);
			//$data = explode("<row name=\"", $data);
			//unset($data[0]);
			//foreach ($data as $a) {
			//    $a = explode("</rowset>", $a, 2);
			//    $a = explode('" shortName="', $a[0], 2);
			//    $name = $a[0];
			//    $a = explode('" allianceID="', $a[1], 2);
			//    $tag = $a[0];
			//    $a = explode('" executorCorpID="', $a[1], 2);
			//    $id = $a[0];
			//    $a = explode('<row corporationID="', $a[1]);
			//    unset($a[0]);
			//    foreach ($a as $corp) {
			//        $corp = explode('" startDate="', $corp, 2);
			//        $corps[$corp[0]] = $id;
			//    }
			//    $this->atags[$id] = $tag;
			//}
			//if (count($corps) > 5) {
			//    $time = time();
			//    $file = '<?php' . "\n\n";
			//    $file .= '$time = ' . $time . ';' . "\n\n";
			//    foreach ($corps as $c => $a) {
			//        $file .= '$corps[' . $c . '] = ' . $a . ';' . "\n";
			//    }
			//    foreach ($this->atags as $id => $tag) {
			//        $file .= '$this -> atags[' . $id . '] = "' . $tag . '";' . "\n";
			//    }
			/*    $file .= '?>';*/
			//    $fp = fopen($sfile, 'w');
			//    fwrite($fp, $file);
			//    fclose($fp);
			//    $this->corps = $corps;
			//}
			//Return $time;
		}
		
		function rowset2($xml) {
			$tmp = explode('<rowset name="alliances" key="allianceID" columns="name,shortName,allianceID,executorCorpID,memberCount,startDate">', $xml, 2);
			return $tmp[1];
		}
		
		function Settings($scripturl) {
			$this->context[$this->context['admin_menu_name']]['tab_data'] = array(
				'title' => $this->txt['lea_lea'],
				//	'help' => 'featuresettings',
				'description' => $this->txt['lea_settings_message'],
				'tabs' => array(
					'info' => array(),
					'settings' => array(),
					'rules' => array(/* 'description' => $this -> txt['signature_settings_desc'],*/),
					'ts' => array(),
					'checks' => array(),
				),
			);
			
			if (isset($_GET['sa']) && strtolower($_GET['sa']) == "rules")
				$this->settings_rules($scripturl);
            elseif (isset($_GET['sa']) && strtolower($_GET['sa']) == "ts")
				$this->ts->settings($scripturl);
            elseif (isset($_GET['sa']) && strtolower($_GET['sa']) == "checks")
				$this->settings_checks($scripturl);
            elseif (isset($_GET['sa']) && strtolower($_GET['sa']) == "settings")
				$this->settings_settings($scripturl);
			else
				$this->settings_info($scripturl);
		}
		
		function settings_info($scripturl) {
			// TODO
			//$info = array('smfv' => $this->modSettings['smfVersion'],
			//    'leav' => $this->version,
			//    'url' => $_SERVER['HTTP_HOST']);
			//$latestv = $this->get_site('http://lea.temar.me/version.php', $info);
			//$latestv = explode("#", $latestv, 2);
			//if (version_compare($latestv[0], $this->version) > 0) {
			//    $vdown = explode('.', $latestv[0], 3);
			//    $vdown = implode('_', $vdown);
			//    $vdown = 'http://temars-eve-api.googlecode.com/files/LEA_' . $vdown . '.zip';
			//    $vdown = '<form action="' . $scripturl . '?action=admin;area=packages;get;sa=download;byurl" method="post" accept-charset="ISO-8859-1" name="Release Download">
			//<input type="hidden" name="package" value="' . $vdown . '" />
			//<input type="hidden" name="filename" value="" />
			//<input type="submit" value="Download" /></form>';
			//}
			//if (version_compare($latestv[1], $this->version) > 0) {
			//    $dvdown = explode('.', $latestv[1], 4);
			//    $fname = 'LEA-trunk.r' . $dvdown[3] . '.tar.gz';
			//    $dvdown = 'http://lea.temar.me/svn/dl.php?repname=LEA&path=%2Ftrunk%2F&isdir=1&rev=' . $dvdown[3] . '&peg=' . $dvdown[3];
			//    $dvdown = '<form action="' . $scripturl . '?action=admin;area=packages;get;sa=download;byurl;' . $this->context['session_var'] . '=' . $this->context['session_id'] . '" method="post" accept-charset="ISO-8859-1" name="Dev Download">
			//<input type="hidden" name="package" value="' . $dvdown . '" />
			//<input type="hidden" name="filename" value="' . $fname . '" />
			//<input type="submit" value="Download" /></form>';
			//}
			//$config_vars = array(
			//    '</form><dt>Your ' . $this->txt['lea_version'] . ': ' . $this->version . '</dt>',
			//    '<dt>Latest Released ' . $this->txt['lea_version'] . ': ' . $latestv[0] . $vdown . '</dt>',
			//    '<dt>Latest Dev ' . $this->txt['lea_version'] . ': ' . $latestv[1] . $dvdown . '</dt>',
			//    '<dt></dt>',
			//);
			
			$this->context['settings_save_dont_show'] = TRUE;
			
			prepareDBSettingContext($config_vars);
		}
		
		function settings_settings($scripturl) {
			$atime = $this->alliance_list(FALSE);
			if ($atime)
				$atime = gmdate("G:i D d M y", $atime) . ' (GMT)';
			else
				$atime = 'Never';
			if (isset($_GET['save'])) {
				$charid = $_POST["lea_charid"];
				$userid = $_POST["lea_userid"];
				$api = $_POST["lea_api"];
			} else {
				$charid = $this->modSettings["lea_charid"];
				$userid = $this->modSettings["lea_userid"];
				$api = $this->modSettings["lea_api"];
			}
			$chars = $this->get_character_info($userid, $api);
			
			$charlist = array();
			if (!empty($chars)) {
				foreach ($chars as $char) {
					$charlist[$char['charid']] = $char['name'];
					if ($charid == $char['charid']) {
						$corp = $char['corpid'];
						$alliance = $char['allianceid'];
					}
				}
			}
			$blues = NULL;
			$reds = NULL;
			$time = FALSE;
			$file = $this->sourcedir . "/../cache/eve_standings.php";
			if (file_exists($file))
				require($file);
			if ($time)
				$time = gmdate("G:i D d M y", $time) . ' (GMT)';
			else
				$time = 'Never';
			$groups = $this->MemberGroups();
			$options = '';
			if (!empty($charlist)) {
				foreach ($charlist as $i => $c) {
					$options .= '<option value="' . $i . '"';
					if ($this->modSettings["lea_charid"] == $i)
						$options .= ' selected="selected"';
					$options .= '>' . $c . '</option>
				';
				}
			}
			$config_vars = array(
				'</form>
			<form action="' . $scripturl . '?action=admin;area=lea;sa=settings;save" method="post" accept-charset="ISO-8859-1" name="lea_settings">',
				'<dt>' . $this->txt['lea_version'] . ': ' . $this->version . '</dt>',
				'',
				// enable?
				array('check', 'lea_enable'),
				'',
				'<dt>' . $this->txt['lea_settings_message'] . '</dt>',
				// api info
				array('int', 'lea_userid', 10),
				array('text', 'lea_api', 64),
				//	array('select', 'lea_charid', $charlist),
				'<dt>
				<a id="setting_lea_charid"></a> <span><label for="lea_charid">' . $this->txt['lea_charid'] . '</label></span>
			</dt>
			<dd>
				<div id="chars"><select name="lea_charid" id="lea_charid" >
					' . $options . '
				</select> <button type="button" onclick="javascript: getchars()">' . $this->txt['lea_getchar'] . '</button></div>
			</dd>
			<script type="text/javascript">
                //function getchars() {
                //    userid = document.lea_settings.lea_userid.value;
                //    api = document.lea_settings.lea_api.value;
                //    include("LEA_xmlhttp.php?page=settings&userid="+userid+"&api="+api);
                //}
                //
                //function include(pURL) {
                //    if (window.XMLHttpRequest) { // code for Mozilla, Safari, ** And Now IE 7 **, etc
                //        xmlhttp=new XMLHttpRequest();
                //    } else if (window.ActiveXObject) { //IE
                //        xmlhttp=new ActiveXObject(\'Microsoft.XMLHTTP\');
                //    }
                //
                //    if (typeof(xmlhttp)==\'object\') {
                //        xmlhttp.onreadystatechange=postFileReady;
                //        xmlhttp.open(\'GET\', pURL, true);
                //        xmlhttp.send(null);
                //    }
                //}
                //
                //function postFileReady() {
                //    if (xmlhttp.readyState==4) {
                //        if (xmlhttp.status==200) {
                //            document.getElementById(\'chars\').innerHTML=xmlhttp.responseText;
                //        }
                //    }
                //}
			</script>
			',
				'<dt>' . $this->txt['lea_standings_updated'] . ': ' . $time . '</dt>',
				'<dt>' . $this->txt['lea_standings_contains'] . ': ' . count($blues) . ' ' . $this->txt['lea_standings_blue'] . ', ' . count($reds) . ' ' . $this->txt['lea_standings_red'] . '</dt>',
				'<dt>' . $this->txt['lea_corpl_updated'] . ': ' . $atime . '</dt>',
				'<dt>' . $this->txt['lea_corpl_contains'] . ': ' . count($this->corps) . '</dt>',
				'',
				array('check', 'lea_regreq'),
				array('check', 'lea_usecharname'),
				array('check', 'lea_avatar_enabled'),
				array('check', 'lea_avatar_locked'),
				array('select', 'lea_avatar_size', array(32 => '32', 64 => '64', 128 => '128', 256 => '256')),
				//	array('int', 'lea_corpid', 10),
				//	array('int', 'lea_allianceid', 10),
				//	array('check', 'lea_useapiabove'),
				array('check', 'lea_custom_name'),
				array('text', 'lea_nf', 15),
				array('check', 'lea_custom_title'),
				array('text', 'lea_tf', 15),
				'',
				'<dt>' . $this->txt['lea_group_settings'] . '</dt>',
				//	array('select', 'lea_groupass_red', $groups),
				//	array('select', 'lea_groupass_corp', $groups),
				//	array('select', 'lea_groupass_alliance', $groups),
				//	array('select', 'lea_groupass_blue', $groups),
				//	array('select', 'lea_groupass_neut', $groups),
				array('select', 'lea_groupass_unknown', $groups),
				'',
				array('text', 'lea_api_server', 40),
				// Who's online.
				//		array('check', 'who_enabled'),
			);
			
			// Saving?
			if (isset($_GET['save'])) {
				//	if(isset($_POST['lea_useapiabove']))
				//	{
				//		$_POST['lea_corpid'] = $corp;
				//		$_POST['lea_allianceid'] = $alliance;
				//		unset($_POST['lea_useapiabove']);
				//	}
				$config_vars[] = array('select', 'lea_charid', $charlist);
				saveDBSettings($config_vars);
				redirectexit('action=admin;area=lea;sa=settings');
				
				loadUserSettings();
				writeLog();
			}
			
			$this->context['post_url'] = $scripturl . '?action=admin;area=lea;save';
			//	$context['settings_title'] = $txt['lea_lea'];
			//	$context['settings_message'] = $txt['lea_settings_message'];
			
			prepareDBSettingContext($config_vars);
		}
		
		function settings_rules($scripturl) {
			$types['corp'] = $this->txt['lea_corp'];
			$types['alliance'] = $this->txt['lea_alliance'];
			$types['blue'] = $this->txt['lea_blue'];
			$types['red'] = $this->txt['lea_red'];
			$types['neut'] = $this->txt['lea_neut'];
			$types['error'] = $this->txt['lea_error'];
			$types['valid'] = $this->txt['lea_valid'];
			$types['skill'] = $this->txt['lea_skill'];
			$types['role'] = $this->txt['lea_role'];
			$types['title'] = $this->txt['lea_title'];
			$types['militia'] = $this->txt['lea_militia'];
			$groups = $this->MemberGroups();
			if (!empty($_POST)) {
				//	echo '<pre>'; var_dump($_POST);die;
				if (isset($_POST['mong'])) {
					foreach ($_POST as $g => $v) {
						$g = explode("_", $g, 2);
						if ($g[0] == "main")
							$gs[$g[1]][0] = 1;
                        elseif ($g[0] == "adit")
							$gs[$g[1]][1] = 1;
					}
					$this->query("UPDATE {db_prefix}lea_groups SET main = 0, additional = 0");
					foreach ($gs as $g => $v) {
						if ($v[0] != 1)
							$v[0] = 0;
						if ($v[1] != 1)
							$v[1] = 0;
						$this->query("UPDATE {db_prefix}lea_groups SET main = {int:main}, additional = {int:adit} WHERE id = {int:id}", array('id' => $g, 'main' => $v[0], 'adit' => $v[1]));
					}
				} elseif (isset($_POST['enr'])) {
					$this->query("UPDATE {db_prefix}lea_rules SET enabled = 0");
					foreach ($_POST as $rule => $v) {
						$rule = explode("_", $rule);
						if (!empty($rule[1]) && is_numeric($rule[1]) && $v == 1) {
							$this->query("UPDATE {db_prefix}lea_rules SET enabled = 1 WHERE ruleid = " . $rule[1]);
						}
					}
				} elseif (isset($_POST['minitype'])) {
					if ($_POST['minitype'] == 'delrule') {
						if (!is_numeric($_POST['value']))
							die("delete value must be number");
						$this->query("DELETE FROM {db_prefix}lea_rules WHERE ruleid = " . $_POST['value']);
						$this->query("DELETE FROM {db_prefix}lea_conditions WHERE ruleid = " . $_POST['value']);
					} elseif ($_POST['minitype'] == 'up' || $_POST['minitype'] == 'down') {
						$id = $_POST['value'];
						if (!is_numeric($id))
							die("move id must be number");
						$rules = $this->smcFunc['db_query']('', "SELECT ruleid, main FROM {db_prefix}lea_rules ORDER BY ruleid");
						$rules = $this->db_select($rules);
						if (!empty($rules)) {
							foreach ($rules as $rule) {
								$rl[$rule[1]][$rule[0]] = $rule[0];
								if ($rule[0] == $id)
									$main = $rule[1];
							}
							if (isset($main)) {
								$rules = $rl[$main];
								sort($rules);
								foreach ($rules as $i => $rule) {
									if ($rule == $id) {
										if ($_POST['minitype'] == 'up')
											$move = $rules[$i - 1];
                                        elseif ($_POST['minitype'] == 'down')
											$move = $rules[$i + 1];
										$this->query("UPDATE {db_prefix}lea_rules SET ruleid = -1 WHERE ruleid = " . $move);
										$this->query("UPDATE {db_prefix}lea_conditions SET ruleid = -1 WHERE ruleid = " . $move);
										$this->query("UPDATE {db_prefix}lea_rules SET ruleid = $move WHERE ruleid = " . $id);
										$this->query("UPDATE {db_prefix}lea_conditions SET ruleid = $move WHERE ruleid = " . $id);
										$this->query("UPDATE {db_prefix}lea_rules SET ruleid = $id WHERE ruleid = -1");
										$this->query("UPDATE {db_prefix}lea_conditions SET ruleid = $id WHERE ruleid = -1");
										Break;
									}
								}
							}
						}
					} else {
						die("Unknown mini form type");
					}
				} elseif ($_POST["submit"] == "EDIT") {
					if (is_numeric($_POST['id'])) {
						$id = $_POST['id'];
						$exists = TRUE;
					} else
						die("error id");
					
					$andor = $_POST['andor'];
					if ($andor != "AND" && $andor != "OR")
						die("andor must be AND or OR");
					
					$name = $this->real_escape_string($_POST['name']);
					
					if ($_POST['main'] == "main")
						$main = 1;
					else
						$main = 0;
					
					if (isset($groups[$_POST['group']]))
						$group = $_POST['group'];
                    elseif (!$exists)
						die("Invalid Group");
					
					$this->query("UPDATE {db_prefix}lea_rules SET name = '$name', main = $main, `group` = $group, andor = '$andor' WHERE ruleid = $id");
				} elseif ($_POST["submit"] == "ADD") {
					if ($_POST['id'] == "new") {
						$id = $this->smcFunc['db_query']('', "SELECT ruleid FROM {db_prefix}lea_rules ORDER BY ruleid DESC LIMIT 1");
						$id = $this->db_select($id);
						if (!empty($id))
							$id = $id[0][0] + 1;
						else
							$id = 1;
						$ids[] = $id;
					} elseif (is_numeric($_POST['id'])) {
						$id = $_POST['id'];
						$exists = TRUE;
					} else
						die("error id");
					
					$andor = $_POST['andor'];
					//if($andor != "AND" && $andor != "OR")
					//	die("andor must be AND or OR");
					
					$name = $this->real_escape_string($_POST['name']);
					
					if ($_POST['main'] == "main")
						$main = 1;
					else
						$main = 0;
					
					if (isset($types[$_POST['type']]))
						$type = $_POST['type'];
					else
						die("Unknown Type");
					
					if ($_POST['isisnt'] == 'isnt')
						$isisnt = 'isnt';
					else
						$isisnt = 'is';
					
					if ($type == "corp" || $type == "alliance") {
						$value = $_POST['value'];
						if (!is_numeric($value)) {
							$post = array('names' => $value);
							$xml = $this->get_xml('find', $post);
							$xml = new SimpleXMLElement($xml);
							$xml = (int)$xml->result->rowset->row[0]['characterID'];
							if ($type == "corp") {
								$check = $this->corp_info($xml);
								if (!empty($check)) {
									$value = $xml;
									$extra = $check['corpname'];
								} else {
									die($this->txt['lea_cantfindcorp'] . $value);
								}
							} else {
								$this->alliance_list();
								$alliances = $this->corps;
								$alliances = array_flip($alliances);
								if (isset($alliances[$xml])) {
									$extra = $value;
									$value = $xml;
								} else {
									die($this->txt['lea_cantfindalliance'] . $value);
								}
							}
						} else {
							if ($type == "corp") {
								$check = $this->corp_info($value);
								if (!empty($check)) {
									$extra = $check['corpname'];
								} else {
									echo "Warning: Unable to find Corp with id: " . $value;
								}
							} else {
								$this->alliance_list();
								$alliances = $this->corps;
								$alliances = array_flip($alliances);
								if (isset($alliances[$value])) {
									$post = array('ids' => $value);
									$xml = $this->get_xml('name', $post);
									$xml = new SimpleXMLElement($xml);
									$xml = (string)$xml->result->rowset->row[0]['name'];
									$extra = $xml;
								} else {
									echo "Warning: Unable to find Alliance with id: " . $value;
								}
							}
						}
						$value = $this->real_escape_string($value);
						$extra = $this->real_escape_string($extra);
					} elseif ($type == "skill" || $type == "role" || $type == "title" || $type == "militia")
						$value = $this->real_escape_string($_POST['value']);

                    elseif ($type == "skill")
						$extra = (int)$_POST['extra'];
					
					if (isset($groups[$_POST['group']]))
						$group = $_POST['group'];
                    elseif (!$exists)
						die("Invalid Group");
					
					if (!$exists)
						$this->query("INSERT INTO {db_prefix}lea_rules (ruleid, name, main, `group`, andor) VALUES ($id, '$name', $main, $group, '$andor')");
					$this->query("INSERT INTO {db_prefix}lea_conditions (ruleid, isisnt, type, value, extra) VALUES ($id, '$isisnt', '$type', '$value', '$extra')");
				}
			}
			$cg = $this->getGroups();
			$agroups = $this->MemberGroups(TRUE);
			$out[0] = $this->txt['lea_groupmon'] . '<form name="groups" method="post" action="">
		<table><tr><td>Name</td><td>Main</td><td>Additional</td></tr>
		';
			foreach ($agroups as $id => $g) {
				$mcheck = '';
				$acheck = '';
				if (isset($cg[$id]) && $cg[$id][0] == 1)
					$mcheck = 'checked';
				if (isset($cg[$id]) && $cg[$id][1] == 1)
					$acheck = 'checked';
				$out[0] .= '<tr><td>' . $g . '</td><td><input type="checkbox" name="main_' . $id . '" value="main" ' . $mcheck . ' /></td><td>';
				if ($id != 0)
					$out[0] .= '<input type="checkbox" name="adit_' . $id . '" value="adit" ' . $acheck . ' /></td>';
				$out[0] .= '</tr>';
			}
			$out[0] .= '</table>
			<input type="submit" name="mong" value="UPDATE">
			</form></tr></table></dt>';
			$out[1] = '';
			$out[2] = '<dt>';
			
			$idl = $this->smcFunc['db_query']('', "SELECT ruleid, name, main, `group`, andor, enabled FROM {db_prefix}lea_rules ORDER BY ruleid");
			$idl = $this->db_select($idl);
			if (!empty($idl)) {
				foreach ($idl as $id) {
					$ids[] = $id[0];
					$list[$id[0]] = array('name' => $id[1], 'main' => $id[2], 'group' => $id[3], 'andor' => $id[4], 'enabled' => $id[5], 'conditions' => array());
				}
			}
			$idl = $this->smcFunc['db_query']('', "SELECT id, ruleid, isisnt, type, value, extra FROM {db_prefix}lea_conditions ORDER BY ruleid");
			$idl = $this->db_select($idl);
			if (!empty($idl)) {
				foreach ($idl as $id) {
					$list[$id[1]]['conditions'][] = array('id' => $id[0], 'isisnt' => $id[2], 'type' => $id[3], 'value' => $id[4], 'extra' => $id[5]);
				}
			}
			//	echo '<pre>'; var_dump($list);die;
			
			$out[2] .= $this->txt['lea_rulesinfo'] . '<br><br><b><u>Main Group Rules</b></u><form name="enablerules" method="post" action="">
		<table border="1">' .
				'<tr><td>ID</td><td>Name</td><td>Rule</td><td>Group</td><td>AND / OR</td><td>Enabled</td></tr>';
			if (!empty($list)) {
				$first = TRUE;
				foreach ($list as $id => $l) {
					if ($l['main'] == 1)
						$last = $id;
				}
				$javalist = '';
				foreach ($list as $id => $l) {
					if ($l['main'] == 1) {
						$span = count($l['conditions']);
						if ($l['enabled'] == 1) {
							$enabled = 'checked';
							$color = 'lightgreen';
						} else {
							$enabled = '';
							$color = 'red';
						}
						$out[2] .= '<tr bgcolor="' . $color . '"><td rowspan="' . $span . '">' . $id . '</td><td rowspan="' . $span . '">' . $l['name'] . '</td>';
						$tr = '';
						foreach ($l['conditions'] as $r) {
							$out[2] .= $tr . '<td>' . strtoupper($r['isisnt']) . ' => ' . $types[$r['type']];
							if ($r['type'] != 'red' && $r['type'] != 'blue' && $r['type'] != 'neut' && $r['type'] != 'error' && $r['type'] != 'valid')
								$out[2] .= ': ' . $r['value'];
							if ($r['extra'] != "")
								$out[2] .= " (" . $r['extra'] . ")";
							//		if($span > 1)
							//			$out[2] .= '<a href="javascript:edit('.$id.')"><img src="'.$this -> settings['images_url'].'/icons/quick_remove.gif"></a>';
							$out[2] .= '</td>';
							if ($tr == '') {
								$out[2] .= '<td rowspan="' . $span . '">' . $groups[$l['group']] . '</td><td rowspan="' . $span . '">' . $l['andor'] . '</td><td rowspan="' . $span . '">
							<table><tr><td><input type="checkbox" name="rule_' . $id . '" value="1" ' . $enabled . ' />';
								$out[2] .= '</td><td width="20">';
								if (!$first)
									$out[2] .= '<a href="javascript:move(' . $id . ', \'up\')"><img src="' . $this->settings['images_url'] . '/sort_up.gif"></a>';
								if ($last != $id)
									$out[2] .= '<a href="javascript:move(' . $id . ', \'down\')"><img src="' . $this->settings['images_url'] . '/sort_down.gif"></a>';
								$out[2] .= '</td><td><a href="javascript:edit(' . $id . ')"><img src="' . $this->settings['images_url'] . '/icons/config_sm.gif"></a>
							<a href="javascript: delrule(\'delrule\', ' . $id . ')"><img src="' . $this->settings['images_url'] . '/icons/quick_remove.gif"></a>
							</td></tr></table>
							</td>';
							}
							$tr = '</tr><tr bgcolor="' . $color . '">';
						}
						$out[2] .= '</tr>';
						$javalist .= "rules[" . $id . "] = Array('" . str_replace("'", "\'", $l['name']) . "', 'true', '" . $l['andor'] . "', '" . str_replace("'", "\'", $l['group']) . "');\n";
						$first = FALSE;
					}
				}
			}
			$out[2] .= '</tr></table><br><b><u>Additional Group Rules</b></u><table border="1"><tr><td>ID</td><td>Name</td><td>Rule</td><td>Group</td><td>AND / OR</td><td>Enabled</td></tr>';
			if (!empty($list)) {
				foreach ($list as $id => $l) {
					if ($l['main'] == 0) {
						$span = count($l['conditions']);
						if ($l['enabled'] == 1) {
							$enabled = 'checked';
							$color = 'lightgreen';
						} else {
							$enabled = '';
							$color = 'red';
						}
						$out[2] .= '<tr bgcolor="' . $color . '"><td rowspan="' . $span . '">' . $id . '</td><td rowspan="' . $span . '">' . $l['name'] . '</td>';
						$tr = '';
						foreach ($l['conditions'] as $r) {
							$out[2] .= $tr . '<td>' . strtoupper($r['isisnt']) . ' => ' . $types[$r['type']];
							if ($r['type'] != 'red' && $r['type'] != 'blue' && $r['type'] != 'neut' && $r['type'] != 'error' && $r['type'] != 'valid')
								$out[2] .= ': ' . $r['value'];
							if ($r['extra'] != "")
								$out[2] .= " (" . $r['extra'] . ")";
							$out[2] .= '</td>';
							if ($tr == '') {
								$out[2] .= '<td rowspan="' . $span . '">' . $groups[$l['group']] . '</td><td rowspan="' . $span . '">' . $l['andor'] . '</td><td rowspan="' . $span . '">
							<table><tr><td><input type="checkbox" name="rule_' . $id . '" value="1" ' . $enabled . ' />';
								$out[2] .= '</td><td width="20">';
								if (!$first)
									$out[2] .= '<a href="javascript:move(' . $id . ', \'up\')"><img src="' . $this->settings['images_url'] . '/sort_up.gif"></a>';
								if ($last != $id)
									$out[2] .= '<a href="javascript:move(' . $id . ', \'down\')"><img src="' . $this->settings['images_url'] . '/sort_down.gif"></a>';
								$out[2] .= '</td><td><a href="javascript:edit(' . $id . ')"><img src="' . $this->settings['images_url'] . '/icons/config_sm.gif"></a>
							<a href="javascript: delrule(\'delrule\', ' . $id . ')"><img src="' . $this->settings['images_url'] . '/icons/quick_remove.gif"></a>
							</td></tr></table>
							</td>';
							}
							$tr = '</tr><tr bgcolor="' . $color . '">';
						}
						$out[2] .= '</tr>';
						$javalist .= "rules[" . $id . "] = Array('" . str_replace("'", "\'", $l['name']) . "', '', '" . $l['andor'] . "', '" . str_replace("'", "\'", $l['group']) . "');\n";
					}
				}
			}
			$out[2] .= '</tr></table><br><input type="submit" name="enr" value="UPDATE"></form>';
			$out[2] .= '<form name="miniform" method="post" action="">
		<input type="hidden" name="minitype" value="" />
		<input type="hidden" name="value" value="" />
		</form></dt>';
			$out[3] = '';
			$out[4] = '<dt><div id="formtitle">Create Rule:</div><br>
					<form name="makerule" method="post" action="">
			<table>
			<tr>
				<td width="134"><div id="lea_nametxt">Name:</div></td>
				<td><div id="lea_name"><input type="text" name="name" value="" /> For reference only</div></td>
			</tr>
			<tr>
				<td width="134">Rule ID:</td>
				<td><select name="id" onchange="javascript: value_type(false)"><option value="new">new</option>';
			foreach ($ids as $id) {
				$out[4] .= '<option value="' . $id . '">' . $id . '</option>';
			}
			
			$out[4] .= '</select></td>
			</tr>
						<tr>
				<td><div id="lea_maintxt">Main Group:</div></td>
				<td><div id="lea_main"><input type="checkbox" name="main" value="main" /></div></td>
			</tr>
			<tr>
				<td><div id="lea_linktxt">Condition link:</div></td>
				<td><div id="lea_link"><select name="andor">
						<option value="AND">AND</option>
						<option value="OR">OR</option>
					</select> should multiple conditions be treated as AND or OR</div></td>
			</tr>
			<tr>
				<td><div id="lea_isisnttxt">IS or ISNT:</div></td>
				<td><div id="lea_isisnt"><select name="isisnt">
						<option value="is">IS</option>
						<option value="isnt">ISNT</option>
					</select></div></td>
			</tr>
			<tr>
				<td><div id="lea_typetxt">Type:</div></td>
				<td><div id="lea_type"><select name="type" onchange="javascript: value_type(false)">';
			foreach ($types as $value => $name) {
				$out[4] .= '<option value="' . $value . '">' . $name . '</option>';
			}
			$out[4] .= '</select></div></td>
			</tr>

				<tr>
				<td><div id="lea_valuetxt"></div></td>
				<td><div id="lea_value"></div></td>
			</tr><tr>
				<td><div id="lea_grouptxt">Group:</div></td>
				<td><div id="lea_group"><select name="group">
				<option value="-">-</option>';
			foreach ($groups as $id => $group) {
				$out[4] .= '<option value="' . $id . '">' . $group . '</option>';
			}
			$out[4] .= '</select></div></td>
			</tr>
			<tr>
				<td width="134">&nbsp;</td>
				<td><input type="submit" name="submit" value="ADD"></td>
			</tr>
			</table>
			</form>
</dt>';
			//			TODO: language file
			$out[4] .= '
<script type="text/javascript">
var rules = new Array();
' . $javalist . '
function value_type(fromedit)
{
	type = document.makerule.type.value;
	id = document.makerule.id.value;
	name = document.makerule.name.value;
	group = document.makerule.group.value;
	main = document.makerule.main.checked;
	andor = document.makerule.andor.value;

	if(document.makerule.submit.value == "EDIT" && fromedit == false)
	{
		edit(id);
		return;
	}
	if(id == "new" || fromedit == true)
	{
		document.getElementById(\'lea_nametxt\').innerHTML="Name:";
		document.getElementById(\'lea_name\').innerHTML=\'<input type="text" name="name" value="\'+name+\'" /> For reference only\';
		document.getElementById(\'lea_maintxt\').innerHTML="Main Group:";
		document.getElementById(\'lea_main\').innerHTML=\'<input type="checkbox" name="main" value="main" />\';
		document.getElementById(\'lea_linktxt\').innerHTML="Condition link:";
		document.getElementById(\'lea_link\').innerHTML=\'<select name="andor"><option value="AND">AND</option><option value="OR">OR</option></select> should multiple conditions be treated as AND or OR\';
		document.getElementById(\'lea_grouptxt\').innerHTML="Group:";
		document.getElementById(\'lea_group\').innerHTML=\'<select name="group"><option value="-">-</option>';
			foreach ($groups as $id => $group) {
				$out[4] .= '<option value="' . $id . '">' . str_replace("'", "\'", $group) . '</option>';
			}
			$out[4] .= '</select>\';
		document.makerule.group.value = group;
		document.makerule.main.checked = main;
		document.makerule.andor.value = andor;
	}
	else
	{
		document.getElementById(\'lea_nametxt\').innerHTML="";
		document.getElementById(\'lea_name\').innerHTML="";
		document.getElementById(\'lea_maintxt\').innerHTML="";
		document.getElementById(\'lea_main\').innerHTML="";
		document.getElementById(\'lea_linktxt\').innerHTML="";
		document.getElementById(\'lea_link\').innerHTML="";
		document.getElementById(\'lea_grouptxt\').innerHTML="";
		document.getElementById(\'lea_group\').innerHTML="";
	}
	if(type == "corp")
	{
		document.getElementById(\'lea_valuetxt\').innerHTML="Corp Name or ID:";
		document.getElementById(\'lea_value\').innerHTML=\'<input type="text" name="value" value="" />\';
	}
	else if(type == "alliance")
	{
		document.getElementById(\'lea_valuetxt\').innerHTML="Alliance Name or ID:";
		document.getElementById(\'lea_value\').innerHTML=\'<input type="text" name="value" value="" />\';
	}
	else if(type == "blue" || type == "red" || type == "neut" || type == "error" || type == "valid")
	{
		document.getElementById(\'lea_valuetxt\').innerHTML="";
		document.getElementById(\'lea_value\').innerHTML="";
	}
	else if(type == "skill")
	{
		document.getElementById(\'lea_valuetxt\').innerHTML="Skill:";
		document.getElementById(\'lea_value\').innerHTML=\'<input type="text" name="value" value="" /> % wildcard Allowed<br>Level: <input type="radio" name="extra" value="1" /> 1 <input type="radio" name="extra" value="1" /> 2 <input type="radio" name="extra" value="1" /> 3 <input type="radio" name="extra" value="1" /> 4 <input type="radio" name="extra" value="1" /> 5\';
	}
	else if(type == "role")
	{
		document.getElementById(\'lea_valuetxt\').innerHTML="Role:";
		document.getElementById(\'lea_value\').innerHTML=\'<select name="value">';
			require($this->sourcedir . '/LEA_Roles.php');
			foreach ($roles as $role => $i) {
				$out[4] .= '<option value="' . $role . '">' . $role . '</option>';
			}
			$out[4] .= '</select>\';
	}
	else if(type == "title")
	{
		document.getElementById(\'lea_valuetxt\').innerHTML="Title:";
		document.getElementById(\'lea_value\').innerHTML=\'<input type="text" name="value" value="" />\';
	}
	else if(type == "militia")
	{
		document.getElementById(\'lea_valuetxt\').innerHTML="Militia:";
		document.getElementById(\'lea_value\').innerHTML=\'<select name="value"><option value="Amarr Empire">Amarr Empire</option><option value="Caldari State">Caldari State</option><option value="Gallente Federation">Gallente Federation</option><option value="Minmatar Republic">Minmatar Republic</option></select>\';
	}
}
newremoved = false;
function edit(id)
{
	document.makerule.type.value="error";
	value_type(true);
	document.makerule.submit.value="EDIT";
	document.getElementById(\'formtitle\').innerHTML="Edit Rule:";
	document.getElementById(\'lea_typetxt\').innerHTML="";
	document.getElementById(\'lea_type\').innerHTML="";
	document.getElementById(\'lea_isisnttxt\').innerHTML="";
	document.getElementById(\'lea_isisnt\').innerHTML="";
	if(!newremoved)
		document.makerule.id.remove("new");
	document.makerule.name.value=rules[id][0];
	document.makerule.id.value=id;
	document.makerule.main.checked=rules[id][1];
	document.makerule.andor.value=rules[id][2];
	document.makerule.group.value=rules[id][3];
	newremoved = true;
}
function delrule(type, value)
{
	if (confirm(rules[value][0]+"\nAre you sure you want Delete this?"))
		subform(type, value);
}
function subform(type, value)
{
	document.miniform.minitype.value=type;
	document.miniform.value.value=value;
	document.miniform.submit();
}
function move(id, value)
{
	subform(value, id);
}
value_type();
</script>
';
			$config_vars = $out;
			$this->context['post_url'] = $scripturl . '?action=admin;area=lea;sa=rules;save';
			$this->context['settings_save_dont_show'] = TRUE;
			prepareDBSettingContext($config_vars);
		}
		
		function settings_checks($scripturl) {
			if (isset($_GET['update'])) {
				if (!$this->modSettings["lea_enable"])
					$file = "API Mod is Disabled";
				if (!$_GET['lastid'] || !is_numeric($_GET['lastid']))
					$lastid = "0";
				else
					$lastid = $_GET['lastid'];
				$this->updateMemberCharacters(NULL, $lastid);
				$users1 = $this->smcFunc['db_query']('', "SELECT id_member, member_name, ID_GROUP FROM {db_prefix}members WHERE id_member <= " . $this->lastid);
				$users1 = $this->db_select($users1);
				if (empty($users1))
					$users1 = 0;
				else
					$users1 = count($users1);
				$users2 = $this->smcFunc['db_query']('', "SELECT id_member, member_name, ID_GROUP FROM {db_prefix}members WHERE id_member > " . $this->lastid);
				$users2 = $this->db_select($users2);
				if (empty($users2))
					$users2 = 0;
				else
					$users2 = count($users2);
				$echo = "<dt>Checked: $users1 / " . ($users1 + $users2) . "<br></dt>";
				if ($users2 > 0) {
					$echo .= '<dt><table><tr><td><a href="' . $scripturl . '?action=admin;area=lea;sa=checks;update;lastid=' . $this->lastid . '">Continue</a></td><td><div id="cdown"></div></td></tr></table></dt>';
					$echo .= '
				<script type="text/javascript">
					var num = 3;
					var interval = setInterval("count();" , 1000);
					function count()
					{
						document.getElementById(\'cdown\').innerHTML="("+num+")";
						if(num == 0)
						{
							clearInterval(interval);
							window.location = "' . $scripturl . '?action=admin;area=lea;sa=checks;update;lastid=' . $this->lastid . '";
						}
						num = num - 1;
					}
				</script>';
				}
				$file = str_replace("\n", "<br>", $this->log);
				$config_vars = array(
					$echo,
					'<dt>' . $file . '</dt>'
				);
			} elseif (isset($_GET['reset'])) {
				if (!$this->modSettings["lea_enable"])
					$file = "API Mod is Disabled";
				$log = $this->pref_reset();
				$config_vars = array(
					'<dt>' . $log . '</dt>'
				);
			} else {
				$config_vars = array(
					'<dt><a href="' . $scripturl . '?action=admin;area=lea;sa=checks;update">' . $this->txt['lea_fullcheck'] . '</a></dt>',
					'<dt><a href="' . $scripturl . '?action=admin;area=lea;sa=checks;reset">' . $this->txt['lea_fullnamecheck'] . '</a></dt>',
				);
			}
			
			//$context['post_url'] = $scripturl . '?action=admin;area=lea;sa=checks;save';
			//		$context['settings_title'] = $txt['lea_lea'];
			//		$context['settings_message'] = $txt['lea_settings_message'];
			//		$this -> context['post_url'] = $scripturl . '?action=admin;area=lea;sa=checks;save';
			$this->context['settings_save_dont_show'] = TRUE;
			prepareDBSettingContext($config_vars);
		}
		
		function MemberGroups($all = FALSE) {
			$list = $this->smcFunc['db_query']('', 'SELECT id_group, group_name FROM {db_prefix}membergroups WHERE min_posts = -1 ORDER BY group_name');
			$list = $this->db_select($list);
			if (!empty($list)) {
				foreach ($list as $l) {
					$groups[$l[0]] = $l[1];
				}
			}
			if (!$all) {
				unset($groups[1]);
			}
			unset($groups[3]);
			$groups[0] = "no membergroup";
			Return $groups;
		}
		
		function real_escape_string($str) {
			global $db_connection;
			return mysqli_real_escape_string($db_connection, $str);
		}
		
		function LEAAdd($memberID, $reg = FALSE) {
			if (!$this->modSettings["lea_enable"])
				Return;
			
			if (!is_numeric($memberID))
				return;
			
			if ($reg) {
				//SMF passes through this page twice, the second time generates an error because the LEA variables don't come through the post
				if (!empty($_POST['lea_user_id'])) {
					$characterHash = $_POST['lea_user_id'];
					// $apis = array($_POST['lea_user_api']);
				} else {
					$characterHash = null;
					// $apis = array();
				}
			} else {
				$characterHash = $_POST['lea_user_id'];
				// $apis = $_POST['lea_user_api'];
			}
			
			$characters = isset($_POST["lea_user_id"]) ? $_SESSION[urlencode($_POST["lea_user_id"])] : null;
			$this->saveToken($memberID, $characters["token"], $characters["character"]);
			
			// TODO
			//foreach ($characterHash as $k => $userid) {
			//    if ($userid == "")
			//        Continue;
			//    $api = $apis[$k];
			//    $duserid = NULL;
			//    $dapi = NULL;
			//    $user = $this->smcFunc['db_query']('', "SELECT character_hash, access_token, refresh_token, status, status_change FROM {db_prefix}lea_tokens WHERE id_member='" . $memberID . "' AND character_hash='" . $this->real_escape_string($userid) . "'");
			//    $user = $this->select($user);
			//    if (!empty($user)) {
			//        $duserid = $user[0][0];
			//        $dapi = $user[0][1];
			//    }
			//    if (!$userid /*|| !$api*/)
			//        Continue;
			//    if ($duserid != $userid || $dapi != $api) {
			//        $this->saveToken($memberID, $_SESSION['lea_registration']);
			//    }
			//}
			
			if (isset($_POST['del_api'])) {
				foreach ($_POST['del_api'] as $userid) {
					$this->query("DELETE FROM {db_prefix}lea_tokens WHERE id_member = $memberID AND character_hash = '" . $this->real_escape_string($userid) . "'");
				}
			}
			
			unset($_POST['del_api']);
			unset($_POST['lea_user_id']);
			unset($_POST['lea_user_api']);
			
			$this->updateMemberCharacters($memberID);
			$characters = $this->getMemberCharacters($memberID, true);
			
			if ($reg || empty($characters) || $characters[0][0] != $_POST['lea_charid']) {
				//if($modSettings['lea_usecharname'])
				
				if ($_POST['lea_charid'] == "-") {
					$characters = $this->smcFunc['db_query']('', "SELECT real_name FROM {db_prefix}members WHERE id_member = " . $memberID);
					$characters = $this->db_select($characters);
					if (!empty($characters)) {
						$realname = $characters[0][0];
						$match = FALSE;
						$characters = $this->getAllCharactersForMember($memberID);
						if (!empty($characters)) {
							foreach ($characters as $char) {
								$comp[] = $char[0];
							}
							$best = $this->best_match($realname, $comp);
							$best = $best[1];
							foreach ($characters as $i => $char) {
								if ($char[0] == $best)
									$match = $i;
							}
							if ($match) {
								$_POST['lea_charid'] = $match;
							}
						}
					}
				}
				
				if ($_POST['lea_charid'] != "-") {
					//$char = $this -> matchedchar;
					$charid = $_POST['lea_charid'];
					if (!is_numeric($charid))
						die('$_POST["lea_charid"] must be number if selected');
					$this->query("REPLACE INTO {db_prefix}lea_member_characters (id_member, character_id, is_main,character_hash) VALUES ('$memberID', '$charid', 1, '$characterHash')");
					$char = $this->smcFunc['db_query']('', "SELECT name, corpid, corp, corp_ticker, allianceid, alliance, alliance_ticker FROM {db_prefix}lea_characters WHERE charid = " . $charid);
					$char = $this->db_select($char);
					if (!empty($char)) {
						$char = $char[0];
						$name = $char[0];
						if ($this->modSettings["lea_custom_title"]) {
							$title = $this->format_name($memberID, $name, 'title');
							$this->query("UPDATE {db_prefix}members SET usertitle = '" . $title . "' WHERE ID_MEMBER = " . $memberID);
						}
						if ($this->modSettings["lea_custom_name"]) {
							$name = $this->format_name($memberID, $name);
							$this->query("UPDATE {db_prefix}members SET real_name = '" . $this->real_escape_string($name) . "' WHERE ID_MEMBER = " . $memberID);
						}
						
						if ($this->modSettings['lea_avatar_enabled']) {
							require_once("Subs-Graphics.php");
							$lea_avatar_size = !empty($this->modSettings['lea_avatar_size']) ? $this->modSettings['lea_avatar_size'] : 64;
							downloadAvatar('http://image.eveonline.com/Character/' . $charid . '_' . $lea_avatar_size . '.jpg', $memberID, $lea_avatar_size, $lea_avatar_size);
						}
					}
				}
			}
		}
		
		function format_name($memID, $char, $type = 'name') {
			$chars = $this->getAllCharactersForMember($memID);
			
			$smfgroups = $this->smf_groups($memID);
			if (!empty($chars)) {
				// $rules = $this -> smcFunc['db_query']('', "SELECT id, smf, ts, tst, nf FROM {db_prefix}lea_ts_rules");
				// $rules = $this -> lea -> select($rules);
				// if(!empty($rules))
				// {
				// foreach($rules as $r)
				// {
				// if(!empty($smfgroups))
				// {
				// foreach($smfgroups as $g)
				// {
				// if($r[1] == $g)
				// {
				// if(!isset($nf))
				// $nf = $r[4];
				// }
				// }
				// }
				// }
				// }
				foreach ($chars as $i => $ch) {
					if ($ch[0] == $char)
						$charinfo = $ch;
				}
				if (!empty($charinfo)) {
					// if($nf)
					// $name = $nf;
					// else
					if ($type == 'title')
						$name = $this->modSettings["lea_tf"];
					else
						$name = $this->modSettings["lea_nf"];
					$name = str_replace('#at#', $charinfo[4], $name);
					$name = str_replace('#ct#', $charinfo[1], $name);
					$name = str_replace('#name#', $char, $name);
				}
			}
			//	if(strlen($name) > 30)
			//	{
			//		$name = substr($name, 0, 30);
			//	}
			return $name;
		}
		
		function smf_groups($memID) {
			$groups = array();
			$dbgs = $this->smcFunc['db_query']('', "SELECT ID_MEMBER, ID_GROUP, additional_groups FROM {db_prefix}members WHERE ID_MEMBER = {int:id}", array('id' => $memID));
			$dbgs = $this->db_select($dbgs);
			if (!empty($dbgs)) {
				$groups[$dbgs[0][1]] = $dbgs[0][1];
				if (!empty($dbgs[0][2])) {
					$dbgs[0][2] = explode(',', $dbgs[0][2]);
					foreach ($dbgs[0][2] as $g)
						$groups[$g] = $g;
				}
			}
			return $groups;
		}
		
		function pref_reset() {
			$user = $this->smcFunc['db_query']('', "SELECT id_member, character_id FROM {db_prefix}lea_member_characters");
			$user = $this->db_select($user);
			if (!empty($user)) {
				foreach ($user as $u) {
					$memberID = $u[0];
					$charid = $u[1];
					$char = $this->smcFunc['db_query']('', "SELECT name, corpid, corp, corp_ticker, allianceid, alliance, alliance_ticker FROM {db_prefix}lea_characters WHERE charid = " . $charid);
					$char = $this->db_select($char);
					if (!empty($char)) {
						$char = $char[0];
						$name = $char[0];
						if ($this->modSettings["lea_custom_title"]) {
							$title = $this->format_name($memberID, $name, 'title');
							$this->query("UPDATE {db_prefix}members SET usertitle = '" . $title . "' WHERE ID_MEMBER = " . $memberID);
						}
						if ($this->modSettings["lea_custom_name"]) {
							$name = $this->format_name($memberID, $name);
							$this->query("UPDATE {db_prefix}members SET real_name = '" . $this->real_escape_string($name) . "' WHERE ID_MEMBER = " . $memberID);
						}
						
						if ($this->modSettings['lea_avatar_enabled']) {
							//	if($this -> modSettings["lea_corptag_options"] == 2)
							//	{
							//		$name = explode("] ", $name, 2);
							//		$name = $name[1];
							//	}
							//	if(isset($this -> chars[$name]['charid']))
							//	{
							require_once("Subs-Graphics.php");
							$lea_avatar_size = !empty($this->modSettings['lea_avatar_size']) ? $this->modSettings['lea_avatar_size'] : 64;
							downloadAvatar('http://image.eveonline.com/Character/' . $charid . '_' . $lea_avatar_size . '.jpg', $memberID, $lea_avatar_size, $lea_avatar_size);
							//	}
						}
					}
					$count++;
				}
			}
			return $count . " User Prefs reset";
		}
		
		function setmains() {
			$user = $this->smcFunc['db_query']('', "SELECT id_member, real_name FROM {db_prefix}members");
			$user = $this->db_select($user);
			if (!empty($user)) {
				foreach ($user as $u) {
					$match = FALSE;
					$chars = $this->getAllCharactersForMember($u[0]);
					if (!empty($chars)) {
						foreach ($chars as $char) {
							$comp[] = $char[0];
						}
						$best = $this->best_match($u[1], $comp);
						$best = $best[1];
						foreach ($chars as $i => $char) {
							if ($char[0] == $best)
								$match = $i;
						}
						if ($match) {
							$this->query("REPLACE INTO {db_prefix}lea_member_characters (id_member, character_id) VALUES (" . $u[0] . ", " . $match . ")");
							echo "User ID: " . $u[0] . " (" . $u[1] . ") Matched to Character $best ($match) <Br>";
						}
					}
					if (!$match) {
						echo "User ID: " . $u[0] . " (" . $u[1] . ") Failed<Br>";
					}
				}
			}
		}
		
		function best_match($find, $in, $perc = 0) {
			$use = array(0);
			$percentage = 0;
			
			if (!empty($in)) {
				foreach ($in as $compare) {
					similar_text($find, $compare, $percentage);
					if ($percentage >= $perc
						&& $percentage > $use[0]) {
						$use = array($percentage, $compare);
					}
				}
			}
			return $use;
		}
		
		function DisplayAPIinfo(&$context, &$modSettings, $db_prefix, &$txt) {
			if (!$this->modSettings["lea_enable"])
				Return;
			return;
			loadLanguage('LEA');
			$ID_MEMBER = $context['user']['id'];
			// Did we get the user by name...
			if (isset($_REQUEST['user']))
				$memberResult = loadMemberData($_REQUEST['user'], true, 'profile');
			// ... or by ID_MEMBER?
            elseif (!empty($_REQUEST['u']))
				$memberResult = loadMemberData((int)$_REQUEST['u'], false, 'profile');
			// If it was just ?action=profile, edit your own profile.
			else
				$memberResult = loadMemberData($ID_MEMBER, false, 'profile');
			
			if (!is_numeric($memberResult[0]))
				die("Invalid User id");
			if ($ID_MEMBER == $memberResult[0])
				$allow = AllowedTo(array('lea_view_own', 'lea_view_any'));
			else
				$allow = AllowedTo('lea_view_any');
			if ($allow) {
				$api = $this->smcFunc['db_query']('', "SELECT character_hash, api, charid, status, status_change FROM {db_prefix}lea_tokens WHERE id_member = " . $memberResult[0]);
				$api = $this->db_select($api);
				if (!empty($api)) {
					$api = $api[0];
				}
				echo '
						</tr><tr>
						<td><b>' . $this->txt['lea_userid_short'] . ': </b></td>
						<td>' . $api[0] . '</td>
						</tr><tr>
						<td><b>' . $this->txt['lea_api_short'] . ': </b></td>
						<td>' . $api[1] . '</td>';
			}
		}
		
		function EveApi($txt, $scripturl, &$context, $settings, $sc) { // old settings mod?
			if (!$this->modSettings["lea_enable"])
				Return;
			$config_vars = array(
				'',
				// enable?
				array('check', 'lea_enable'),
				'',
				// api info
				array('int', 'lea_userid', 10),
				array('text', 'lea_api', 64),
				//		array('check', 'topbottomEnable'),
				//		array('check', 'onlineEnable'),
				//		array('check', 'enableVBStyleLogin'),
				//	'',
				// Pagination stuff.
				//		array('int', 'defaultMaxMembers'),
				//	'',
				// This is like debugging sorta.
				//		array('check', 'timeLoadPageEnable'),
				//		array('check', 'disableHostnameLookup'),
				'',
				// Who's online.
				//		array('check', 'who_enabled'),
			);
			
			// Saving?
			if (isset($_GET['save'])) {
				saveDBSettings($config_vars);
				redirectexit('action=featuresettings;sa=lea');
				
				loadUserSettings();
				writeLog();
			}
			
			$context['post_url'] = $scripturl . '?action=featuresettings2;save;sa=lea';
			$context['settings_title'] = $this->txt['mods_cat_layout'];
			$context['settings_message'] = $this->txt['lea_settings_message'];
			
			//	prepareDBSettingContext($config_vars);
		}
		
		function UserModifyLEA($memID, &$leainfo) {
			//	if(!$this -> modSettings["lea_enable"])
			//		Return;
			
			//	isAllowedTo('lea_edit_any');
			if (!is_numeric($memID))
				die("Invalid User id");
			$this->memid = $memID;
			$user = $this->smcFunc['db_query']('', "SELECT character_hash, api, status, matched, error FROM {db_prefix}lea_tokens WHERE id_member = " . $memID);
			$user = $this->db_select($user);
			if (!empty($user)) {
				foreach ($user as $u) {
					$characters = $this->get_acc_chars($u[0]);
					$adits = NULL;
					$matched = explode(";", $u[3], 2);
					if (is_numeric($matched[0])) {
						$mname = $this->smcFunc['db_query']('', "SELECT name FROM {db_prefix}lea_rules WHERE ruleid = {int:id}", array('id' => $matched[0]));
						$mname = $this->db_select($mname);
						if (!empty($mname))
							$mname = $mname[0][0];
					} else
						$mname = $matched[0];
					if (!empty($matched[1]))
						$adits = explode(',', $matched[1]);
					$anames = array();
					$prefs = $this->smcFunc['db_query']('', "SELECT character_id FROM {db_prefix}lea_member_characters WHERE id_member = {int:id_member}", array('id_member' => $memID));
					$prefs = $this->db_select($prefs);
					if (!empty($prefs))
						$character_id = $prefs[0][0];
					else
						$character_id = "";
					if (!empty($adits) && $adits[0] != '') {
						foreach ($adits as $a) {
							if (is_numeric($a)) {
								$aname = $this->smcFunc['db_query']('', "SELECT name FROM {db_prefix}lea_rules WHERE ruleid = {int:id}", array('id' => $a));
								$aname = $this->db_select($aname);
								if (!empty($aname))
									$anames[] = $aname[0][0];
							}
						}
						$aname = implode(", ", $anames);
					} else {
						$aname = 'none';
					}
					$leainfo[] = array(
						"userid" => $u[0],
						"api" => $u[1],
						//	"msg" => $msg,
						'charnames' => $characters,
						'character_id' => $character_id,
						'status' => $u[2],
						'mainrule' => $mname,
						'aditrules' => $aname,
						'error' => $u[4]
					);
				}
			}
		}
		
		function registrationFields() {
			global $scripturl;
			
			if (!$this->modSettings["lea_enable"])
				return;
			
			$post['id'] = isset($_POST['lea_user_id']) ? $_POST['lea_user_id'] : '';
			$post['api'] = isset($_POST['lea_user_api']) ? $_POST['lea_user_api'] : '';
			
			$user = isset($_GET['characterHash']) ? $_SESSION[urlencode($_GET['characterHash'])] : null;
			
			if ($user) { ?>
                <input type="hidden" name="lea_user_id" value="<?= $user['character']['CharacterOwnerHash'] ?>"/>
                <input type="hidden" name="lea_charid" value="<?= $user['character']['CharacterID'] ?>"/>
                <dl class="register_form">
                    <dt><strong><label>Имя персонажа</label></strong></dt>
                    <dd><?= $user['character']['CharacterName'] ?></dd>
                    <dt><strong><label>Имя корпорации</label></strong></dt>
                    <dd><?= $user['character']['CorporationName'] ?></dd>
                </dl>
				<?php
			} else { ?>
                <dl class="register_form">
                    <dt>Войдите с помощью вашего аккаунта в EVE Online</dt>
                    <dd>
                        <a id="ssologinimage" href="<?= $scripturl . '?action=sso_callback&returnaction=register' ?>"><img
                                    src="https://web.ccpgamescdn.com/eveonlineassets/developers/eve-sso-login-black-large.png"/></a>
                    </dd>
                </dl>
                <script type="text/javascript">
                    // window.onload = () => document.querySelectorAll("#registration input").forEach((x) => x.closest('dl').style.display = 'none');
                    window.onload = () => document.querySelectorAll("#registration input").forEach((x) => x.setAttribute('disabled', 'disabled'));

                    // function getchars() {
                    //     userid = document.registration.lea_user_id.value;
                    //     api = document.registration.lea_user_api.value;
                    //     include("LEA_xmlhttp.php?userid=" + userid + "&api=" + api);
                    // }
                    //
                    // if (auto) getchars();

                    function include(pURL) {
                        if (window.XMLHttpRequest) { // code for Mozilla, Safari, ** And Now IE 7 **, etc
                            xmlhttp = new XMLHttpRequest();
                        } else if (window.ActiveXObject) { //IE
                            xmlhttp = new ActiveXObject('Microsoft.XMLHTTP');
                        }
                        if (typeof(xmlhttp) == 'object') {
                            xmlhttp.onreadystatechange = postFileReady;
                            xmlhttp.open('GET', pURL, true);
                            xmlhttp.send(null);
                        }
                    }

                    function postFileReady() {
                        if (xmlhttp.readyState == 4) {
                            if (xmlhttp.status == 200) {
                                document.getElementById('chars').innerHTML = xmlhttp.responseText;
                            }
                        }
                    }
                </script>
				<?php
			}
		}
		
		function loginFields() {
			global $scripturl;
			
			if (!$this->modSettings["lea_enable"])
				return '';
			
			$lines =
				'<h3 class="hr">или</h3>'
				. '<a id="ssologinimage" href="' . $scripturl . '?action=sso_callback&returnaction=login2" style="margin-left: 25%;">'
				. '<img style="margin-bottom:10px;" src="https://web.ccpgamescdn.com/eveonlineassets/developers/eve-sso-login-black-large.png"/>'
				. '</a>';
			
			return $lines;
		}
		
		function reg_checks() {
			if ($this->modSettings['lea_regreq']) {
				//$chars = $this->get_characters($_POST['lea_user_id'], $_POST['lea_user_api']);
				//if (empty($chars)){ // invalid api
				//    $ret = $this->txt['lea_regreq_error'];
				//    if (empty($ret))
				//        $ret = 'A Valid API is Required to Register on this Forum';
				//    Return $ret;
				//}
				//if (!isset($_SESSION['lea_registration']) || !$this->characterHashExists($_SESSION['lea_registration']['character']['CharacterOwnerHash'])) {
				//    $ret = $this->txt['lea_regreq_error'];
				//    if (empty($ret))
				//        $ret = 'A authorization is required to Register on this Forum';
				//    Return $ret;
				//}
			}
			//if (!empty($_POST['lea_user_id']) && (empty($_POST['lea_charid']) || strlen($_POST['lea_charid']) < 3)) {
			//    echo '<script>var auto = 1;</script>';
			//    $ret = $this->txt['lea_regchar_error'];
			//    if (empty($ret))
			//        $ret = 'Please Select a Character';
			//    Return $ret;
			//}
		}
		
		function characterHashExists($hash) { // TODO
			if (str_replace(' ', '+', $hash) == 'dPnzp2oEnP172TE+dyJ9lg0OiBQ=')
				return true;
			return false;
		}
		
		function avatar_option() {
			echo '
			<script type="text/javascript">
				function getPortrait(id)
				{
					var maxHeight = ', !empty($this->modSettings['avatar_max_height_external']) ? $this->modSettings['avatar_max_height_external'] : 0, ';
					var maxWidth = ', !empty($this->modSettings['avatar_max_width_external']) ? $this->modSettings['avatar_max_width_external'] : 0, ';
					var tempImage = new Image();

					tempImage.src = \'http://image.eveonline.com/Character/\'+id+\'_', !empty($this->modSettings['lea_avatar_size']) ? $this->modSettings['lea_avatar_size'] : 64, '.jpg\';
					if (maxWidth != 0 && tempImage.width > maxWidth)
					{
						document.getElementById("eavatar").style.height = parseInt((maxWidth * tempImage.height) / tempImage.width) + "px";
						document.getElementById("eavatar").style.width = maxWidth + "px";
					}
					else if (maxHeight != 0 && tempImage.height > maxHeight)
					{
						document.getElementById("eavatar").style.width = parseInt((maxHeight * tempImage.width) / tempImage.height) + "px";
						document.getElementById("eavatar").style.height = maxHeight + "px";
					}
					document.getElementById("eavatar").src = \'http://image.eveonline.com/Character/\'+id+\'_', !empty($this->modSettings['lea_avatar_size']) ? $this->modSettings['lea_avatar_size'] : 64, '.jpg\';

				}
			</script>
			<div id="avatar_lea">
			<select name="attachment" value="', !empty($this->context['member']['avatar']['lea']) ? $this->context['member']['avatar']['lea'] : '', '"  onfocus="selectRadioByName(document.forms.creator.avatar_choice, \'lea\');" onchange="getPortrait(this.value);" >';
			$chars = $this->get_char_list(TRUE);
			//	echo "\n<pre>"; var_dump($this -> context['member']['avatar']);die;
			if (!empty($chars)) {
				foreach ($chars as $id => $char) {
					echo '<option value="' . $id . '">' . $char . '</option>';
				}
			}
			echo '</select>' .
				'<br><img name="eavatar" id="eavatar" src="', !empty($this->modSettings["lea_enable"]) && $this->context['member']['avatar']['choice'] == 'lea' ? $this->context['member']['avatar']['lea'] : $this->modSettings['avatar_url'] . '/blank.gif', '" />' .
				'</div>';
		}
		
		function avatar_option_lock() {
			if ($this->modSettings["lea_avatar_locked"]) {
				$this->context['member']['avatar']["allow_upload"] = FALSE;
				$this->context['member']['avatar']["allow_external"] = FALSE;
				$this->context['member']['avatar']["allow_server_stored"] = FALSE;
			}
		}
		
		function avatar_save($memID, &$profile_vars, &$cur_profile) {
			// Remove any attached avatar...
			removeAttachments(array('id_member' => $memID));
			
			$profile_vars['avatar'] = $_POST['attachment'];
			
			if (!is_numeric($profile_vars['avatar']))
				return 'bad_avatar';
			
			require_once($this->sourcedir . '/Subs-Graphics.php');
			$lea_avatar_size = !empty($this->modSettings['lea_avatar_size']) ? $this->modSettings['lea_avatar_size'] : 64;
			if (downloadAvatar('http://image.eveonline.com/Character/' . $profile_vars['avatar'] . '_' . $lea_avatar_size . '.jpg', $memID, $lea_avatar_size, $lea_avatar_size)) {
				$profile_vars['avatar'] = '';
				$cur_profile['id_attach'] = $this->modSettings['new_avatar_data']['id'];
				$cur_profile['filename'] = $this->modSettings['new_avatar_data']['filename'];
				$cur_profile['attachment_type'] = $this->modSettings['new_avatar_data']['type'];
			}
		}
		
		private function getGroups() {
			$result = [];
			$characterGroupQuery = $this->smcFunc['db_query']('', "SELECT id, main, additional FROM {db_prefix}lea_groups ORDER BY id");
			$characterGroupQuery = $this->db_select($characterGroupQuery);
			if (!empty($characterGroupQuery)) {
				foreach ($characterGroupQuery as $cgqs)
					$result[$cgqs[0]] = array($cgqs[1], $cgqs[2]);
			}
			return $result;
		}
	}
	
	$lea = new LEA($db_prefix, $sourcedir, $modSettings, $user_info, $context, $txt, $smcFunc, $settings);
	
	require_once($sourcedir . '/LEA_TS.php');
	$lea->ts = $leats;
	$leats->lea = $lea;
	
	$forum_copyright .= '</span></li><li class="copyright"><span><a href="http://code.google.com/p/temars-eve-api/" target="_blank" class="new_win">LEA ' . $lea->version . ' &copy; 2009-2011, Temars EVE API</a>';
	
	function editlea($memID) {
		global $lea, $leainfo, $sourcedir, $context, $settings, $options, $scripturl, $modSettings, $txt, $db_prefix;
		$lea->UserModifyLEA($memID, $leainfo, $context, $settings, $options, $scripturl, $modSettings, $txt, $db_prefix);
	}
	
	function ModifyLEASettings() {
		global $lea, $sourcedir, $scripturl, $context;
		// Will need the utility functions from here.
		require_once($sourcedir . '/ManageServer.php');
		
		$context['sub_template'] = 'show_settings';
		$lea->Settings($scripturl);
	}
	
	function template_editlea() {
		global $lea, $leainfo, $sourcedir, $context, $settings, $options, $scripturl, $modSettings, $txt;
		if ($lea->memid == $context['user']['id']) {
			if (allowedTo(array('lea_edit_own', 'lea_edit_any')))
				$edit = TRUE;
		} else {
			if (allowedTo(array('lea_edit_any')))
				$edit = TRUE;
		}
		
		if (isset($_GET['sa']) && strtolower($_GET['sa']) == "ts")
			return template_edit_lea_ts();
        elseif (isset($_GET['sa']) && strtolower($_GET['sa']) == "jabber")
			return template_edit_lea_jabber();
		
		echo '
		<form action="', $scripturl, '?action=profile;area=lea;save" method="post" accept-charset="', $context['character_set'], '" name="creator" id="creator">
			<table border="0" width="100%" cellspacing="1" cellpadding="4" align="center" class="bordercolor">
				<tr class="titlebg">
					<td height="26">
						&nbsp;<img src="', $settings['images_url'], '/icons/profile_sm.gif" alt="" border="0" align="top" />&nbsp;
						', $txt['lea_lea'], '
					</td>
				</tr><tr class="windowbg">
					<td class="smalltext" height="25" style="padding: 2ex;">
						', $txt['lea_userinfo'], '
					</td>
				</tr><tr>
					<td class="windowbg2" style="padding-bottom: 2ex;">
						<table border="0" width="100%" cellpadding="3">';
		if (!$modSettings["lea_enable"]) {
			echo '<tr><td>' . $txt['lea_disabled'] . '</td></tr>';
		} else {
			foreach ($leainfo as $info) {
				foreach ($info['charnames'] as $i => $char)
					$charlist[$i] = $char[0];
			}
			echo '<tr><td>' . $txt['lea_charid'] . '</td><td>';
			if ($edit)
				echo '<select name="lea_charid" id="lea_charid" >';
			if (!empty($charlist)) {
				if (!isset($charlist[$leainfo[0]['character_id']]))
					echo '<option value="-", SELECTED>-</option>';
				foreach ($charlist as $i => $c) {
					if ($edit)
						echo '<option value="' . $i . '"', $i == $leainfo[0]['character_id'] ? 'SELECTED' : '', '>' . $c . '</option>';
				}
				if (!$edit)
					echo $charlist[$leainfo[0]['character_id']];
			} else {
				if ($edit)
					echo '<option value="-", SELECTED>-</option>';
				else
					echo '-';
			}
			if ($edit)
				echo '</select>';
			echo '</td></tr>';
			if ($edit) {
				$leainfo[] = array(
					"userid" => '',
					"api" => '',
					//	"msg" => $msg,
					'charnames' => '',
					'status' => '',
					'mainrule' => '',
					'aditrules' => '',
					'error' => ''
				);
			}
			foreach ($leainfo as $i => $info) {
				echo '<tr><td colspan="3"><hr class="hrcolor" width="100%" size="1"/></td></tr>';
				echo '<tr><td>
			<b>', $txt['lea_status'], ':</b></td><td>' . $info['status'];
				if ($info['status'] == 'API Error')
					echo ' (' . $info['error'] . ')';
				echo '</td>
				</tr><tr><td><b>', $txt['lea_mainrule'], ':</b></td><td>' . $info['mainrule'] . '</td>
				</tr><tr><td><b>', $txt['lea_aditrules'], ':</b></td><td>' . $info['aditrules'] . '</td>
				</tr><tr><td>
				<b>', $txt['lea_characters'], ':</b></td><td>';
				if (!empty($info['charnames'])) {
					echo '<style type="text/css">
					green {color:green}
					blue {color:blue}
					red {color:red}
					</style>';
					$echo = array();
					foreach ($info['charnames'] as $char) {
						$char[3] = $char[3] != '' ? ' / <blue>' . $char[3] . '</blue>' : '';
						$echo[] = '[' . $char[1] . '] ' . $char[0] . ' (<green>' . $char[2] . '</green>' . $char[3] . ')';
					}
					echo implode('<br>', $echo);
				}
				echo '</td></tr>
				<tr><td>
				<b>', $txt['lea_userid'], ':</b></td>
				<td>';
				if ($edit) {
					if ($info['userid'] == "")
						echo '<input type="text" name="lea_user_id[]" value="' . $info['userid'] . '" size="20" />';
					else {
						echo '<input type="hidden" name="lea_user_id[]" value="' . $info['userid'] . '" size="20" />';
						echo $info['userid'] . '</td><td> <input type="checkbox" name="del_api[]" value="' . $info['userid'] . '" /> Delete</td>';
					}
					echo '</td></tr>';
				} else {
					echo $info['userid'];
					echo '</td></tr>';
				}
			}
			template_profile_save();
		}
		echo '          </table>
					</td>
				</tr>
			</table>
		</form>';
	}
	
	function lea_addActions(&$actionArray) {
		$actionArray['sso_callback'] = array('LEA.php', 'sso_callback');
	}
	
	function sso_callback() {
		global $lea;
		$lea->sso_callback();
	}
