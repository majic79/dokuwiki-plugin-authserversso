<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

define('AUTH_USERFILE',DOKU_CONF.'users.auth.php');

class auth_plugin_authserversso extends DokuWiki_Auth_Plugin {
	const CONF_VAR_AUTH_ID = 'auth_var_id';
	const CONF_VAR_AUTH_EMAIL = 'auth_var_email';
	const CONF_VAR_AUTH_REALNAME = 'auth_var_realname';

	protected $users = null;

	protected $_pattern = array();
	
  protected $_pregsplit_safe = false;
	
	protected $globalConf = array();
	 
	/* Server variables ($_SERVER) */
	//protected $env = array();
    
	public function __construct() {
		parent::__construct();
		
		if(!@is_readable(AUTH_USERFILE)) {
			$this->success = false;
		} else {
			$this->cando['external'] = true;

			if(@is_writable(AUTH_USERFILE)) {
				//$this->cando['addUser'] = true;
				//$this->cando['delUser'] = true;
				//$this->cando['modLogin'] = true;
				// $this->cando['modPass'] = true;
				$this->cando['modMail'] = true;
				$this->cando['modName'] = true;
				$this->cando['modGroups'] = true;
			}
			$this->cando['logout'] = false;
			$this->cando['getUsers'] = true;
			$this->cando['getUserCount'] = true;
		}

		$this->_pregsplit_safe = version_compare(PCRE_VERSION,'6.7','>=');
		$this->loadConfig();
		$this->success = true;
	}
    
	// Required
	public function checkPass($user, $pass) {
		dbglog("authserversso: checkPass '{$user}':'{$pass}' ");
		//return ($user == $this->cleanUser($_SERVER['PHP_AUTH_USER']) && $pass == $_SERVER['PHP_AUTH_PW']);		
		return $this->trustExternal($user, $pass);
		// $userinfo = $this->getUserData($user);
		// if($userinfo === false) return false;
		
		// return auth_verifyPassword($pass, $this->users[$user]['pass']);
	}
	
	public function getUserData($user, $requireGroups=true) {
		dbglog("authserversso: getUserData {$user}");
		if($this->users === null) $this->_loadUserData();
		return isset($this->users[$user]) ? $this->users[$user] : false;
	}
	
	protected function _createUserLine($user, $pass, $name, $mail, $grps) {
		$groups   = join(',', $grps);
		$userline = array($user, $pass, $name, $mail, $groups);
		$userline = str_replace('\\', '\\\\', $userline); // escape \ as \\
		$userline = str_replace(':', '\\:', $userline); // escape : as \:
		$userline = join(':', $userline)."\n";
		return $userline;
	}	
	
	public function createUser($user, $pwd, $name, $mail, $grps = null) {
		global $conf;
		dbglog("authserversso: createUser {$user}");

		// user mustn't already exist
		if($this->getUserData($user) !== false) {
			msg($this->getLang('userexists'), -1);
			return false;
		}

		$pass = auth_cryptPassword($pwd);

		// set default group if no groups specified
		if(!is_array($grps)) $grps = array($conf['defaultgroup']);

		// prepare user line
		$userline = $this->_createUserLine($user, $pass, $name, $mail, $grps);

		if(!io_saveFile(AUTH_USERFILE, $userline, true)) {
			msg($this->getLang('writefail'), -1);
			return null;
		}

		$this->users[$user] = compact('pass', 'name', 'mail', 'grps');
		return $pwd;
	}
	
	public function modifyUser($user, $changes) {
		global $ACT;
		dbglog("authserversso: modifyUser {$user}");

		// sanity checks, user must already exist and there must be something to change
		if(($userinfo = $this->getUserData($user)) === false) {
			msg($this->getLang('usernotexists'), -1);
			return false;
		}

		// don't modify protected users
		if(!empty($userinfo['protected'])) {
			msg(sprintf($this->getLang('protected'), hsc($user)), -1);
			return false;
		}

		if(!is_array($changes) || !count($changes)) return true;

		// update userinfo with new data, remembering to encrypt any password
		$newuser = $user;
		foreach($changes as $field => $value) {
			if($field == 'user') {
				$newuser = $value;
				continue;
			}
			if($field == 'pass') $value = auth_cryptPassword($value);
			$userinfo[$field] = $value;
		}

		$userline = $this->_createUserLine($newuser, $userinfo['pass'], $userinfo['name'], $userinfo['mail'], $userinfo['grps']);

		if(!io_replaceInFile(AUTH_USERFILE, '/^'.$user.':/', $userline, true)) {
			msg('There was an error modifying your user data. You may need to register again.', -1);
			// FIXME, io functions should be fail-safe so existing data isn't lost
			$ACT = 'register';
			return false;
		}

		$this->users[$newuser] = $userinfo;
		return true;
	}
	
	public function deleteUsers($users) {
		if(!is_array($users) || empty($users)) return 0;
		dbglog('authserversso: deleteUsers');

		if($this->users === null) $this->_loadUserData();

		$deleted = array();
		foreach($users as $user) {
			// don't delete protected users
			if(!empty($this->users[$user]['protected'])) {
				msg(sprintf($this->getLang('protected'), hsc($user)), -1);
				continue;
			}
			if(isset($this->users[$user])) $deleted[] = preg_quote($user, '/');
		}

		if(empty($deleted)) return 0;

		$pattern = '/^('.join('|', $deleted).'):/';
		if (!io_deleteFromFile(AUTH_USERFILE, $pattern, true)) {
			msg($this->getLang('writefail'), -1);
			return 0;
		}

		// reload the user list and count the difference
		$count = count($this->users);
		$this->_loadUserData();
		$count -= count($this->users);
		return $count;
	}
	
	public function getUserCount($filter = array()) {
		dbglog('authserversso: getUserCount');
		if($this->users === null) $this->_loadUserData();

		if(!count($filter)) return count($this->users);

		$count = 0;
		$this->_constructPattern($filter);

		foreach($this->users as $user => $info) {
			$count += $this->_filter($user, $info);
		}

		return $count;
	}

	public function retrieveUsers($start = 0, $limit = 0, $filter = array()) {
		dbglog('authserversso: retrieveUsers');
		if($this->users === null) $this->_loadUserData();

		ksort($this->users);

		$i     = 0;
		$count = 0;
		$out   = array();
		$this->_constructPattern($filter);

		foreach($this->users as $user => $info) {
			if($this->_filter($user, $info)) {
				if($i >= $start) {
					$out[$user] = $info;
					$count++;
					if(($limit > 0) && ($count >= $limit)) break;
				}
				$i++;
			}
		}

		return $out;
	}
	
	public function cleanUser($user) {
		global $conf;
		return cleanID(str_replace(':', $conf['sepchar'], $user));
	}
 
	public function cleanGroup($group) {
		global $conf;
		return cleanID(str_replace(':', $conf['sepchar'], $group));
	}
 
	protected function _loadUserData(){
		dbglog('authserversso: load user data');
		$this->users = $this->_readUserFile(AUTH_USERFILE);
	
	}
	
	protected function _readUserFile($file) {
		$users = array();
		if(!file_exists($file)) return $users;
		
		dbglog('authserversso: read user file');
		$lines = file($file);
		foreach($lines as $line) {
			$line = preg_replace('/#.*$/', '', $line); //ignore comments
			$line = trim($line);
			if(empty($line)) continue;

			$row = $this->_splitUserData($line);
			$row = str_replace('\\:', ':', $row);
			$row = str_replace('\\\\', '\\', $row);

			$groups = array_values(array_filter(explode(",", $row[4])));

			$users[$row[0]]['pass'] = $row[1];
			$users[$row[0]]['name'] = urldecode($row[2]);
			$users[$row[0]]['mail'] = $row[3];
			$users[$row[0]]['grps'] = $groups;
		}
		return $users;
	}
	protected function _splitUserData($line){
		// due to a bug in PCRE 6.6, preg_split will fail with the regex we use here
		// refer github issues 877 & 885
		if ($this->_pregsplit_safe){
		return preg_split('/(?<![^\\\\]\\\\)\:/', $line, 5);       // allow for : escaped as \:
		}

		$row = array();
		$piece = '';
		$len = strlen($line);
		for($i=0; $i<$len; $i++){
			if ($line[$i]=='\\'){
				$piece .= $line[$i];
				$i++;
				if ($i>=$len) break;
			} else if ($line[$i]==':') {
				$row[] = $piece;
				$piece = '';
				continue;
			}
			$piece .= $line[$i];
		}
		$row[] = $piece;

		return $row;
	}		
	
	protected function _filter($user, $info) {
		foreach($this->_pattern as $item => $pattern) {
			if($item == 'user') {
				if(!preg_match($pattern, $user)) return false;
			} else if($item == 'grps') {
				if(!count(preg_grep($pattern, $info['grps']))) return false;
			} else {
				if(!preg_match($pattern, $info[$item])) return false;
			}
		}
		return true;
	}
	
	protected function _constructPattern($filter) {
		$this->_pattern = array();
		foreach($filter as $item => $pattern) {
			$this->_pattern[$item] = '/'.str_replace('/', '\/', $pattern).'/i'; // allow regex characters
		}
	}

	/**
	* Do all authentication
	* @param   string  $user    Username
	* @param   string  $pass    Cleartext Password
	* @param   bool    $sticky  Cookie should not expire
	* @return  bool             true on successful auth
	*/
	function trustExternal($user, $pass, $sticky=false) {
	//public function trustExternal() {
		global $USERINFO;
		global $ACT;
		global $conf;
		global $auth;
		
		dbglog('authserversso: trustExternal');

		//$do = array_key_exists('do', $_REQUEST) ? $_REQUEST['do'] : null;
		
		//Got a session already ?
		if($this->hasSession()) {
			dbglog('authserversso: Session found');
			return true;
		}
		$userSso = $this->cleanUser($this->getSSOId());
		$data = $this->getUserData($userSso);
		if($data == false) {
			$mail = $this->getSSOMail();
			$name = $this->getSSOName();
			$pwd = auth_pwgen();
			$pwd = $this->createUser($userSso, $pwd, $name, $mail);
			if(!is_null($pwd)) {
				$data = $this->getUserData($userSso);
			}
		}
		if($data == false) {
			dbglog('authserversso: could not get user');
			return false;
		}
		$this->setSession($userSso, $data['grps'], $data['mail'], $data['name']);
		dbglog('authserversso: authenticated user');
		return true;
	}
    
	private function getSSOId() {
		return $this->getServerVar($this->conf[self::CONF_VAR_AUTH_ID]);
	}
	
	private function getSSOMail() {
		$mail = $this->getServerVar($this->conf[self::CONF_VAR_AUTH_EMAIL]);
		if(!$mail || !mail_isvalid($mail)) return null;
		return $mail;
	}

	private function getSSOName() {
		return $this->getServerVar($this->conf[self::CONF_VAR_AUTH_REALNAME]);
	}
	
	private function getServerVar($varName) {
			if(is_null($varName)) return null;
			if(!array_key_exists($varName, $_SERVER)) return null;
			$varVal = $_SERVER[$varName];
			dbglog("authserversso: getServerVar {$varName}:{$varVal}");
			return $varVal;
	}
		
	private function hasSession() {
			global $USERINFO;
			dbglog('authserversso: check hasSession');
			if(!empty($_SESSION[DOKU_COOKIE]['auth']['info'])) {
				dbglog('authserversso: Session found');
				$USERINFO['name'] = $_SESSION[DOKU_COOKIE]['auth']['info']['name'];
				$USERINFO['mail'] = $_SESSION[DOKU_COOKIE]['auth']['info']['mail'];
				$USERINFO['grps'] = $_SESSION[DOKU_COOKIE]['auth']['info']['grps'];
				$_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['auth']['user'];
			}
			return false;
	}
    
	// Create user session
	private function setSession($user, $grps, $mail, $name) {
			global $USERINFO;
			$USERINFO['name'] = $name;
			$USERINFO['mail'] = $mail;
			$USERINFO['grps'] = is_array($grps) ? $grps : array();
			$_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
			$_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
			$_SERVER['REMOTE_USER'] = $user;
			return $_SESSION[DOKU_COOKIE];
	}   
}