<?php
use dokuwiki\Extension\ActionPlugin;

class action_plugin_authserversso extends ActionPlugin {
	/*
	public function __construct() {
		global $active;
		
		//dbglog("authserversso: Action constructor: {$authClass}");
		//dbglog('authserversso: Disable login');
		$disableactions = explode(',', $conf['disableactions']);
		$disableactions = array_map('trim', $disableactions);
		if (!in_array('login', $disableactions)) {
			$disableactions[] = 'login';
		}
		$conf['disableactions'] = implode(',', $disableactions);
		$conf['autopasswd'] = 0;
	}
	*/
	function register(Doku_Event_Handler $controller){
		// dbglog('authserversso: Register hooks');
		//$controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'clean_global_auth', NULL);
		$controller->register_hook('ACTION_ACT_PREPROCESS', 'AFTER', $this, 'skip_login_action', NULL);
		$controller->register_hook('HTML_REGISTERFORM_OUTPUT', 'BEFORE', $this, 'modify_register_form', NULL);
	}
	
	function clean_global_auth(&$event, $param) {
		if(isset($_SERVER['PHP_AUTH_USER'])) {
			dbglog('authserversso: Clean PHP_AUTH_USER');
			unset($_SERVER['PHP_AUTH_USER']);
		}
		if(isset($_SERVER['PHP_AUTH_PW'])) {
			dbglog('authserversso: Clean PHP_AUTH_PW');
			unset($_SERVER['PHP_AUTH_PW']);
		}
	}
	
	function skip_login_action(&$event, $param) {
		if ($event->data == 'login') {
			send_redirect($ID, 'show');
		}
	}	
	
	function modify_register_form(&$event, $param) {
		$pos = $event->data->findElementByAttribute('name','login');
		if (!$pos)
			return;

		$elem = $event->data->getElementAt($pos);
		$elem['value'] = $_SERVER['REMOTE_USER'];
		$elem['readonly'] = 'readonly';
		$event->data->replaceElement($pos, $elem);

		$pwd = auth_pwgen();
		foreach (array('pass', 'passchk') as $name) {
			$pos = $event->data->findElementByAttribute('name', $name);
			$event->data->replaceElement($pos, NULL);
			$event->data->addHidden($name, $pwd);
		}
	}	
}