<?php

namespace AuthTutorial;

use Models\MySQL\User;
use Phalcon\Events\Manager;
use Phalcon\Mvc\User\Component;

/**
 * Class Auth
 *
 * @package App
 */
class Auth extends Component
{
	const M_FRONTEND = 1;
	const M_BACKEND  = 2;

	/**
	 * @var CRUD
	 */
	protected $_crud;

	protected $_options = [
		'session_key'     => 'identity',
		'auth_field'      => ['id', 'email'],
		'forgot_fields'   => 'id, username, email',
		'forgot_key'      => 'Auth:Forgot:Tokens',
		'module'          => self::M_FRONTEND,
		'remember_expire' => 8600,
		'remember_cookie' => 'rmt',
		'remember_key'    => 'Auth:Remember:Tokens',
		'auth_map'        => 'auth_map:',
	];

	/**
	 * @var string
	 */
	protected $_forgot_token;

	/**
	 * @var boolean
	 */
	protected $_isIdentity;

	/**
	 * @var array
	 */
	protected $_errorMessages = [];

	/**
	 * @var User
	 */
	protected $_User;

	/**
	 * Auth constructor.
	 *
	 * @param array $_options
	 */
	public function __construct(array $_options = [])
	{
		$this->_options = array_merge($this->_options, $_options);

		$this->_crud = new CRUD($this->_options);

		$this->checkAuth();
	}

	/**
	 * Идентифицирован ли пользователь
	 *
	 * @return bool
	 */
	public function isIdentity()
	{
		if ( $this->_isIdentity === null ) {
			$this->_isIdentity = (bool) $this->session->has($this->_options['session_key']);
		}

		return ($this->_isIdentity === true);
	}

	public function loginByToken($token)
	{
		if ( $this->redis->exists($token) === false ) {
			$message = $this->t->_('Неправильный логин или пароль. Пожалуйста попробуйте снова или воспользуйтесь ссылкой "Забыли пароль?"');

			$this->appendMessage($message);

			return false;
		}

		$userId = (int) $this->redis->get($token);

		$User = User::findFirst($userId);

		if ( !$User ) {
			$message = $this->t->_('Неправильный логин или пароль. Пожалуйста попробуйте снова или воспользуйтесь ссылкой "Забыли пароль?"');

			$this->appendMessage($message);

			return false;
		}

		$tokenCheck = md5(sprintf('ip[%s]:agent[%s]:id[%s]:pass[%s]', $this->request->getClientAddress(), $this->request->getUserAgent(), $userId, $User->getPassword()));

		if ( $token !== $tokenCheck ) {
			$message = $this->t->_('Неправильный логин или пароль. Пожалуйста попробуйте снова или воспользуйтесь ссылкой "Забыли пароль?"');

			$this->appendMessage($message);

			return false;
		}

		return $this->logIn($User->getLogin(), '', false, false);
	}

	public function loginSocial($login)
	{
		return $this->logIn($login, '', false, false);
	}

	/**
	 * @param string $login
	 * @param string $pass
	 * @param bool   $needRemember
	 * @param bool   $checkPass
	 *
	 * @return bool
	 */
	public function logIn($login, $pass, $needRemember = false, $checkPass = true)
	{
		if ( $this->_eventsManager instanceof Manager ) {
			$fire = $this->_eventsManager->fire('auth:beforeAuth', $this, [
				'login'        => $login,
				'pass'         => $pass,
				'needRemember' => $needRemember,
				'checkPass'    => $checkPass,
			]);

			if ( $fire === false ) {
				return false;
			}
		}

		$User = $this->_crud->findUser($this->_options['auth_field'], $login);

		if ( !$User ) {
			$message = $this->t->_('Неправильный логин или пароль. Пожалуйста попробуйте снова или воспользуйтесь ссылкой "Забыли пароль?"');

			$this->appendMessage($message);

			$this->_crud->saveFailedLogin($login, $message);

			return false;
		}

		/**
		 * Проверяем пароль
		 */
		if ( $checkPass && !$this->security->checkHash($pass, $User->getPassword()) ) {
			$this->logOut();

			$message = $this->t->_('Неправильный пароль или логин. Пожалуйста попробуйте снова или воспользуйтесь ссылкой "Забыли пароль?"');

			$this->appendMessage($message);

			$this->_crud->saveFailedLogin($login, $message);

			return false;
		}

		if ( $this->_eventsManager instanceof Manager ) {
			$fire = $this->_eventsManager->fire('auth:afterUserChecked', $this, $User);

			if ( $fire === false ) {
				return false;
			}
		}

		$data = [
			'id'      => (int) $User->getId(),
			'user_id' => (int) $User->getId(),
			'login'   => $User->getAuthField(),
			'email'   => $User->getEmail(),
			'role'    => $User->getRole(),
			'token'   => sha1($User->getEmail() . $User->getPassword() . $this->request->getUserAgent()),
			'agent'   => md5($this->request->getUserAgent()),
			'created' => time(),
		];

		$this->_setIdentity($data);

		if ( $needRemember ) {
			$this->_setRemember($data);
		}

		if ( $this->_eventsManager instanceof Manager ) {
			$fire = $this->_eventsManager->fire('auth:afterAuth', $this, $User);

			if ( $fire === false ) {
				$this->logOut();

				return false;
			}
		}

		return true;
	}

	/**
	 * Выходим
	 */
	public function logOut()
	{
		$this->cookies->get($this->_options['remember_cookie'])->delete();
		$this->session->remove($this->_options['session_key']);

		$this->_isIdentity = null;
	}

	public function logoutById($userId)
	{
		$key = $this->_options['auth_map'] . $userId;

		$data = $this->redis->hGetAll($key);

		array_unshift($data, $this->_options['remember_key']);
		call_user_func_array([$this->redis, 'hDel'], $data);

		$redisConnection = $this->redisConnection;

		$data = $this->redis->hGetAll($key);

		$redisConnection->select(0);
		$redisConnection->del($data);

		$this->redis->del($key);
		$this->di->get('socket')->push('backend', 'user-logout', [
			'user_id' => $userId,
		]);
	}

	public function getAuthById($userId)
	{
		$key = $this->_options['auth_map'] . $userId;

		$data = $this->redis->hGetAll($key);

		$redisConnection = $this->redisConnection;
		$redisConnection->select(0);

		$out = [];

		foreach ( $data as $key => $datum ) {
			if ( strpos($key, 'session') === 0 ) {
				$temp = unserialize($redisConnection->get($datum));

				if ( is_array($temp) ) {
					foreach ( $temp as $k => $item ) {
						if ( strpos($k, 'identity') === 0 ) {
							$out[] = $item;

							break;
						}
					}
				}
			}
		}

		return $out;
	}

	/**
	 * Записываем сообщение об ошибке
	 *
	 * @param $message
	 */
	public function appendMessage($message)
	{
		$this->_errorMessages[] = $message;
	}

	/**
	 * Отдаём сообщения об ошибках
	 *
	 * @return array
	 */
	public function getMessages()
	{
		return $this->_errorMessages;
	}

	/**
	 * Получаем информацию об авторизованном пользователе
	 *
	 * @param null $key
	 *
	 * @return mixed
	 */
	public function getIdentity($key = null)
	{
		$identity = $this->session->get($this->_options['session_key']);

		if ( $key !== null ) {
			return $identity[$key];
		}

		return $identity;
	}

	/**
	 * Проверяем есть ли кука для 'Запомнить меня'
	 *
	 * @return boolean
	 */
	public function isRemember()
	{
		return $this->cookies->has($this->_options['remember_cookie']);
	}

	/**
	 * Получает данные для входа через режим 'Запомнить меня'
	 *
	 * @return array
	 */
	public function getRemember()
	{
		$token = $this->cookies->get($this->_options['remember_cookie'])->getValue();
		$data  = $this->_crud->getRememberData($this->_options['remember_key'], $token);

		if ( !$data ) {
			$this->cookies->get($this->_options['remember_cookie'])->delete();

			return [];
		}

		return $data;
	}

	/**
	 * @param int $userId
	 *
	 * @return boolean
	 */
	public function forgotMakeToken($userId)
	{
		$token = preg_replace('/[^a-zA-Z0-9]/', '', base64_encode(openssl_random_pseudo_bytes(32)));

		if ( !$this->_crud->setForgotData($this->_options['forgot_key'], $token, $userId) ) {
			$this->appendMessage($this->t->_('Внезапно возникла непонятная ошибка') . '¯\_(ツ)_/¯');

			return false;
		}

		$this->_forgot_token = $token;

		return true;
	}

	/**
	 * @param $token
	 *
	 * @return int
	 */
	public function forgotGetUserId($token)
	{
		return (int) $this->_crud->getForgotData($this->_options['forgot_key'], $token);
	}

	/**
	 * @return string
	 */
	public function getForgotToken()
	{
		return $this->_forgot_token;
	}

	/**
	 * @param bool $refresh
	 *
	 * @return \Backend\Models\MySQL\User
	 */
	public function getUser($refresh = false)
	{
		if ( null === $this->_User || $refresh ) {
			$this->_User = $this->_crud->findUser('id', $this->getIdentity('user_id'));
		}

		return $this->_User;
	}

	protected function checkRemember()
	{
		$remember = $this->getRemember();

		if ( !count($remember) ) {
			$this->logOut();

			return false;
		}

		$User = $this->_crud->findUser($this->_options['auth_field'], $remember['login']);

		if ( !$User ) {
			$this->logOut();

			return false;
		}

		$token = sha1($User->getEmail() . $User->getPassword() . $this->request->getUserAgent());

		if ( $remember['token'] === $token ) {
			$this->logOut();

			return false;
		}

		/**
		 * Проверяем не истекла ли кука
		 */
		if ( (time() - $this->_options['remember_expire']) >= $remember['created'] ) {
			$this->logOut();

			return false;
		}

		$this->logIn($User->getAuthField(), '', false, false);

		return true;
	}

	/**
	 * Записываем данные об авторизации
	 *
	 * @param array $data
	 */
	protected function _setIdentity(array $data)
	{
		$this->session->set($this->_options['session_key'], $data);
		$this->_isIdentity = true;

		$key = $this->_options['auth_map'] . $data['id'];

		$this->redis->hSet($key, 'token:' . time(), $this->session->getId());
		$this->redis->hSet($key, 'session:' . time(), '_PHCR:session:' . $this->session->getId());
	}

	/**
	 * Записываем данные для авторизации по куке
	 *
	 * @param array $data
	 */
	protected function _setRemember(array $data)
	{
		$expire = time() + $this->_options['remember_expire'];

		if ( $this->_crud->setRememberData($this->_options['remember_key'], $data['token'], $data) ) {
			$this->cookies->set($this->_options['remember_cookie'], $data['token'], $expire, '/');
		}
	}

	/**
	 * Проверка авторизации
	 *
	 * @return bool
	 */
	protected function checkAuth()
	{
		/**
		 * Проверяем не была ли сессия переставлена из другого браузера
		 */
		if ( $this->isIdentity() ) {
			$identity = $this->getIdentity();

			if ( $identity['agent'] !== md5($this->request->getUserAgent()) ) {
				$this->appendMessage('There was a substitution of session');

				$this->logOut();

				return false;
			}
		}

		/**
		 * Проверяем совпадают ли данные в сессии с данными в куки
		 * если не совпадают - разлогиниваем пользователя
		 */
		if ( $this->isIdentity() && $this->isRemember() ) {
			$identity = $this->getIdentity();
			$remember = $this->getRemember();

			if ( empty($identity) || empty($remember) ) {
				return false;
			}

			if ( $identity['token'] !== $remember['token'] ) {
				$this->logOut();

				return false;
			}
		}

		/**
		 * Идентифицируем пользователя если есть кука и он не идентифицирован
		 */
		if ( !$this->isIdentity() && $this->isRemember() ) {
			$this->checkRemember();

			return true;
		}

		return true;
	}
}