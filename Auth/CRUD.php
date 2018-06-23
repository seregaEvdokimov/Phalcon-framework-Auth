<?php

namespace AuthTutorial;

use Models\MySQL\User;
use Phalcon\Mvc\User\Component;

/**
 * Class CRUD
 *
 * @package App\Auth
 */
class CRUD extends Component implements CRUDInterface
{
	protected $_options = [];

	/**
	 * CRUD constructor.
	 *
	 * @param array $_options
	 */
	public function __construct(array $_options = [])
	{
		$this->_options = $_options;
	}

	public function saveFailedLogin($login, $reason)
	{
	}

	public function saveSuccessLogin($login)
	{
	}

	public function findUser($field, $value)
	{
		if ( is_array($field) ) {
			$temp = [];
			foreach ( $field as $f ) {
				$temp[] = "{$f} = :value:";
			}
			$conditions = implode(' OR ', $temp);
		} else {
			$conditions = "{$field} = :value:";
		}

		return User::findFirst([
			'conditions' => "({$conditions}) AND site_id = :site_id:",
			'bind'       => [
				'value'   => $value,
				'site_id' => $this->settings->get('site_id'),
			],
		]);
	}

	public function setRememberData($key, $token, $data)
	{
		return $this->redis->hSet($key, $token, json_encode($data, JSON_UNESCAPED_UNICODE)) !== false;
	}

	public function getRememberData($key, $token)
	{
		return json_decode($this->redis->hGet($key, $token), true);
	}

	/**
	 * @param string $key
	 * @param string $token
	 * @param int    $userId
	 *
	 * @return mixed
	 */
	public function setForgotData($key, $token, $userId)
	{
		return $this->redis->hSet($key, $token, $userId) !== false;
	}

	/**
	 * @param string $key
	 * @param string $token
	 *
	 * @return int
	 */
	public function getForgotData($key, $token)
	{
		return (int) $this->redis->hGet($key, $token);
	}
}