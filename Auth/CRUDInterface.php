<?php

namespace AuthTutorial;

/**
 * Interface CRUDInterface
 *
 * @package App\Auth
 */
interface CRUDInterface
{
	public function saveFailedLogin($login, $reason);

	public function saveSuccessLogin($login);

	public function findUser($field, $value);

	/**
	 * @param $key
	 * @param $token
	 * @param $data
	 *
	 * @return boolean
	 */
	public function setRememberData($key, $token, $data);

	/**
	 * @param $key
	 * @param $token
	 *
	 * @return array
	 */
	public function getRememberData($key, $token);

	/**
	 * @param string $key
	 * @param string $token
	 * @param int    $userId
	 *
	 * @return boolean
	 */
	public function setForgotData($key, $token, $userId);

	/**
	 * @param string $key
	 * @param string $token
	 *
	 * @return integer
	 */
	public function getForgotData($key, $token);
}