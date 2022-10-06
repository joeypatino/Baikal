<?php

namespace Baikal\Core;

use Sabre\HTTP;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\ResponseInterface;

/**
 * HTTP Basic authentication backend class.
 */
class RemoteAuth extends \Sabre\DAV\Auth\Backend\AbstractBasic
{

    protected $username;

    protected $endpoint;

    /**
     * Creates the backend.
     *
     * @param string $endpoint The endpoint
     */
    function __construct($endpoint)
    {
        error_log("\r\nRemoteAuth.__construct\r\n" . $endpoint . "\r\n");
        $this->endpoint = $endpoint;
    }

    function validateUserPass($username, $password)
    {
        error_log("\r\nRemoteAuth.validateUserPass\r\n");
        $url = $this->endpoint;
        $data = array('user' => $username, 'password' => $password);
        $options = array(
            'http' => array(
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => http_build_query($data)
            )
        );
        $context = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        if ($result === FALSE) {
            return false;
        }
        $obj = json_decode($result, true);
        if (!empty($obj['result']['user'])) {
            $this->username = $obj['result']['user'];
            return true;
        }
        return false;
    }

    function check(RequestInterface $request, ResponseInterface $response)
    {
        $auth = new HTTP\Auth\Basic(
            $this->realm,
            $request,
            $response
        );

        $userpass = $auth->getCredentials();
        if (!$userpass) {
            return [false, "No 'Authorization: Basic' header found. Either the client didn't send one, or the server is misconfigured"];
        }
        if (!$this->validateUserPass($userpass[0], $userpass[1])) {
            return [false, 'Username or password was incorrect'];
        }
        error_log("\r\n" . "true" . $this->principalPrefix . $this->username . "\r\n");
        return [true, $this->principalPrefix . $this->username];
    }
}