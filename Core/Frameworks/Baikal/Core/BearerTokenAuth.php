<?php

namespace Baikal\Core;

use Sabre\HTTP;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\ResponseInterface;
use Firebase\JWT\JWT;

/**
 * This is an authentication backend that uses a BearerToken to authenticate.
 */
class BearerTokenAuth extends \Sabre\DAV\Auth\Backend\AbstractBearer
{
    protected $secret;

    /**
     * Creates the backend
     *
     * @param string $secret . The token secret
     */
    function __construct($secret)
    {
        error_log("\r\nBearerTokenAuth.__construct\r\n" . $secret . "\r\n");
        $this->secret = $secret;
    }

    function validateBearerToken($bearerToken)
    {
        error_log("\r\nBearerTokenAuth.validateBearerToken\r\n" . $bearerToken . "\r\n");
        $decoded = JWT::decode($bearerToken, $this->secret, array('HS256'));
        $decoded_array = (array)$decoded;
        if (isset($decoded_array["user"])) {
            error_log("\r\n" . "principals/" . $decoded_array["user"] . "\r\n");
            return "principals/" . $decoded_array["user"];
        }
        return false;
    }
}
