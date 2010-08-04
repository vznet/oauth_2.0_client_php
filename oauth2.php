<?php
/**
 * Copyright (c) 2010 VZnet Netzwerke Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author    Bastian Hofmann <bhfomann@vz.net>
 * @copyright 2010 VZnet Netzwerke Ltd.
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class OAuth2_Service_Configuration
{
    /**
     * @var string
     */
    private $_authorizeEndpoint;

    /**
     * @var string
     */
    private $_accessTokenEndpoint;

    /**
     * @param string $authorizeEndpoint
     * @param string $accessTokenEndpoint
     */
    public function __construct($authorizeEndpoint, $accessTokenEndpoint) {
        $this->_authorizeEndpoint = $authorizeEndpoint;
        $this->_accessTokenEndpoint = $accessTokenEndpoint;
    }

    /**
     * @return string
     */
    public function getAuthorizeEndpoint() {
        return $this->_authorizeEndpoint;
    }

    /**
     * @return string
     */
    public function getAccessTokenEndpoint() {
        return $this->_accessTokenEndpoint;
    }

}

class OAuth2_Service
{
    /**
     * @var OAuth2_Client
     */
    private $_client;

    /**
     * @var OAuth2_Service_Configuration
     */
    private $_configuration;

    /**
     * @var OAuth2_DataStore_Abstract
     */
    private $_dataStore;

    /**
     * @var string
     */
    private $_scope;

    /**
     * @param OAuth2_Client $client
     * @param OAuth2_Service_Configuration $configuration
     * @param OAuth2_DataStore_Abstract $dataStore
     * @param string $scope optional
     */
    public function  __construct(OAuth2_Client $client,
            OAuth2_Service_Configuration $configuration,
            OAuth2_DataStore_Abstract $dataStore,
            $scope = null) {
        $this->_client = $client;
        $this->_configuration = $configuration;
        $this->_dataStore = $dataStore;
        $this->_scope = $scope;
    }

    /**
     * redirect to authorize endpoint of service
     */
    public function authorize() {
        $parameters = array(
            'type' => 'web_server',
            'client_id' => $this->_client->getClientKey(),
            'redirect_uri' => $this->_client->getCallbackUrl()
        );
        if ($this->_scope) {
            $parameters['scope'] = $this->_scope;
        }
        $url = $this->_configuration->getAuthorizeEndpoint() . '?' . http_build_query($parameters);

        header('Location: ' . $url);
        die();
    }

    /**
     * get access token of from service, has to be called after successfull authorization
     *
     * @param string $code optional, if no code given method tries to get it out of $_GET
     */
    public function getAccessToken($code = null) {
        if (! $code) {
            if (! isset($_GET['code'])) {
                throw new OAuth2_Exception('could not retrieve code out of callback request and no code given');
            }
            $code = $_GET['code'];
        }

        $parameters = array(
            'grant_type' => 'authorization_code',
            'type' => 'web_server',
            'client_id' => $this->_client->getClientKey(),
            'client_secret' => $this->_client->getClientSecret(),
            'redirect_uri' => $this->_client->getCallbackUrl(),
            'code' => $code,
        );

        $http = new OAuth2_HttpClient($this->_configuration->getAccessTokenEndpoint(), 'POST', http_build_query($parameters));
        $http->execute();

        $this->_parseAccessTokenResponse($http);
    }

    /**
     * refresh access token
     *
     * @param OAuth2_Token $token
     */
    public function refreshAccessToken(OAuth2_Token $token) {
        if (! $token->getRefreshToken()) {
            throw new OAuth2_Exception('could not refresh access token, no refresh token available');
        }

        $parameters = array(
            'grant_type' => 'refresh_token',
            'type' => 'web_server',
            'client_id' => $this->_client->getClientKey(),
            'client_secret' => $this->_client->getClientSecret(),
            'refresh_token' => $token->getRefreshToken(),
        );

        $http = new OAuth2_HttpClient($this->_configuration->getAccessTokenEndpoint(), 'POST', http_build_query($parameters));
        $http->execute();

        $this->_parseAccessTokenResponse($http);
    }

    /**
     * parse the response of an access token request and store it in dataStore
     *
     * @param OAuth2_HttpClient $http
     */
    private function _parseAccessTokenResponse(OAuth2_HttpClient $http) {
        $headers = $http->getHeaders();
        $type = 'text';
        if (isset($headers['Content-Type']) && strpos($headers['Content-Type'], 'application/json') !== false) {
            $type = 'json';
        }

        switch ($type) {
            case 'json':
                $response = json_decode($http->getResponse(), true);
                break;
            case 'text':
            default:
                $response = OAuth2_HttpClient::parseStringToArray($http->getResponse(), '&', '=');
                break;
        }

        if (isset($response['error'])) {
            throw new OAuth2_Exception('got error while requesting access token: ' . $response['error']);
        }
        if (! isset($response['access_token'])) {
            throw new OAuth2_Exception('no access_token found');
        }

        $token = new OAuth2_Token($response['access_token'], 
                isset($response['refresh_token']) ? $response['refresh_token'] : null, 
                isset($response['expires_in']) ? $response['expires_in'] : null);

        $this->_dataStore->storeAccessToken($token);
    }

    /**
     * call an api endpoint. automatically adds needed authorization headers with access token or parameters
     *
     * @param string $endpoint
     * @param string $method default 'GET'
     * @param array $uriParameters optional
     * @param mixed $postBody optional, can be string or array
     * @return string
     */
    public function callApiEndpoint($endpoint, $method = 'GET', array $uriParameters = array(), $postBody = null) {
        $token = $this->_dataStore->retrieveAccessToken();

        //check if token is invalid
        if ($token->getLifeTime() && $token->getLifeTime() < time()) {
            $token = $this->refreshAccessToken($token);
        }

        if ($method !== 'GET') {
            if (is_array($postBody)) {
                $postBody['oauth_token'] = $token->getAccessToken();
                $parameters = http_build_query($postBody);
            } else {
                $postBody .= '&oauth_token=' . urlencode($token->getAccessToken());
                $parameters = $postBody;
            }
        } else {
            $uriParameters['oauth_token'] = $token->getAccessToken();
        }

        if (! empty($uriParameters)) {
            $endpoint .= (strpos($endpoint, '?') !== false ? '&' : '?') . http_build_query($uriParameters);
        }

        $parameters = null;

        $header = array();
        $header = array('Authorization: OAuth ' . $token->getAccessToken());

        $http = new OAuth2_HttpClient($endpoint, $method, $parameters, $header);
        $http->execute();
        
        return $http->getResponse();
    }
}

class OAuth2_Token
{
    /**
     * @var string
     */
    private $_accessToken;

    /**
     * @var string
     */
    private $_refreshToken;

    /**
     * @var string
     */
    private $_lifeTime;

    /**
     *
     * @param string $accessToken
     * @param string $refreshToken
     * @param int $lifeTime
     */
    public function __construct($accessToken = null, $refreshToken = null, $lifeTime = null) {
        $this->_accessToken = $accessToken;
        $this->_refreshToken = $refreshToken;
        if ($lifeTime) {
            $this->_lifeTime = ((int)$lifeTime) + time();
        }
    }

    /**
     * @return string
     */
    public function getAccessToken() {
        return $this->_accessToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken() {
        return $this->_refreshToken;
    }

    /**
     * @return int
     */
    public function getLifeTime() {
        return $this->_lifeTime;
    }

}

class OAuth2_DataStore_Session extends OAuth2_DataStore_Abstract
{
    public function __construct() {
        session_start();
    }

    /**
     *
     * @return OAuth2_Token
     */
    public function retrieveAccessToken() {
        return isset($_SESSION['oauth2_token']) ? $_SESSION['oauth2_token'] : new OAuth2_Token();
    }

    /**
     * @param OAuth2_Token $token
     */
    public function storeAccessToken(OAuth2_Token $token) {
        $_SESSION['oauth2_token'] = $token;
    }

    public function  __destruct() {
        session_write_close();
    }
}

abstract class OAuth2_DataStore_Abstract
{
    /**
     * @param OAuth2_Token $token
     */
    abstract function storeAccessToken(OAuth2_Token $token);

    /**
     * @return OAuth2_Token
     */
    abstract function retrieveAccessToken();
}

class OAuth2_Client
{
    /**
     * @var string
     */
    private $_clientKey;

    /**
     * @var string
     */
    private $_clientSecret;

    /**
     * @var string
     */
    private $_callbackUrl;

    /**
     *
     * @param string $clientKey
     * @param string $clientSecret
     * @param string $callbackUrl
     */
    public function __construct($clientKey, $clientSecret, $callbackUrl) {
        $this->_clientKey = $clientKey;
        $this->_clientSecret = $clientSecret;
        $this->_callbackUrl = $callbackUrl;
    }

    /**
     * @return string
     */
    public function getClientKey() {
        return $this->_clientKey;
    }

    /**
     * @return string
     */
    public function getClientSecret() {
        return $this->_clientSecret;
    }

    /**
     * @return string
     */
    public function getCallbackUrl() {
        return $this->_callbackUrl;
    }
}

class OAuth2_HttpClient
{
    /**
     * @var string
     */
    private $_url;

    /**
     * @var string
     */
    private $_method;

    /**
     * @var string
     */
    private $_parameters;

    /**
     * @var array
     */
    private $_requestHeader;

    /**
     * @var string
     */
    private $_response;

    /**
     * @var array
     */
    private $_headers;

    /**
     * @var array
     */
    private $_info;

    /**
     * @var boolean
     */
    private $_debug = false;

    /**
     * @param string $url
     * @param string $method
     * @param string $parameters
     * @param array $header  any additional header which should be set
     */
    public function __construct($url, $method, $parameters = null, array $header = array()) {
        $this->_url = $url;
        $this->_method = $method;
        $this->_parameters = $parameters;
        $this->_requestHeader = $header;
    }

    /**
     * parses a string with two delimiters to an array
     *
     * example:
     *
     * param1=value1&param2=value2
     *
     * will result with delimiters & and = to
     *
     * array(
     *   'param1' => 'value1',
     *   'param2' => 'value2',
     * )
     *
     * @param string $string
     * @param string $firstDelimiter
     * @param string $secondDelimiter
     * @return array
     */
    public static function parseStringToArray($string, $firstDelimiter, $secondDelimiter) {
        $resultArray = array();
        $parts = explode($firstDelimiter, $string);
        foreach ($parts as $part) {
            $partsPart = explode($secondDelimiter, $part);
            $resultArray[$partsPart[0]] = isset($partsPart[1]) ? trim($partsPart[1]) : '';
        }
        return $resultArray;
    }

    /**
     * executes the curl request
     */
    public function execute() {
        $ch = curl_init();

        if ($this->_method === 'POST') {
            curl_setopt($ch, CURLOPT_URL, $this->_url);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $this->_parameters);
        } else {
            curl_setopt($ch, CURLOPT_URL, $this->_url . ($this->_parameters ? '?' . $this->_parameters : ''));
        }

        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        if (! empty($this->_requestHeader)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $this->_requestHeader);
        }

        $fullResponse = curl_exec($ch);
        $this->_info = curl_getinfo($ch);

        $this->_response = substr($fullResponse, $this->_info['header_size'], strlen($fullResponse));
        if ($this->_response === false) {
            $this->_response = '';
        }
        $headers = rtrim(substr($fullResponse, 0, $this->_info['header_size']));

        $this->_headers = OAuth2_HttpClient::parseStringToArray($headers, PHP_EOL, ':');

        if ($this->_debug) {
            echo "<pre>";
            print_r($this->_url);
            echo PHP_EOL;
            print_r($this->_headers);
            echo PHP_EOL;
            print_r($this->_response);
            echo "</pre>";
        }
        
        curl_close($ch);
    }

    /**
     * @return string
     */
    public function getResponse() {
        return $this->_response;
    }

    /**
     * @return array
     */
    public function getHeaders() {
        return $this->_headers;
    }

    /**
     * @param boolean $debug 
     */
    public function setDebug($debug) {
        $this->_debug = $debug;
    }

}

class OAuth2_Exception extends Exception {}