<?php

class OAuth2_Service_Configuration
{
    private $_authorizeEndpoint;
    private $_accessTokenEndpoint;

    public function __construct($authorizeEndpoint, $accessTokenEndpoint) {
        $this->_authorizeEndpoint = $authorizeEndpoint;
        $this->_accessTokenEndpoint = $accessTokenEndpoint;
    }

    public function getAuthorizeEndpoint() {
        return $this->_authorizeEndpoint;
    }

    public function getAccessTokenEndpoint() {
        return $this->_accessTokenEndpoint;
    }

}

class OAuth2_Service
{
    private $_client;
    private $_configuration;
    private $_dataStore;
    private $_scope;
    
    public function  __construct(OAuth2_Client $client,
            OAuth2_Service_Configuration $configuration,
            OAuth2_DataStore_Abstract $dataStore,
            $scope = null) {
        $this->_client = $client;
        $this->_configuration = $configuration;
        $this->_dataStore = $dataStore;
        $this->_scope = $scope;
    }
    
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
    }

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

    }
}

class OAuth2_Token
{
    private $_accessToken;
    private $_refreshToken;
    private $_lifeTime;

    public function __construct($accessToken = null, $refreshToken = null, $lifeTime = null) {
        $this->_accessToken = $accessToken;
        $this->_refreshToken = $refreshToken;
        if ($lifeTime) {
            $this->_lifeTime = $lifeTime + time();
        }
    }

    public function getAccessToken() {
        return $this->_accessToken;
    }

    public function getRefreshToken() {
        return $this->_refreshToken;
    }

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

    public function storeAccessToken(OAuth2_Token $token) {
        $_SESSION['oauth2_token'] = $token;
    }

    public function  __destruct() {
        session_write_close();
    }
}

abstract class OAuth2_DataStore_Abstract
{
    abstract function storeAccessToken(OAuth2_Token $token);
    abstract function retrieveAccessToken();
}

class OAuth2_Client
{
    private $_clientKey;
    private $_clientSecret;
    private $_callbackUrl;

    public function __construct($clientKey, $clientSecret, $callbackUrl) {
        $this->_clientKey = $clientKey;
        $this->_clientSecret = $clientSecret;
        $this->_callbackUrl = $callbackUrl;
    }

    public function getClientKey() {
        return $this->_clientKey;
    }

    public function getClientSecret() {
        return $this->_clientSecret;
    }

    public function getCallbackUrl() {
        return $this->_callbackUrl;
    }
}

class OAuth2_HttpClient
{
    private $_url;
    private $_method;
    private $_parameters;
    private $_requestHeader;

    private $_response;
    private $_headers;
    private $_info;

    public function __construct($url, $method, $parameters = null, array $header = array()) {
        $this->_url = $url;
        $this->_method = $method;
        $this->_parameters = $parameters;
        $this->_requestHeader = $header;
    }

    public static function parseStringToArray($string, $firstDelimiter, $secondDelimiter) {
        $resultArray = array();
        $parts = explode($firstDelimiter, $string);
        foreach ($parts as $part) {
            $partsPart = explode($secondDelimiter, $part);
            $resultArray[$partsPart[0]] = isset($partsPart[1]) ? trim($partsPart[1]) : '';
        }
        return $resultArray;
    }

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

        echo "<pre>";
        print_r($this->_url);
        echo PHP_EOL;
        print_r($this->_headers);
        echo PHP_EOL;
        print_r($this->_response);
        echo "</pre>";
        curl_close($ch);
    }

    public function getResponse() {
        return $this->_response;
    }

    public function getHeaders() {
        return $this->_headers;
    }


}

class OAuth2_Exception extends Exception
{
    
}