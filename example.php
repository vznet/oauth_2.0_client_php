<?php

spl_autoload_register(function ($class) {
    require str_replace('\\', DIRECTORY_SEPARATOR, $class) . '.php';
});

// configuration of client credentials
$client = new OAuth2\Client(
        'CLIENT_ID',
        'CLIENT_SECRET',
        'CALLBACK_URL');

// configuration of service
$configuration = new OAuth2\Service\Configuration(
        'AUTHORIZE_ENDPOINT',
        'ACCESS_TOKEN_ENDPOINT');

// storage class for access token, just implement OAuth2\DataStore interface for
// your own implementation
$dataStore = new OAuth2\DataStore\Session();

$scope = null;

$service = new OAuth2\Service($client, $configuration, $dataStore, $scope);

if (isset($_GET['action'])) {
    switch ($_GET['action']) {
        case 'authorize':
            // redirects to authorize endpoint
            $service->authorize();
            break;
        case 'requestApi':
            // calls api endpoint with access token
            echo $service->callApiEndpoint('API_ENDPOINT');
            break;
    }
}

if (isset($_GET['code'])) {
    // retrieve access token from endpoint
    $service->getAccessToken();
}

$token = $dataStore->retrieveAccessToken();

?>
<html>
    <head>
    </head>
    <body>
        Consumer Key: <input type="text" id="consumer-key" value="<?= $client->getClientKey() ?>" /><br />
        Consumer Secret: <input type="text" id="consumer-secret" value="<?= $client->getClientSecret() ?>" /><br />
        Access Token: <input type="text" id="access-token" value="<?= $token->getAccessToken() ?>" /><br />
        Refresh Token: <input type="text" id="refresh-token" value="<?= $token->getRefreshToken() ?>" /><br />
        LifeTime: <input type="text" id="lifetime" value="<?= $token->getLifeTime() ?>" /><br />
        <br />
        <a href="example.php?action=authorize" id="authorize">authorize</a><br />
        <br />
        <a href="example.php?action=requestApi" id="request-api">request API</a><br />
    </body>
</html>
