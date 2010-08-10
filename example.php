<?php

require_once 'oauth2.php';

// configuration of client credentials
$client = new OAuth2_Client(
        'CLIENT_ID',
        'CLIENT_SECRET',
        'CALLBACK_URL');

// configuration of service
$configuration = new OAuth2_Service_Configuration(
        'AUTHORIZE_ENDPOINT',
        'ACCESS_TOKEN_ENDPOINT');

// storage class for access token, just extend OAuth2_DataStore_Abstract for
// your own implementation
$dataStore = new OAuth2_DataStore_Session();

$scope = null;

$service = new OAuth2_Service($client, $configuration, $dataStore, $scope);

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
        <script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js"></script>
    </head>
    <body>
        Consumer Key: <input type="text" id="consumer-key" value="<?= $client->getClientKey() ?>" /><br />
        Consumer Secret: <input type="text" id="consumer-secret" value="<?= $client->getClientSecret() ?>" /><br />
        Access Token: <input type="text" id="access-token" value="<?= $token->getAccessToken() ?>" /><br />
        Refresh Token: <input type="text" id="refresh-token" value="<?= $token->getRefreshToken() ?>" /><br />
        LifeTime: <input type="text" id="lifetime" value="<?= $token->getLifeTime() ?>" /><br />
        <br />
        <a href="javascript:;" id="authorize">authorize</a><br />
        <br />
        <a href="javascript:;" id="request-api">request API</a><br />
        <script type="text/javascript">
            $('#authorize').click(function() {
                window.location.href = 'index.php?action=authorize';
            });
            $('#request-api').click(function() {
                window.location.href = 'index.php?action=requestApi';
            });
        </script>
    </body>
</html>