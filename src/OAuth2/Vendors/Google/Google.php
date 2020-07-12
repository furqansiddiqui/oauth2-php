<?php
declare(strict_types=1);

namespace FurqanSiddiqui\OAuth2\Vendors\Google;

use FurqanSiddiqui\OAuth2\Profile;
use FurqanSiddiqui\OAuth2\Vendors\AbstractVendor;
use HttpClient\HttpClient;
use HttpClient\Response;

/**
 * Class Google
 * @package FurqanSiddiqui\OAuth2\Vendors\Google
 */
class Google extends AbstractVendor
{
    /**
     * @param string $appId
     * @param string $redirectURI
     * @return string
     */
    public static function AuthenticateURL(string $appId, string $redirectURI): string
    {
        return "https://accounts.google.com/o/oauth2/v2/auth?" . http_build_query([
                "response_type" => "code",
                "client_id" => $appId,
                "redirect_uri" => $redirectURI,
                "scope" => "profile email"
            ]);
    }

    /**
     * @param array $input
     * @param string $redirectURI
     * @return Profile
     * @throws GoogleException
     * @throws \HttpClient\Exception\HttpClientException
     * @throws \HttpClient\Exception\RequestException
     * @throws \HttpClient\Exception\ResponseException
     * @throws \HttpClient\Exception\SSLException
     */
    public function requestProfile(array $input, string $redirectURI): Profile
    {
        $accessToken = $this->code2Token($input["code"] ?? "", $redirectURI);
        $googleProfile = HttpClient::Get(
            "https://people.googleapis.com/v1/people/me?" . http_build_query([
                "personFields" => "emailAddresses,names,locales",
                "access_token" => $accessToken
            ])
        )->json();
        $googleProfile->ssl()->verify(true);
        $googleProfile = $googleProfile->send();

        $googleProfile = $this->getResponse($googleProfile);
        $errorMessage = $googleProfile["error"]["message"] ?? null;
        if (is_string($errorMessage)) {
            throw new GoogleException(sprintf('%1$s: %2$s', __METHOD__, $errorMessage));
        }

        $resourceName = $googleProfile["resourceName"] ?? null;
        if (!is_string($resourceName) || !preg_match('/^profile\/[0-9]+$/', $resourceName)) {
            $googleProfileId = explode("/", $resourceName)[1];
        }

        if (!isset($googleProfileId) || !is_string($googleProfileId) || !$googleProfileId) {
            throw new GoogleException('Google+ profile ID was not received');
        }

        $profile = new Profile($accessToken);
        $profile->id = $googleProfileId;
        $profile->email = $googleProfile["emailAddresses"][0]["value"] ?? null;
        $profile->firstName = $googleProfile["names"][0]["givenName"] ?? null;
        $profile->lastName = $googleProfile["names"][0]["familyName"] ?? null;

        return $profile;
    }

    /**
     * @param Response\HttpClientResponse $response
     * @return array
     * @throws GoogleException
     */
    protected function getResponse(Response\HttpClientResponse $response): array
    {
        if (!$response instanceof Response\JSONResponse) {
            throw new GoogleException('Unexpected HTTP response type');
        }

        return $response->array();
    }

    /**
     * @param string $code
     * @param string $redirectURI
     * @return string
     * @throws GoogleException
     * @throws \HttpClient\Exception\HttpClientException
     * @throws \HttpClient\Exception\RequestException
     * @throws \HttpClient\Exception\ResponseException
     */
    private function code2Token(string $code, string $redirectURI): string
    {
        $accessTokenRequest = HttpClient::Post("https://www.googleapis.com/oauth2/v4/token")
            ->payload([
                "code" => $code,
                "client_id" => $this->appId,
                "client_secret" => $this->appSecret,
                "redirect_uri" => $redirectURI,
                "grant_type" => "authorization_code"
            ])->json();
        $accessTokenRequest->ssl()->verify(true);
        $accessTokenRequest = $accessTokenRequest->send();

        $response = $this->getResponse($accessTokenRequest);
        $errorMessage = $response["error_description"] ?? null;
        if (is_string($errorMessage)) {
            throw new GoogleException(sprintf('%1$s: %2$s', __METHOD__, $errorMessage));
        }

        $accessToken = $response["access_token"] ?? null;
        if (!is_string($accessToken)) {
            throw new GoogleException('Failed to retrieve "access_token"');
        }

        return $accessToken;
    }
}
