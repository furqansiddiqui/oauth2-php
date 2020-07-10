<?php
declare(strict_types=1);

namespace FurqanSiddiqui\OAuth2\Vendors\Facebook;

use FurqanSiddiqui\OAuth2\Profile;
use FurqanSiddiqui\OAuth2\Vendors\AbstractVendor;
use HttpClient\HttpClient;
use HttpClient\Response;

/**
 * Class Facebook
 * @package OAuth2\Vendors\Facebook
 */
class Facebook extends AbstractVendor
{
    /** @var string|null */
    private ?string $accessToken = null;

    /**
     * @param string $appId
     * @param string $redirectURI
     * @return string
     */
    public static function AuthenticateURL(string $appId, string $redirectURI): string
    {
        return "https://www.facebook.com/v2.10/dialog/oauth?" . http_build_query([
                "client_id" => $appId,
                "redirect_uri" => $redirectURI,
                "scope" => "public_profile,email"
            ]);
    }

    /**
     * @param array $input
     * @param string $redirectURI
     * @return Profile
     * @throws FacebookException
     * @throws \HttpClient\Exception\HttpClientException
     * @throws \HttpClient\Exception\RequestException
     * @throws \HttpClient\Exception\ResponseException
     */
    public function requestProfile(array $input, string $redirectURI): Profile
    {
        if (isset($input["access_token"]) && is_string($input["access_token"])) {
            $this->setToken($input["access_token"]);
        } elseif (isset($input["code"]) && is_string($input["code"])) {
            $this->code2Token($input["code"], $redirectURI);
        }

        if (!$this->hasToken()) {
            throw new FacebookException('Failed to retrieve "access_token" from Facebook API');
        }

        $profile = $this->validateToken();

        // Get profile fields
        $requestProfile = HttpClient::Get(
            "https://graph.facebook.com/me?" . http_build_query([
                "fields" => "email,first_name,last_name",
                "access_token" => $this->accessToken
            ])
        )->json();
        $requestProfile->ssl()->verify(true);
        $requestProfile = $requestProfile->send();
        $response = $this->getResponse($requestProfile);

        $errorMessage = $response["error"]["message"] ?? null;
        if ($errorMessage) {
            throw new FacebookException(sprintf('%1$s: %2$s', __METHOD__, $errorMessage));
        }

        $responseProfileId = $response["id"] ?? "";
        if ($responseProfileId !== $profile->id) {
            throw new FacebookException(sprintf('%1$s: Profile ID mismatch', __METHOD__));
        }

        // Set Profile props
        $profile->email = $response["email"] ?? null;
        $profile->firstName = $response["first_name"] ?? null;
        $profile->lastName = $response["last_name"] ?? null;

        return $profile;
    }

    /**
     * @param Response\HttpClientResponse $response
     * @return array
     * @throws FacebookException
     */
    protected function getResponse(Response\HttpClientResponse $response): array
    {
        if (!$response instanceof Response\JSONResponse) {
            throw new FacebookException('Unexpected HTTP response type');
        }

        return $response->array();
    }

    /**
     * @param string $code
     * @param string $redirectURI
     * @return string
     * @throws FacebookException
     * @throws \HttpClient\Exception\HttpClientException
     * @throws \HttpClient\Exception\RequestException
     * @throws \HttpClient\Exception\ResponseException
     */
    private function code2Token(string $code, string $redirectURI): string
    {
        $accessTokenRequest = HttpClient::Get(
            "https://graph.facebook.com/v2.10/oauth/access_token?" . http_build_query([
                "client_id" => $this->appId,
                "client_secret" => $this->appSecret,
                "redirect_uri" => $redirectURI,
                "code" => $code
            ])
        )->json();
        $accessTokenRequest->ssl()->verify(true);
        $accessTokenRequest = $accessTokenRequest->send();
        $response = $this->getResponse($accessTokenRequest);

        $accessToken = $response["access_token"] ?? null;
        if (is_string($accessToken)) {
            $this->accessToken = $accessToken;
            return $accessToken;
        }

        $errorMessage = $response["error"]["message"] ?? null;
        $errorMessage = $errorMessage ?? "Failed to retrieve access_token via API";

        throw new FacebookException(sprintf('%1$s: %2$s', __METHOD__, $errorMessage));
    }

    /**
     * @param string $token
     */
    private function setToken(string $token)
    {
        $this->accessToken = $token;
    }

    /**
     * @return bool
     */
    private function hasToken(): bool
    {
        return !empty($this->accessToken);
    }

    /**
     * @return Profile
     * @throws FacebookException
     * @throws \HttpClient\Exception\HttpClientException
     * @throws \HttpClient\Exception\RequestException
     * @throws \HttpClient\Exception\ResponseException
     */
    private function validateToken(): Profile
    {
        $debugRequest = HttpClient::Get(
            'https://graph.facebook.com/debug_token?' . http_build_query([
                "input_token" => $this->accessToken,
                "access_token" => sprintf('%s|%s', $this->appId, $this->appSecret)
            ])
        )->json();
        $debugRequest->ssl()->verify(true);
        $debugRequest = $debugRequest->send();

        if ($debugRequest->code() !== 200) {
            throw new FacebookException(
                sprintf('Unexpected HTTP response code %1$d', $debugRequest->code())
            );
        }

        $response = $this->getResponse($debugRequest);
        $isValid = $response["data"]["is_valid"] ?? false;
        if ($isValid !== true) {
            throw new FacebookException('Invalid "access_token"');
        }

        $errorMessage = $response["data"]["error"]["message"] ?? null;
        if (is_string($errorMessage)) {
            throw new FacebookException($errorMessage);
        }

        // Cross-checking
        $appId = $response["data"]["app_id"] ?? null;
        $profileId = $response["data"]["user_id"] ?? null;
        $scopes = $response["data"]["scopes"] ?? [];
        unset($response);

        if (strval($appId) !== $this->appId) {
            throw new FacebookException('Application ID mismatch');
        }

        if (!is_array($scopes)) {
            throw new FacebookException('Invalid scopes');
        } elseif (!in_array("public_profile", $scopes)) {
            throw new FacebookException('Required scope "public_profile" was not granted');
        }

        // Create a Profile instance
        $profile = new Profile($this->accessToken);
        $profile->id = $profileId;

        return $profile;
    }
}
