<?php
declare(strict_types=1);

namespace FurqanSiddiqui\OAuth2\Vendors\LinkedIn;

use FurqanSiddiqui\OAuth2\Profile;
use FurqanSiddiqui\OAuth2\Vendors\AbstractVendor;
use HttpClient\HttpClient;
use HttpClient\Response\HttpClientResponse;
use HttpClient\Response\JSONResponse;

/**
 * Class LinkedIn
 * @package FurqanSiddiqui\OAuth2\Vendors\LinkedIn
 */
class LinkedIn extends AbstractVendor
{
    /**
     * @param string $appId
     * @param string $redirectURI
     * @return string
     */
    public static function AuthenticateURL(string $appId, string $redirectURI): string
    {
        return "https://www.linkedin.com/oauth/v2/authorization?" . http_build_query([
                "response_type" => "code",
                "client_id" => $appId,
                "redirect_uri" => $redirectURI,
                "state" => time(),
                "scope" => "r_basicprofile r_emailaddress"
            ]);
    }

    /**
     * @param HttpClientResponse $response
     * @return array
     * @throws LinkedInException
     */
    protected function getResponse(HttpClientResponse $response): array
    {
        if (!$response instanceof JSONResponse) {
            throw new LinkedInException('Unexpected HTTP response type');
        }

        return $response->array();
    }

    /**
     * @param array $input
     * @param string $redirectURI
     * @return Profile
     * @throws LinkedInException
     * @throws \HttpClient\Exception\HttpClientException
     * @throws \HttpClient\Exception\RequestException
     * @throws \HttpClient\Exception\ResponseException
     */
    public function requestProfile(array $input, string $redirectURI): Profile
    {
        $accessToken = $this->code2Token(strval($input["code"] ?? ""), $redirectURI);
        $linkedInProfile = HttpClient::Get(
            "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,email-address)"
        );
        $linkedInProfile->header("Authorization", "Bearer " . $accessToken);
        $linkedInProfile->header("x-li-format", "json");
        $linkedInProfile->ssl()->verify(true);
        $linkedInProfile = $linkedInProfile->send();

        $linkedInProfile = $this->getResponse($linkedInProfile);
        $errorMessage = $linkedInProfile["message"] ?? null;
        if (is_string($errorMessage)) {
            throw new LinkedInException(sprintf('%1$s: %2$s', __METHOD__, urldecode($errorMessage)));
        }

        $linkedInProfileId = $linkedInProfile["id"] ?? null;
        if (!is_string($linkedInProfileId)) {
            throw new LinkedInException('LinkedIn profile ID was not received');
        }

        $profile = new Profile($linkedInProfileId);
        $profile->id = $linkedInProfileId;
        $profile->email = $linkedInProfile["emailAddress"] ?? null;
        $profile->firstName = $linkedInProfile["firstName"] ?? null;
        $profile->lastName = $linkedInProfile["lastName"] ?? null;

        return $profile;
    }

    /**
     * @param string $code
     * @param string $redirectURI
     * @return string
     * @throws LinkedInException
     * @throws \HttpClient\Exception\HttpClientException
     * @throws \HttpClient\Exception\RequestException
     * @throws \HttpClient\Exception\ResponseException
     */
    private function code2Token(string $code, string $redirectURI): string
    {
        $accessTokenRequest = HttpClient::Post("https://www.linkedin.com/oauth/v2/accessToken")
            ->payload([
                "code" => $code,
                "client_id" => $this->appId,
                "client_secret" => $this->appSecret,
                "redirect_uri" => $redirectURI,
                "grant_type" => "authorization_code"
            ]);
        $accessTokenRequest->ssl()->verify(true);
        $accessTokenRequest = $accessTokenRequest->send();
        $response = $this->getResponse($accessTokenRequest);

        $errorMessage = $response["error_description"] ?? null;
        if (is_string($errorMessage)) {
            throw new LinkedInException(sprintf('%1$s: %2$s', __METHOD__, $errorMessage));
        }

        $accessToken = $response["access_token"] ?? null;
        if (!is_string($accessToken)) {
            throw new LinkedInException('Failed to retrieve "access_token"');
        }

        return $accessToken;
    }
}
