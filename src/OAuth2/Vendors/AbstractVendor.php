<?php
declare(strict_types=1);

namespace FurqanSiddiqui\OAuth2\Vendors;

use FurqanSiddiqui\OAuth2\Profile;
use HttpClient\Response\HttpClientResponse;

/**
 * Class AbstractVendor
 * @package FurqanSiddiqui\OAuth2\Vendors
 */
abstract class AbstractVendor
{
    /** @var string */
    protected string $appId;
    /** @var string */
    protected string $appSecret;

    /**
     * AbstractVendor constructor.
     * @param string $appId
     * @param string $appSecret
     */
    public function __construct(string $appId, string $appSecret)
    {
        $this->appId = $appId;
        $this->appSecret = $appSecret;
    }

    /**
     * @param array $input
     * @param string $redirectURI
     * @return Profile
     */
    abstract public function requestProfile(array $input, string $redirectURI): Profile;

    /**
     * @param HttpClientResponse $response
     * @return array
     */
    abstract protected function getResponse(HttpClientResponse $response): array;

    /**
     * @param string $appId
     * @param string $redirectURI
     * @return string
     */
    abstract public static function AuthenticateURL(string $appId, string $redirectURI): string;
}
