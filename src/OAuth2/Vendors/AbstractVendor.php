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
     * @return array|string[]
     */
    public function __debugInfo(): array
    {
        return [get_called_class() . " OAuth2.0 Credentials"];
    }

    /**
     * @return string
     */
    public function getAppId(): string
    {
        return $this->appId;
    }

    /**
     * @return string
     */
    public function getAppSecret(): string
    {
        return $this->appSecret;
    }

    /**
     * @param string $redirectURI
     * @return string
     */
    public function getAuthURL(string $redirectURI): string
    {
        return $this->AuthenticateURL($this->appId, $redirectURI);
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
