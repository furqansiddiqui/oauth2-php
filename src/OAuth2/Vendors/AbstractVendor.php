<?php
declare(strict_types=1);

namespace OAuth2\Vendors;

use HttpClient\Response;
use OAuth2\Profile;

/**
 * Class AbstractVendor
 * @package OAuth2
 */
abstract class AbstractVendor
{
    /** @var string */
    protected $appId;
    /** @var string */
    protected $appSecret;

    /**
     * AbstractVendor constructor.
     * @param string $appId
     * @param string $appSecret
     */
    public function __construct(string $appId, string $appSecret)
    {
        $this->appId    =   $appId;
        $this->appSecret    =   $appSecret;
    }

    /**
     * @param array $input
     * @param string $redirectURI
     * @return Profile
     */
    abstract public function requestProfile(array $input, string $redirectURI) : Profile;

    /**
     * @param Response $response
     * @return array
     */
    abstract protected function getResponse(Response $response) : array;

    /**
     * @param string $appId
     * @param string $redirectURI
     * @return string
     */
    abstract public static function AuthenticateURL(string $appId, string $redirectURI) : string;
}