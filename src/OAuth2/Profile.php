<?php
declare(strict_types=1);

namespace OAuth2;

/**
 * Class Profile
 * @package OAuth2
 */
class Profile
{
    /** @var string|null */
    private $accessToken;
    /** @var string|null */
    public $id;
    /** @var string|null */
    public $email;
    /** @var string|null */
    public $firstName;
    /** @var string|null */
    public $lastName;

    /**
     * Profile constructor.
     * @param string|null $accessToken
     */
    public function __construct(string $accessToken = null)
    {
        $this->accessToken  =   $accessToken;
    }
}