<?php
declare(strict_types=1);

namespace FurqanSiddiqui\OAuth2;

/**
 * Class Profile
 * @package FurqanSiddiqui\OAuth2
 */
class Profile
{
    /** @var string|null */
    private ?string $accessToken;
    /** @var string|null */
    public ?string $id = null;
    /** @var string|null */
    public ?string $email = null;
    /** @var string|null */
    public ?string $firstName = null;
    /** @var string|null */
    public ?string $lastName = null;

    /**
     * Profile constructor.
     * @param string|null $accessToken
     */
    public function __construct(string $accessToken = null)
    {
        $this->accessToken = $accessToken;
    }
}
