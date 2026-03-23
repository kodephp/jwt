<?php

declare(strict_types=1);

namespace Kode\Jwt\OpenId;

use Kode\Jwt\Token\Payload;

/**
 * OpenID Connect 用户信息
 */
final readonly class UserInfo
{
    public function __construct(
        public string $sub,
        public ?string $name = null,
        public ?string $givenName = null,
        public ?string $familyName = null,
        public ?string $middleName = null,
        public ?string $nickname = null,
        public ?string $preferredUsername = null,
        public ?string $profile = null,
        public ?string $picture = null,
        public ?string $website = null,
        public ?string $email = null,
        public bool $emailVerified = false,
        public ?string $gender = null,
        public ?string $birthdate = null,
        public ?string $zoneinfo = null,
        public ?string $locale = null,
        public ?string $phoneNumber = null,
        public bool $phoneNumberVerified = false,
        public ?string $address = null,
        public ?int $updatedAt = null,
        public array $customClaims = []
    ) {
    }

    /**
     * 从 Payload 创建 UserInfo
     */
    public static function fromPayload(Payload $payload): self
    {
        $custom = $payload->getCustomData();

        return new self(
            sub: (string) $payload->uid,
            name: $custom['name'] ?? $payload->username,
            givenName: $custom['given_name'] ?? null,
            familyName: $custom['family_name'] ?? null,
            middleName: $custom['middle_name'] ?? null,
            nickname: $custom['nickname'] ?? null,
            preferredUsername: $payload->username,
            profile: $custom['profile'] ?? null,
            picture: $custom['picture'] ?? null,
            website: $custom['website'] ?? null,
            email: $custom['email'] ?? null,
            emailVerified: (bool) ($custom['email_verified'] ?? false),
            gender: $custom['gender'] ?? null,
            birthdate: $custom['birthdate'] ?? null,
            zoneinfo: $custom['zoneinfo'] ?? null,
            locale: $custom['locale'] ?? null,
            phoneNumber: $custom['phone_number'] ?? null,
            phoneNumberVerified: (bool) ($custom['phone_number_verified'] ?? false),
            address: $custom['address'] ?? null,
            updatedAt: $custom['updated_at'] ?? null,
            customClaims: $custom
        );
    }

    /**
     * 转换为数组
     */
    public function toArray(): array
    {
        $result = ['sub' => $this->sub];

        if ($this->name !== null) {
            $result['name'] = $this->name;
        }
        if ($this->givenName !== null) {
            $result['given_name'] = $this->givenName;
        }
        if ($this->familyName !== null) {
            $result['family_name'] = $this->familyName;
        }
        if ($this->middleName !== null) {
            $result['middle_name'] = $this->middleName;
        }
        if ($this->nickname !== null) {
            $result['nickname'] = $this->nickname;
        }
        if ($this->preferredUsername !== null) {
            $result['preferred_username'] = $this->preferredUsername;
        }
        if ($this->profile !== null) {
            $result['profile'] = $this->profile;
        }
        if ($this->picture !== null) {
            $result['picture'] = $this->picture;
        }
        if ($this->website !== null) {
            $result['website'] = $this->website;
        }
        if ($this->email !== null) {
            $result['email'] = $this->email;
        }
        if ($this->emailVerified) {
            $result['email_verified'] = true;
        }
        if ($this->gender !== null) {
            $result['gender'] = $this->gender;
        }
        if ($this->birthdate !== null) {
            $result['birthdate'] = $this->birthdate;
        }
        if ($this->zoneinfo !== null) {
            $result['zoneinfo'] = $this->zoneinfo;
        }
        if ($this->locale !== null) {
            $result['locale'] = $this->locale;
        }
        if ($this->phoneNumber !== null) {
            $result['phone_number'] = $this->phoneNumber;
        }
        if ($this->phoneNumberVerified) {
            $result['phone_number_verified'] = true;
        }
        if ($this->address !== null) {
            $result['address'] = $this->address;
        }
        if ($this->updatedAt !== null) {
            $result['updated_at'] = $this->updatedAt;
        }

        return array_merge($result, $this->customClaims);
    }
}
