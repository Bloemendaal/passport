<?php

namespace Laravel\Passport;

use Illuminate\Container\Container;

trait HasApiTokens
{
    /**
     * The current access token for the authentication user.
     *
     * @var \Laravel\Passport\Token
     */
    protected $accessToken;

    /**
     * Get all of the user's registered OAuth clients.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function clients()
    {
        return $this->hasMany(Passport::clientModel(), 'user_id');
    }

    /**
     * Get all of the access tokens for the user.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function tokens()
    {
        return $this->hasMany(Passport::tokenModel(), 'user_id')->orderBy('created_at', 'desc');
    }

    /**
     * Get the current access token being used by the user.
     *
     * @return \Laravel\Passport\Token|null
     */
    public function token()
    {
        return $this->accessToken;
    }

    /**
     * Determine if the current API token has a given scope.
     *
     * @param  string  $scope
     * @return bool
     */
    public function tokenCan($scope)
    {
        return $this->accessToken ? $this->accessToken->can($scope) : false;
    }

    /**
     * Create a new personal access token for the user.
     *
     * @param  string  $name
     * @param  array  $scopes
     * @return \Laravel\Passport\PersonalAccessTokenResult
     */
    public function createToken($name, array $scopes = [])
    {
        return Container::getInstance()->make(PersonalAccessTokenFactory::class)->make(
            $this->getKey(),
            $name,
            $scopes
        );
    }

    /**
     * Activate new device for the user.
     * @todo fix this not ready
     * @param  string  $user_code
     * @return string|null id of the device or null when there is no device.
     */
    public function activateDevice($user_code)
    {
        return Container::getInstance()->make(DeviceCodeRepository::class)->activate(
            $this->getKey(),
            $user_code
        );
    }

    /**
     * Set the current access token for the user.
     *
     * @param  \Laravel\Passport\Token  $accessToken
     * @return $this
     */
    public function withAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;

        return $this;
    }
}
