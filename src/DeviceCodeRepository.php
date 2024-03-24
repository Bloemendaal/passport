<?php

namespace Laravel\Passport;

class DeviceCodeRepository
{
    /**
     * Authorizes a device with the user id. Resets the usercode to avoid duplications.
     * @return string|null id of the activated device or null when the device was not found.
     */
    public function activate($user_id, $user_code): ?string
    {
        $deviceCode = Passport::deviceCode()
            ->where('user_code', $user_code)
            ->whereNull('user_id')
            ->first();

        if (!$deviceCode) {
            return null;
        }

        $deviceCode->user_id = $user_id;
        $deviceCode->user_code = null;
        $deviceCode->save();

        return $deviceCode->id;
    }

    /**
     * Creates a new device code.
     *
     * @param  array  $attributes
     * @return \Laravel\Passport\DeviceCode
     */
    public function create($attributes)
    {
        return Passport::deviceCode()->create($attributes);
    }

    /**
     * Get a device code by the given ID.
     *
     * @param  string  $id
     * @return \Laravel\Passport\DeviceCode
     */
    public function find($id)
    {
        return Passport::deviceCode()->where('id', $id)->first();
    }

    /**
     * Get a token by the given user ID and token ID.
     *
     * @param  string  $id
     * @param  int  $userId
     * @return \Laravel\Passport\Token|\Laravel\Passport\Token|null
     */
    public function findForUser($id, $userId)
    {
        return $this->forUser($userId, $id)->first();
    }

    /**
     * Get the token instances for the given user ID.
     *
     * @param  mixed  $userId
     * @param  mixed  $id
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function forUser($userId, $id = null)
    {
        $deviceTokens = Passport::token()
            ->whereUserId($userId)
            ->whereRevoked(false)
            ->whereHas('client', function ($query) {
                $query->whereDeviceClient(true);
            });

        $deviceRequests = Passport::deviceCode()
            ->whereUserId($userId)
            ->whereRevoked(false);

        if (!\is_null($id)) {
            $deviceTokens = $deviceTokens->whereId($id);
            $deviceRequests = $deviceRequests->whereId($id);
        }

        return $deviceTokens->get()->concat($deviceRequests->get());
    }

    /**
     * Set the retry interval of this code.
     *
     * @param  string  $id
     * @param  int     $seconds
     * @return \Laravel\Passport\DeviceCode
     */
    public function setRetryInterval($id, $seconds)
    {
        Passport::deviceCode()->where('id', $id)->first()->setInterval($seconds);
    }

    /**
     * Revoke an device code.
     *
     * @param  string  $id
     * @return mixed
     */
    public function revokeDeviceCode($id)
    {
        return Passport::deviceCode()->where('id', $id)->update(['revoked' => true]);
    }

    /**
     * Check if the device code has been revoked.
     *
     * @param  string  $id
     * @return bool
     */
    public function isDeviceCodeRevoked($id)
    {
        if ($deviceCode = $this->find($id)) {
            return $deviceCode->revoked;
        }

        return true;
    }
}
