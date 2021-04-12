<?php

namespace Laravel\Passport;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\App;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptTrait;

class DeviceCode extends Model
{
    use CryptTrait;

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'oauth_device_codes';

    /**
     * Indicates if the IDs are auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The guarded attributes on the model.
     *
     * @var array
     */
    protected $guarded = [];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'scopes' => 'array',
        'revoked' => 'bool',
    ];

    /**
     * The attributes that should be mutated to dates.
     *
     * @var array
     */
    protected $dates = [
        'last_polled_at',
        'expires_at',
    ];

    /**
     * The name of the "created at" column.
     *
     * @var string
     */
    const CREATED_AT = null;

    /**
     * The name of the "updated at" column.
     *
     * @var string
     */
    const UPDATED_AT = 'last_polled_at';

    /**
     * The "type" of the primary key ID.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * Get the client that owns the authentication code.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function client()
    {
        return $this->belongsTo(Passport::clientModel());
    }

    /**
     * Update the retry interval for this device.
     *
     * @param  int   $seconts
     * @return bool
     */
    public function setInterval($seconds)
    {
        $this->retry_interval = $seconds;

        return $this->save();
    }

    /**
     * Revoke the instance.
     *
     * @return bool
     */
    public function revoke()
    {
        return $this->forceFill(['revoked' => true])->save();
    }

    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        $this->setEncryptionKey(
            App::make(AuthorizationServer::class)->getEncryptionKey()
        );
    }

    public function resolveRouteBinding($value, $field = null)
    {
        if ($field === 'decode') {
            try {
                $deviceCodePayload = \json_decode($this->decrypt($value));

                if (!\property_exists($deviceCodePayload, 'device_code_id')) {
                    return null;
                }

                return $this->where('id', $deviceCodePayload->device_code_id)->first();
            } catch (\Exception $e) {
                return null;
            }
        }

        return parent::resolveRouteBinding($value, $field);
    }
}
