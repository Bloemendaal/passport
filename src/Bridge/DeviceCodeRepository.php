<?php

namespace Laravel\Passport\Bridge;

use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\DeviceCodeRepository as PassportDeviceCodeRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use League\OAuth2\Server\Repositories\DeviceCodeRepositoryInterface;

class DeviceCodeRepository implements DeviceCodeRepositoryInterface
{
    use FormatsScopesForStorage;

    /**
     * The token repository instance.
     *
     * @var \Laravel\Passport\DeviceCodeRepository
     */
    protected $deviceCodeRepository;

    /**
     * The event dispatcher instance.
     *
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $events;

    /**
     * Create a new repository instance.
     *
     * @param  \Laravel\Passport\DeviceCodeRepository  $deviceCodeRepository
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     */
    public function __construct(PassportDeviceCodeRepository $deviceCodeRepository, Dispatcher $events)
    {
        $this->events = $events;
        $this->deviceCodeRepository = $deviceCodeRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewDeviceCode()
    {
        return new DeviceCode($this->deviceCodeRepository);
    }

    /**
     * {@inheritdoc}
     */
    public function persistNewDeviceCode(DeviceCodeEntityInterface $deviceCodeEntity)
    {
        $this->deviceCodeRepository->create([
            'id' => $deviceCodeEntity->getIdentifier(),
            'user_code' => $deviceCodeEntity->getUserCode(),
            'user_id' => null,
            'client_id' => $deviceCodeEntity->getClient()->getIdentifier(),
            'scopes' => $this->scopesToArray($deviceCodeEntity->getScopes()),
            'revoked' => false,
            'retry_interval' => $deviceCodeEntity->getRetryInterval(),
            'last_polled_at' => $deviceCodeEntity->getLastPolledDateTime(),
            'expires_at' => $deviceCodeEntity->getExpiryDateTime(),
        ]);

        // @todo add events
    }

    /**
     * {@inheritdoc}
     */
    public function getDeviceCodeByIdentifier($deviceCodeId, $grantType, ClientEntityInterface $clientEntity)
    {
        $deviceCode = $this->deviceCodeRepository->find($deviceCodeId);

        $deviceCodeEntity = $this->getNewDeviceCode();
        $deviceCodeEntity->setIdentifier($deviceCode->id);
        $deviceCodeEntity->setUserCode($deviceCode->user_code);
        $deviceCodeEntity->setUserIdentifier($deviceCode->user_id);
        $deviceCodeEntity->setRetryInterval($deviceCode->retry_interval);
        $deviceCodeEntity->setLastPolledDateTime($deviceCode->last_polled_at);

        foreach ($deviceCode->scopes as $scope) {
            $deviceCodeEntity->addScope(new Scope($scope));
        }

        $deviceCodeEntity->setClient($clientEntity);

        $deviceCode->touch();

        return $deviceCodeEntity;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeDeviceCode($deviceCodeId)
    {
        $this->deviceCodeRepository->revokeDeviceCode($deviceCodeId);
    }

    /**
     * {@inheritdoc}
     */
    public function isDeviceCodeRevoked($deviceCodeId)
    {
        return $this->deviceCodeRepository->isDeviceCodeRevoked($deviceCodeId);
    }
}
