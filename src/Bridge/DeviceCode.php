<?php

namespace Laravel\Passport\Bridge;

use DateTimeImmutable;
use Laravel\Passport\DeviceCodeRepository;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\DeviceCodeTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;

class DeviceCode implements DeviceCodeEntityInterface
{
    use DeviceCodeTrait, EntityTrait, TokenEntityTrait {
        checkRetryFrequency as parentCheckRetryFrequency;
    }

    /**
     * @param  \Laravel\Passport\DeviceCodeRepository  $deviceCodeRepository
     * @return void
     */
    public function __construct(DeviceCodeRepository $deviceCodeRepository)
    {
        $this->deviceCodeRepository = $deviceCodeRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function setUserCode($userCode)
    {
        if (!preg_match("/\w+-\w+/", $userCode)) {
            $userCode = substr_replace($userCode, '-', 4, 0);
        }

        $this->userCode = $userCode;
    }

    /**
     * {@inheritdoc}
     */
    public function checkRetryFrequency(DateTimeImmutable $nowDateTime)
    {
        $slowDownSeconds = $this->parentCheckRetryFrequency($nowDateTime);

        if ($slowDownSeconds) {
            $slowDownSeconds = ceil($slowDownSeconds * 2.0);
            $this->deviceCodeRepository->setRetryInterval(
                $this->getIdentifier(),
                $slowDownSeconds
            );
        }

        return $slowDownSeconds;
    }
}
