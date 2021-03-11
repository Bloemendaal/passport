<?php

namespace Laravel\Passport\Http\Controllers;

use Laravel\Passport\DeviceCodeRepository;
use Laravel\Passport\DeviceCode;
use Laravel\Passport\Passport;
use Illuminate\Http\Response;
use Illuminate\Http\Request;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;

class DeviceAccessTokenController
{
    /**
     * The token repository implementation.
     *
     * @var \Laravel\Passport\TokenRepository
     */
    protected $tokenRepository;

    /**
     * The validation factory implementation.
     *
     * @var \Illuminate\Contracts\Validation\Factory
     */
    protected $validation;

    /**
     * Create a controller instance.
     *
     * @param  \Laravel\Passport\DeviceCodeRepository  $deviceCodeRepository
     * @param  \Illuminate\Contracts\Validation\Factory  $validation
     * @return void
     */
    public function __construct(
        DeviceCodeRepository $deviceCodeRepository,
        ValidationFactory $validation
    ) {
        $this->validation = $validation;
        $this->deviceCodeRepository = $deviceCodeRepository;
    }

    /**
     * Check device request exist.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function request(Request $request)
    {
        $deviceCode = DeviceCode::where('user_code', $request->user_code)
            ->where('expires_at', '>', now())
            ->first();

        return $deviceCode ?? response()->json([
            'message' => __('User code has expired or is invalid please try again.')
        ], 404);
    }

    /**
     * Get all of the personal access tokens for the authenticated user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function forUser(Request $request)
    {
        return $this->deviceCodeRepository
            ->forUser($request->user()->getKey())
            ->sortBy('expires_at')
            ->values();
    }

    /**
     * Activate new device for the user.
     * @fix this response myst be created..
     * @param  \Illuminate\Http\Request  $request
     * @return \Laravel\Passport\PersonalAccessTokenResult
     */
    public function store(Request $request)
    {
        $validate = [
            'user_code' => [
                'required',
                'exists:' . with(new DeviceCode)->getTable() . ',user_code'
            ],
        ];

        $errors = [
            'user_code.exists' => 'This code do not exist please try again.',
        ];

        $this->validation->make($request->all(), $validate, $errors)->validate();

        return $request->user()->activateDevice($request->user_code);
    }

    /**
     * Delete the given token.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $tokenId
     * @return \Illuminate\Http\Response
     */
    public function destroy(Request $request, $tokenId)
    {
        $token = $this->deviceCodeRepository->findForUser(
            $tokenId,
            $request->user()->getKey()
        );

        if (\is_null($token)) {
            return new Response('', 404);
        }

        $token->revoke();

        return new Response('', Response::HTTP_NO_CONTENT);
    }
}
