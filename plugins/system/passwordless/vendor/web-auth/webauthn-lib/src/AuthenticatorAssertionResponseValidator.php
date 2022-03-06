<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Akeeba\Passwordless\Webauthn;

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Akeeba\Passwordless\CBOR\Decoder;
use Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager;
use Akeeba\Passwordless\CBOR\Tag\TagObjectManager;
use Akeeba\Passwordless\Cose\Algorithm\Manager;
use Akeeba\Passwordless\Cose\Algorithm\Signature\Signature;
use Akeeba\Passwordless\Cose\Key\Key;
use function count;
use function in_array;
use function is_string;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use function Akeeba\Passwordless\Safe\parse_url;
use Throwable;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Akeeba\Passwordless\Webauthn\Counter\CounterChecker;
use Akeeba\Passwordless\Webauthn\Counter\ThrowExceptionIfInvalid;
use Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingHandler;
use Akeeba\Passwordless\Webauthn\Util\CoseSignatureFixer;

class AuthenticatorAssertionResponseValidator
{
    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $publicKeyCredentialSourceRepository;

    /**
     * @var Decoder
     */
    private $decoder;

    /**
     * @var TokenBindingHandler
     */
    private $tokenBindingHandler;

    /**
     * @var ExtensionOutputCheckerHandler
     */
    private $extensionOutputCheckerHandler;

    /**
     * @var Manager|null
     */
    private $algorithmManager;

    /**
     * @var CounterChecker
     */
    private $counterChecker;

    /**
     * @var LoggerInterface|null
     */
    private $logger;

    public function __construct(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, \Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingHandler $tokenBindingHandler, \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler $extensionOutputCheckerHandler, \Akeeba\Passwordless\Cose\Algorithm\Manager $algorithmManager, ?\Akeeba\Passwordless\Webauthn\Counter\CounterChecker $counterChecker = null, ?LoggerInterface $logger = null)
    {
        if (null !== $logger) {
            @trigger_error('The argument "logger" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setLogger".', E_USER_DEPRECATED);
        }
        if (null !== $counterChecker) {
            @trigger_error('The argument "counterChecker" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setCounterChecker".', E_USER_DEPRECATED);
        }
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;
        $this->decoder = new \Akeeba\Passwordless\CBOR\Decoder(new \Akeeba\Passwordless\CBOR\Tag\TagObjectManager(), new \Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager());
        $this->tokenBindingHandler = $tokenBindingHandler;
        $this->extensionOutputCheckerHandler = $extensionOutputCheckerHandler;
        $this->algorithmManager = $algorithmManager;
        $this->counterChecker = $counterChecker ?? new \Akeeba\Passwordless\Webauthn\Counter\ThrowExceptionIfInvalid();
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#verifying-assertion
     */
    public function check(string $credentialId, \Akeeba\Passwordless\Webauthn\AuthenticatorAssertionResponse $authenticatorAssertionResponse, \Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, ServerRequestInterface $request, ?string $userHandle, array $securedRelyingPartyId = []): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource
    {
        try {
            $this->logger->info('Checking the authenticator assertion response', [
                'credentialId' => $credentialId,
                'authenticatorAssertionResponse' => $authenticatorAssertionResponse,
                'publicKeyCredentialRequestOptions' => $publicKeyCredentialRequestOptions,
                'host' => $request->getUri()->getHost(),
                'userHandle' => $userHandle,
            ]);
            /** @see 7.2.1 */
            if (0 !== count($publicKeyCredentialRequestOptions->getAllowCredentials())) {
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($this->isCredentialIdAllowed($credentialId, $publicKeyCredentialRequestOptions->getAllowCredentials()), 'The credential ID is not allowed.');
            }

            /** @see 7.2.2 */
            $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId($credentialId);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notNull($publicKeyCredentialSource, 'The credential ID is invalid.');

            /** @see 7.2.3 */
            $attestedCredentialData = $publicKeyCredentialSource->getAttestedCredentialData();
            $credentialUserHandle = $publicKeyCredentialSource->getUserHandle();
            $responseUserHandle = $authenticatorAssertionResponse->getUserHandle();

            /** @see 7.2.2 User Handle*/
            if (null !== $userHandle) { //If the user was identified before the authentication ceremony was initiated,
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq($credentialUserHandle, $userHandle, 'Invalid user handle');
                if (null !== $responseUserHandle && '' !== $responseUserHandle) {
                    \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq($credentialUserHandle, $responseUserHandle, 'Invalid user handle');
                }
            } else {
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notEmpty($responseUserHandle, 'User handle is mandatory');
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq($credentialUserHandle, $responseUserHandle, 'Invalid user handle');
            }

            $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
            $isU2F = \Akeeba\Passwordless\Webauthn\U2FPublicKey::isU2FKey($credentialPublicKey);
            if ($isU2F) {
                $credentialPublicKey = \Akeeba\Passwordless\Webauthn\U2FPublicKey::createCOSEKey($credentialPublicKey);
            }
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notNull($credentialPublicKey, 'No public key available.');
            $stream = new \Akeeba\Passwordless\Webauthn\StringStream($credentialPublicKey);
            $credentialPublicKeyStream = $this->decoder->decode($stream);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($stream->isEOF(), 'Invalid key. Presence of extra bytes.');
            $stream->close();

            /** @see 7.2.4 */
            /** @see 7.2.5 */
            //Nothing to do. Use of objects directly

            /** @see 7.2.6 */
            $C = $authenticatorAssertionResponse->getClientDataJSON();

            /** @see 7.2.7 */
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq('webauthn.get', $C->getType(), 'The client data type is not "webauthn.get".');

            /** @see 7.2.8 */
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true(hash_equals($publicKeyCredentialRequestOptions->getChallenge(), $C->getChallenge()), 'Invalid challenge.');

            /** @see 7.2.9 */
            $rpId = $publicKeyCredentialRequestOptions->getRpId() ?? $request->getUri()->getHost();
            $facetId = $this->getFacetId($rpId, $publicKeyCredentialRequestOptions->getExtensions(), $authenticatorAssertionResponse->getAuthenticatorData()->getExtensions());
            $parsedRelyingPartyId = \Akeeba\Passwordless\Safe\parse_url($C->getOrigin());
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($parsedRelyingPartyId, 'Invalid origin');
            if (!in_array($facetId, $securedRelyingPartyId, true)) {
                $scheme = $parsedRelyingPartyId['scheme'] ?? '';
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq('https', $scheme, 'Invalid scheme. HTTPS required.');
            }
            $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notEmpty($clientDataRpId, 'Invalid origin rpId.');
            $rpIdLength = mb_strlen($facetId);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq(mb_substr('.'.$clientDataRpId, -($rpIdLength + 1)), '.'.$facetId, 'rpId mismatch.');

            /** @see 7.2.10 */
            if (null !== $C->getTokenBinding()) {
                $this->tokenBindingHandler->check($C->getTokenBinding(), $request);
            }

            $expectedRpIdHash = $isU2F ? $C->getOrigin() : $facetId;
            // u2f response has full origin in rpIdHash
            /** @see 7.2.11 */
            $rpIdHash = hash('sha256', $expectedRpIdHash, true);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true(hash_equals($rpIdHash, $authenticatorAssertionResponse->getAuthenticatorData()->getRpIdHash()), 'rpId hash mismatch.');

            /** @see 7.2.12 */
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($authenticatorAssertionResponse->getAuthenticatorData()->isUserPresent(), 'User was not present');
            /** @see 7.2.13 */
            if (\Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED === $publicKeyCredentialRequestOptions->getUserVerification()) {
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($authenticatorAssertionResponse->getAuthenticatorData()->isUserVerified(), 'User authentication required.');
            }

            /** @see 7.2.14 */
            $extensionsClientOutputs = $authenticatorAssertionResponse->getAuthenticatorData()->getExtensions();
            if (null !== $extensionsClientOutputs) {
                $this->extensionOutputCheckerHandler->check(
                    $publicKeyCredentialRequestOptions->getExtensions(),
                    $extensionsClientOutputs
                );
            }

            /** @see 7.2.15 */
            $getClientDataJSONHash = hash('sha256', $authenticatorAssertionResponse->getClientDataJSON()->getRawData(), true);

            /** @see 7.2.16 */
            $dataToVerify = $authenticatorAssertionResponse->getAuthenticatorData()->getAuthData().$getClientDataJSONHash;
            $signature = $authenticatorAssertionResponse->getSignature();
            $coseKey = new \Akeeba\Passwordless\Cose\Key\Key($credentialPublicKeyStream->getNormalizedData());
            $algorithm = $this->algorithmManager->get($coseKey->alg());
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($algorithm, \Akeeba\Passwordless\Cose\Algorithm\Signature\Signature::class, 'Invalid algorithm identifier. Should refer to a signature algorithm');
            $signature = \Akeeba\Passwordless\Webauthn\Util\CoseSignatureFixer::fix($signature, $algorithm);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($algorithm->verify($dataToVerify, $coseKey, $signature), 'Invalid signature.');

            /** @see 7.2.17 */
            $storedCounter = $publicKeyCredentialSource->getCounter();
            $responseCounter = $authenticatorAssertionResponse->getAuthenticatorData()->getSignCount();
            if (0 !== $responseCounter || 0 !== $storedCounter) {
                $this->counterChecker->check($publicKeyCredentialSource, $responseCounter);
            }
            $publicKeyCredentialSource->setCounter($responseCounter);
            $this->publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);

            /** @see 7.2.18 */
            //All good. We can continue.
            $this->logger->info('The assertion is valid');
            $this->logger->debug('Public Key Credential Source', ['publicKeyCredentialSource' => $publicKeyCredentialSource]);

            return $publicKeyCredentialSource;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function setCounterChecker(\Akeeba\Passwordless\Webauthn\Counter\CounterChecker $counterChecker): self
    {
        $this->counterChecker = $counterChecker;

        return $this;
    }

    /**
     * @param array<PublicKeyCredentialDescriptor> $allowedCredentials
     */
    private function isCredentialIdAllowed(string $credentialId, array $allowedCredentials): bool
    {
        foreach ($allowedCredentials as $allowedCredential) {
            if (hash_equals($allowedCredential->getId(), $credentialId)) {
                return true;
            }
        }

        return false;
    }

    private function getFacetId(string $rpId, \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs, ?\Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs $authenticationExtensionsClientOutputs): string
    {
        if (null === $authenticationExtensionsClientOutputs || !$authenticationExtensionsClientInputs->has('appid') || !$authenticationExtensionsClientOutputs->has('appid')) {
            return $rpId;
        }
        $appId = $authenticationExtensionsClientInputs->get('appid')->value();
        $wasUsed = $authenticationExtensionsClientOutputs->get('appid')->value();
        if (!is_string($appId) || true !== $wasUsed) {
            return $rpId;
        }

        return $appId;
    }
}
