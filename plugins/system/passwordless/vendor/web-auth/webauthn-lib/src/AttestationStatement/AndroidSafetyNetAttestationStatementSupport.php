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

namespace Akeeba\Passwordless\Webauthn\AttestationStatement;

use Akeeba\Passwordless\Assert\Assertion;
use InvalidArgumentException;
use Jose\Component\Core\Algorithm as AlgorithmInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use function Akeeba\Passwordless\Safe\json_decode;
use function Akeeba\Passwordless\Safe\sprintf;
use Akeeba\Passwordless\Webauthn\AuthenticatorData;
use Akeeba\Passwordless\Webauthn\CertificateToolbox;
use Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath;

final class AndroidSafetyNetAttestationStatementSupport implements \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupport
{
    /**
     * @var string|null
     */
    private $apiKey;

    /**
     * @var ClientInterface|null
     */
    private $client;

    /**
     * @var CompactSerializer
     */
    private $jwsSerializer;

    /**
     * @var JWSVerifier|null
     */
    private $jwsVerifier;

    /**
     * @var RequestFactoryInterface|null
     */
    private $requestFactory;

    /**
     * @var int
     */
    private $leeway;

    /**
     * @var int
     */
    private $maxAge;

    public function __construct(?ClientInterface $client = null, ?string $apiKey = null, ?RequestFactoryInterface $requestFactory = null, ?int $leeway = null, ?int $maxAge = null)
    {
        if (!class_exists(Algorithm\RS256::class)) {
            throw new RuntimeException('The algorithm RS256 is missing. Did you forget to install the package web-token/jwt-signature-algorithm-rsa?');
        }
        if (!class_exists(JWKFactory::class)) {
            throw new RuntimeException('The class Jose\Component\KeyManagement\JWKFactory is missing. Did you forget to install the package web-token/jwt-key-mgmt?');
        }
        if (null !== $client) {
            @trigger_error('The argument "client" is deprecated since version 3.3 and will be removed in 4.0. Please set `null` instead and use the method "enableApiVerification".', E_USER_DEPRECATED);
        }
        if (null !== $apiKey) {
            @trigger_error('The argument "apiKey" is deprecated since version 3.3 and will be removed in 4.0. Please set `null` instead and use the method "enableApiVerification".', E_USER_DEPRECATED);
        }
        if (null !== $requestFactory) {
            @trigger_error('The argument "requestFactory" is deprecated since version 3.3 and will be removed in 4.0. Please set `null` instead and use the method "enableApiVerification".', E_USER_DEPRECATED);
        }
        if (null !== $maxAge) {
            @trigger_error('The argument "maxAge" is deprecated since version 3.3 and will be removed in 4.0. Please set `null` instead and use the method "setMaxAge".', E_USER_DEPRECATED);
        }
        if (null !== $leeway) {
            @trigger_error('The argument "leeway" is deprecated since version 3.3 and will be removed in 4.0. Please set `null` instead and use the method "setLeeway".', E_USER_DEPRECATED);
        }
        $this->jwsSerializer = new CompactSerializer();
        $this->initJwsVerifier();

        //To be removed in 4.0
        $this->leeway = $leeway ?? 0;
        $this->maxAge = $maxAge ?? 60000;
        $this->apiKey = $apiKey;
        $this->client = $client;
        $this->requestFactory = $requestFactory;
    }

    public function enableApiVerification(ClientInterface $client, string $apiKey, RequestFactoryInterface $requestFactory): self
    {
        $this->apiKey = $apiKey;
        $this->client = $client;
        $this->requestFactory = $requestFactory;

        return $this;
    }

    public function setMaxAge(int $maxAge): self
    {
        $this->maxAge = $maxAge;

        return $this;
    }

    public function setLeeway(int $leeway): self
    {
        $this->leeway = $leeway;

        return $this;
    }

    public function name(): string
    {
        return 'android-safetynet';
    }

    /**
     * @param mixed[] $attestation
     */
    public function load(array $attestation): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement
    {
        \Akeeba\Passwordless\Assert\Assertion::keyExists($attestation, 'attStmt', 'Invalid attestation object');
        foreach (['ver', 'response'] as $key) {
            \Akeeba\Passwordless\Assert\Assertion::keyExists($attestation['attStmt'], $key, \Akeeba\Passwordless\Safe\sprintf('The attestation statement value "%s" is missing.', $key));
            \Akeeba\Passwordless\Assert\Assertion::notEmpty($attestation['attStmt'][$key], \Akeeba\Passwordless\Safe\sprintf('The attestation statement value "%s" is empty.', $key));
        }
        $jws = $this->jwsSerializer->unserialize($attestation['attStmt']['response']);
        $jwsHeader = $jws->getSignature(0)->getProtectedHeader();
        \Akeeba\Passwordless\Assert\Assertion::keyExists($jwsHeader, 'x5c', 'The response in the attestation statement must contain a "x5c" header.');
        \Akeeba\Passwordless\Assert\Assertion::notEmpty($jwsHeader['x5c'], 'The "x5c" parameter in the attestation statement response must contain at least one certificate.');
        $certificates = $this->convertCertificatesToPem($jwsHeader['x5c']);
        $attestation['attStmt']['jws'] = $jws;

        return \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::createBasic(
            $this->name(),
            $attestation['attStmt'],
            new \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath($certificates)
        );
    }

    public function isValid(string $clientDataJSONHash, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attestationStatement, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData): bool
    {
        $trustPath = $attestationStatement->getTrustPath();
        \Akeeba\Passwordless\Assert\Assertion::isInstanceOf($trustPath, \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath::class, 'Invalid trust path');
        $certificates = $trustPath->getCertificates();
        $firstCertificate = current($certificates);
        \Akeeba\Passwordless\Assert\Assertion::string($firstCertificate, 'No certificate');

        $parsedCertificate = openssl_x509_parse($firstCertificate);
        \Akeeba\Passwordless\Assert\Assertion::isArray($parsedCertificate, 'Invalid attestation object');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($parsedCertificate, 'subject', 'Invalid attestation object');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($parsedCertificate['subject'], 'CN', 'Invalid attestation object');
        \Akeeba\Passwordless\Assert\Assertion::eq($parsedCertificate['subject']['CN'], 'attest.android.com', 'Invalid attestation object');

        /** @var JWS $jws */
        $jws = $attestationStatement->get('jws');
        $payload = $jws->getPayload();
        $this->validatePayload($payload, $clientDataJSONHash, $authenticatorData);

        //Check the signature
        $this->validateSignature($jws, $trustPath);

        //Check against Google service
        $this->validateUsingGoogleApi($attestationStatement);

        return true;
    }

    private function validatePayload(?string $payload, string $clientDataJSONHash, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData): void
    {
        \Akeeba\Passwordless\Assert\Assertion::notNull($payload, 'Invalid attestation object');
        $payload = JsonConverter::decode($payload);
        \Akeeba\Passwordless\Assert\Assertion::isArray($payload, 'Invalid attestation object');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($payload, 'nonce', 'Invalid attestation object. "nonce" is missing.');
        \Akeeba\Passwordless\Assert\Assertion::eq($payload['nonce'], base64_encode(hash('sha256', $authenticatorData->getAuthData().$clientDataJSONHash, true)), 'Invalid attestation object. Invalid nonce');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($payload, 'ctsProfileMatch', 'Invalid attestation object. "ctsProfileMatch" is missing.');
        \Akeeba\Passwordless\Assert\Assertion::true($payload['ctsProfileMatch'], 'Invalid attestation object. "ctsProfileMatch" value is false.');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($payload, 'timestampMs', 'Invalid attestation object. Timestamp is missing.');
        \Akeeba\Passwordless\Assert\Assertion::integer($payload['timestampMs'], 'Invalid attestation object. Timestamp shall be an integer.');
        $currentTime = time() * 1000;
        \Akeeba\Passwordless\Assert\Assertion::lessOrEqualThan($payload['timestampMs'], $currentTime + $this->leeway, \Akeeba\Passwordless\Safe\sprintf('Invalid attestation object. Issued in the future. Current time: %d. Response time: %d', $currentTime, $payload['timestampMs']));
        \Akeeba\Passwordless\Assert\Assertion::lessOrEqualThan($currentTime - $payload['timestampMs'], $this->maxAge, \Akeeba\Passwordless\Safe\sprintf('Invalid attestation object. Too old. Current time: %d. Response time: %d', $currentTime, $payload['timestampMs']));
    }

    private function validateSignature(JWS $jws, \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath $trustPath): void
    {
        $jwk = JWKFactory::createFromCertificate($trustPath->getCertificates()[0]);
        $isValid = $this->jwsVerifier->verifyWithKey($jws, $jwk, 0);
        \Akeeba\Passwordless\Assert\Assertion::true($isValid, 'Invalid response signature');
    }

    private function validateUsingGoogleApi(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attestationStatement): void
    {
        if (null === $this->client || null === $this->apiKey || null === $this->requestFactory) {
            return;
        }
        $uri = \Akeeba\Passwordless\Safe\sprintf('https://www.googleapis.com/androidcheck/v1/attestations/verify?key=%s', urlencode($this->apiKey));
        $requestBody = \Akeeba\Passwordless\Safe\sprintf('{"signedAttestation":"%s"}', $attestationStatement->get('response'));
        $request = $this->requestFactory->createRequest('POST', $uri);
        $request = $request->withHeader('content-type', 'application/json');
        $request->getBody()->write($requestBody);

        $response = $this->client->sendRequest($request);
        $this->checkGoogleApiResponse($response);
        $responseBody = $this->getResponseBody($response);
        $responseBodyJson = \Akeeba\Passwordless\Safe\json_decode($responseBody, true);
        \Akeeba\Passwordless\Assert\Assertion::keyExists($responseBodyJson, 'isValidSignature', 'Invalid response.');
        \Akeeba\Passwordless\Assert\Assertion::boolean($responseBodyJson['isValidSignature'], 'Invalid response.');
        \Akeeba\Passwordless\Assert\Assertion::true($responseBodyJson['isValidSignature'], 'Invalid response.');
    }

    private function getResponseBody(ResponseInterface $response): string
    {
        $responseBody = '';
        $response->getBody()->rewind();
        while (true) {
            $tmp = $response->getBody()->read(1024);
            if ('' === $tmp) {
                break;
            }
            $responseBody .= $tmp;
        }

        return $responseBody;
    }

    private function checkGoogleApiResponse(ResponseInterface $response): void
    {
        \Akeeba\Passwordless\Assert\Assertion::eq(200, $response->getStatusCode(), 'Request did not succeeded');
        \Akeeba\Passwordless\Assert\Assertion::true($response->hasHeader('content-type'), 'Unrecognized response');

        foreach ($response->getHeader('content-type') as $header) {
            if (0 === mb_strpos($header, 'application/json')) {
                return;
            }
        }

        throw new InvalidArgumentException('Unrecognized response');
    }

    /**
     * @param string[] $certificates
     *
     * @return string[]
     */
    private function convertCertificatesToPem(array $certificates): array
    {
        foreach ($certificates as $k => $v) {
            $certificates[$k] = \Akeeba\Passwordless\Webauthn\CertificateToolbox::fixPEMStructure($v);
        }

        return $certificates;
    }

    private function initJwsVerifier(): void
    {
        $algorithmClasses = [
            Algorithm\RS256::class, Algorithm\RS384::class, Algorithm\RS512::class,
            Algorithm\PS256::class, Algorithm\PS384::class, Algorithm\PS512::class,
            Algorithm\ES256::class, Algorithm\ES384::class, Algorithm\ES512::class,
            Algorithm\EdDSA::class,
        ];
        /* @var AlgorithmInterface[] $algorithms */
        $algorithms = [];
        foreach ($algorithmClasses as $algorithm) {
            if (class_exists($algorithm)) {
                /* @var AlgorithmInterface $algorithm */
                $algorithms[] = new $algorithm();
            }
        }
        $algorithmManager = new AlgorithmManager($algorithms);
        $this->jwsVerifier = new JWSVerifier($algorithmManager);
    }
}
