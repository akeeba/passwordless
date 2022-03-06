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

namespace Akeeba\Passwordless\Webauthn\MetadataService;

use Akeeba\Passwordless\Assert\Assertion;
use Akeeba\Passwordless\Base64Url\Base64Url;
use function count;
use InvalidArgumentException;
use function is_array;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Akeeba\Passwordless\League\Uri\UriString;
use LogicException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use function Akeeba\Passwordless\Safe\json_decode;
use function Akeeba\Passwordless\Safe\sprintf;
use Throwable;
use Akeeba\Passwordless\Webauthn\CertificateToolbox;

class MetadataService
{
    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var array
     */
    private $additionalQueryStringValues;

    /**
     * @var array
     */
    private $additionalHeaders;

    /**
     * @var string
     */
    private $serviceUri;

    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(string $serviceUri, ClientInterface $httpClient, RequestFactoryInterface $requestFactory, array $additionalQueryStringValues = [], array $additionalHeaders = [], ?LoggerInterface $logger = null)
    {
        if (0 !== count($additionalQueryStringValues)) {
            @trigger_error('The argument "additionalQueryStringValues" is deprecated since version 3.3 and will be removed in 4.0. Please set an empty array instead and us the method `addQueryStringValues`.', E_USER_DEPRECATED);
        }
        if (0 !== count($additionalQueryStringValues)) {
            @trigger_error('The argument "additionalHeaders" is deprecated since version 3.3 and will be removed in 4.0. Please set an empty array instead and us the method `addHeaders`.', E_USER_DEPRECATED);
        }
        if (null !== $logger) {
            @trigger_error('The argument "logger" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setLogger" instead.', E_USER_DEPRECATED);
        }
        $this->serviceUri = $serviceUri;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->additionalQueryStringValues = $additionalQueryStringValues;
        $this->additionalHeaders = $additionalHeaders;
        $this->logger = $logger ?? new NullLogger();
    }

    public function addQueryStringValues(array $additionalQueryStringValues): self
    {
        $this->additionalQueryStringValues = $additionalQueryStringValues;

        return $this;
    }

    public function addHeaders(array $additionalHeaders): self
    {
        $this->additionalHeaders = $additionalHeaders;

        return $this;
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function has(string $aaguid): bool
    {
        try {
            $toc = $this->fetchMetadataTOCPayload();
        } catch (Throwable $e) {
            return false;
        }
        foreach ($toc->getEntries() as $entry) {
            if ($entry->getAaguid() === $aaguid && null !== $entry->getUrl()) {
                return true;
            }
        }

        return false;
    }

    public function get(string $aaguid): \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement
    {
        $toc = $this->fetchMetadataTOCPayload();
        foreach ($toc->getEntries() as $entry) {
            if ($entry->getAaguid() === $aaguid && null !== $entry->getUrl()) {
                $mds = $this->fetchMetadataStatementFor($entry);
                $mds
                    ->setStatusReports($entry->getStatusReports())
                    ->setRootCertificates($toc->getRootCertificates())
                ;

                return $mds;
            }
        }

        throw new InvalidArgumentException(\Akeeba\Passwordless\Safe\sprintf('The Metadata Statement with AAGUID "%s" is missing', $aaguid));
    }

    /**
     * @deprecated This method is deprecated since v3.3 and will be removed in v4.0
     */
    public function getMetadataStatementFor(\Akeeba\Passwordless\Webauthn\MetadataService\MetadataTOCPayloadEntry $entry, string $hashingFunction = 'sha256'): \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement
    {
        return $this->fetchMetadataStatementFor($entry, $hashingFunction);
    }

    public function fetchMetadataStatementFor(\Akeeba\Passwordless\Webauthn\MetadataService\MetadataTOCPayloadEntry $entry, string $hashingFunction = 'sha256'): \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement
    {
        $this->logger->info('Trying to get the metadata statement for a given entry', ['entry' => $entry]);
        try {
            $hash = $entry->getHash();
            $url = $entry->getUrl();
            if (null === $hash || null === $url) {
                throw new LogicException('The Metadata Statement has not been published');
            }
            $uri = $this->buildUri($url);
            $result = $this->fetchMetadataStatement($uri, true, $hash, $hashingFunction);
            $this->logger->info('The metadata statement exists');
            $this->logger->debug('Metadata Statement', ['mds' => $result]);

            return $result;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    /**
     * @deprecated This method is deprecated since v3.3 and will be removed in v4.0
     */
    public function getMetadataTOCPayload(): \Akeeba\Passwordless\Webauthn\MetadataService\MetadataTOCPayload
    {
        return $this->fetchMetadataTOCPayload();
    }

    private function fetchMetadataTOCPayload(): \Akeeba\Passwordless\Webauthn\MetadataService\MetadataTOCPayload
    {
        $this->logger->info('Trying to get the metadata service TOC payload');
        try {
            $uri = $this->buildUri($this->serviceUri);
            $toc = $this->fetchTableOfContent($uri);
            $this->logger->info('The TOC payload has been received');
            $this->logger->debug('TOC payload', ['toc' => $toc]);

            return $toc;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    private function buildUri(string $uri): string
    {
        $parsedUri = \Akeeba\Passwordless\League\Uri\UriString::parse($uri);
        $queryString = $parsedUri['query'];
        $query = [];
        if (null !== $queryString) {
            parse_str($queryString, $query);
        }
        foreach ($this->additionalQueryStringValues as $k => $v) {
            if (!isset($query[$k])) {
                $query[$k] = $v;
                continue;
            }
            if (!is_array($query[$k])) {
                $query[$k] = [$query[$k], $v];
                continue;
            }
            $query[$k][] = $v;
        }
        $parsedUri['query'] = 0 === count($query) ? null : http_build_query($query, '', '&', PHP_QUERY_RFC3986);

        return \Akeeba\Passwordless\League\Uri\UriString::build($parsedUri);
    }

    private function fetchTableOfContent(string $uri): \Akeeba\Passwordless\Webauthn\MetadataService\MetadataTOCPayload
    {
        $content = $this->fetch($uri);
        $rootCertificates = [];
        $payload = $this->getJwsPayload($content, $rootCertificates);
        $data = \Akeeba\Passwordless\Safe\json_decode($payload, true);

        $toc = \Akeeba\Passwordless\Webauthn\MetadataService\MetadataTOCPayload::createFromArray($data);
        $toc->setRootCertificates($rootCertificates);

        return $toc;
    }

    private function fetchMetadataStatement(string $uri, bool $isBase64UrlEncoded, string $hash = '', string $hashingFunction = 'sha256'): \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement
    {
        $payload = $this->fetch($uri);
        if ('' !== $hash) {
            \Akeeba\Passwordless\Assert\Assertion::true(hash_equals($hash, hash($hashingFunction, $payload, true)), 'The hash cannot be verified. The metadata statement shall be rejected');
        }
        $json = $isBase64UrlEncoded ? Base64Url::decode($payload) : $payload;
        $data = \Akeeba\Passwordless\Safe\json_decode($json, true);

        return \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement::createFromArray($data);
    }

    private function fetch(string $uri): string
    {
        $request = $this->requestFactory->createRequest('GET', $uri);
        foreach ($this->additionalHeaders as $k => $v) {
            $request = $request->withHeader($k, $v);
        }
        $response = $this->httpClient->sendRequest($request);
        \Akeeba\Passwordless\Assert\Assertion::eq(200, $response->getStatusCode(), \Akeeba\Passwordless\Safe\sprintf('Unable to contact the server. Response code is %d', $response->getStatusCode()));
        $content = $response->getBody()->getContents();
        \Akeeba\Passwordless\Assert\Assertion::notEmpty($content, 'Unable to contact the server. The response has no content');

        return $content;
    }

    private function getJwsPayload(string $token, array &$rootCertificates): string
    {
        $jws = (new CompactSerializer())->unserialize($token);
        \Akeeba\Passwordless\Assert\Assertion::eq(1, $jws->countSignatures(), 'Invalid response from the metadata service. Only one signature shall be present.');
        $signature = $jws->getSignature(0);
        $payload = $jws->getPayload();
        \Akeeba\Passwordless\Assert\Assertion::notEmpty($payload, 'Invalid response from the metadata service. The token payload is empty.');
        $header = $signature->getProtectedHeader();
        \Akeeba\Passwordless\Assert\Assertion::keyExists($header, 'alg', 'The "alg" parameter is missing.');
        \Akeeba\Passwordless\Assert\Assertion::eq($header['alg'], 'ES256', 'The expected "alg" parameter value should be "ES256".');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($header, 'x5c', 'The "x5c" parameter is missing.');
        \Akeeba\Passwordless\Assert\Assertion::isArray($header['x5c'], 'The "x5c" parameter should be an array.');
        $key = JWKFactory::createFromX5C($header['x5c']);
        $rootCertificates = array_map(static function (string $x509): string {
            return \Akeeba\Passwordless\Webauthn\CertificateToolbox::fixPEMStructure($x509);
        }, $header['x5c']);
        $algorithm = new ES256();
        $isValid = $algorithm->verify($key, $signature->getEncodedProtectedHeader().'.'.$jws->getEncodedPayload(), $signature->getSignature());
        \Akeeba\Passwordless\Assert\Assertion::true($isValid, 'Invalid response from the metadata service. The token signature is invalid.');

        return $jws->getPayload();
    }
}
