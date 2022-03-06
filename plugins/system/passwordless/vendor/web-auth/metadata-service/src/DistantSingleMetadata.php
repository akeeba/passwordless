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
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use function Akeeba\Passwordless\Safe\json_decode;
use function Akeeba\Passwordless\Safe\sprintf;

class DistantSingleMetadata extends \Akeeba\Passwordless\Webauthn\MetadataService\SingleMetadata
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
    private $additionalHeaders;

    /**
     * @var string
     */
    private $uri;

    /**
     * @var bool
     */
    private $isBase64Encoded;

    public function __construct(string $uri, bool $isBase64Encoded, ClientInterface $httpClient, RequestFactoryInterface $requestFactory, array $additionalHeaders = [])
    {
        parent::__construct($uri, $isBase64Encoded); //Useless
        $this->uri = $uri;
        $this->isBase64Encoded = $isBase64Encoded;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->additionalHeaders = $additionalHeaders;
    }

    public function getMetadataStatement(): \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement
    {
        $payload = $this->fetch();
        $json = $this->isBase64Encoded ? \Akeeba\Passwordless\Base64Url\Base64Url::decode($payload) : $payload;
        $data = \Akeeba\Passwordless\Safe\json_decode($json, true);

        return \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement::createFromArray($data);
    }

    private function fetch(): string
    {
        $request = $this->requestFactory->createRequest('GET', $this->uri);
        foreach ($this->additionalHeaders as $k => $v) {
            $request = $request->withHeader($k, $v);
        }
        $response = $this->httpClient->sendRequest($request);
        \Akeeba\Passwordless\Assert\Assertion::eq(200, $response->getStatusCode(), \Akeeba\Passwordless\Safe\sprintf('Unable to contact the server. Response code is %d', $response->getStatusCode()));
        $content = $response->getBody()->getContents();
        \Akeeba\Passwordless\Assert\Assertion::notEmpty($content, 'Unable to contact the server. The response has no content');

        return $content;
    }
}
