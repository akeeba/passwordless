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

namespace Akeeba\Passwordless\Webauthn\CertificateChainChecker;

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use function count;
use InvalidArgumentException;
use function is_int;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use Akeeba\Passwordless\Safe\Exceptions\FilesystemException;
use function Akeeba\Passwordless\Safe\file_put_contents;
use function Akeeba\Passwordless\Safe\ksort;
use function Akeeba\Passwordless\Safe\mkdir;
use function Akeeba\Passwordless\Safe\rename;
use function Akeeba\Passwordless\Safe\sprintf;
use function Akeeba\Passwordless\Safe\tempnam;
use function Akeeba\Passwordless\Safe\unlink;
use Akeeba\Passwordless\Symfony\Component\Process\Process;

final class OpenSSLCertificateChainChecker implements \Akeeba\Passwordless\Webauthn\CertificateChainChecker\CertificateChainChecker
{
    /**
     * @var ClientInterface
     */
    private $client;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var string[]
     */
    private $rootCertificates = [];

    public function __construct(ClientInterface $client, RequestFactoryInterface $requestFactory)
    {
        $this->client = $client;
        $this->requestFactory = $requestFactory;
    }

    public function addRootCertificate(string $certificate): self
    {
        $this->rootCertificates[] = $certificate;

        return $this;
    }

    /**
     * @param string[] $authenticatorCertificates
     * @param string[] $trustedCertificates
     */
    public function check(array $authenticatorCertificates, array $trustedCertificates): void
    {
        if (0 === count($trustedCertificates)) {
            $this->checkCertificatesValidity($authenticatorCertificates, true);

            return;
        }
        $this->checkCertificatesValidity($authenticatorCertificates, false);

        $hasCrls = false;
        $processArguments = ['-no-CAfile', '-no-CApath'];

        $caDirname = $this->createTemporaryDirectory();
        $processArguments[] = '--CApath';
        $processArguments[] = $caDirname;

        foreach ($trustedCertificates as $certificate) {
            $this->saveToTemporaryFile($caDirname, $certificate, 'webauthn-trusted-', '.pem');
            $crl = $this->getCrls($certificate);
            if ('' !== $crl) {
                $hasCrls = true;
                $this->saveToTemporaryFile($caDirname, $crl, 'webauthn-trusted-crl-', '.crl');
            }
        }

        $rehashProcess = new \Akeeba\Passwordless\Symfony\Component\Process\Process(['openssl', 'rehash', $caDirname]);
        $rehashProcess->run();
        while ($rehashProcess->isRunning()) {
            //Just wait
        }
        if (!$rehashProcess->isSuccessful()) {
            throw new InvalidArgumentException('Invalid certificate or certificate chain');
        }

        $filenames = [];
        $leafCertificate = array_shift($authenticatorCertificates);
        $leafFilename = $this->saveToTemporaryFile(sys_get_temp_dir(), $leafCertificate, 'webauthn-leaf-', '.pem');
        $crl = $this->getCrls($leafCertificate);
        if ('' !== $crl) {
            $hasCrls = true;
            $this->saveToTemporaryFile($caDirname, $crl, 'webauthn-leaf-crl-', '.pem');
        }
        $filenames[] = $leafFilename;

        foreach ($authenticatorCertificates as $certificate) {
            $untrustedFilename = $this->saveToTemporaryFile(sys_get_temp_dir(), $certificate, 'webauthn-untrusted-', '.pem');
            $crl = $this->getCrls($certificate);
            if ('' !== $crl) {
                $hasCrls = true;
                $this->saveToTemporaryFile($caDirname, $crl, 'webauthn-untrusted-crl-', '.pem');
            }
            $processArguments[] = '-untrusted';
            $processArguments[] = $untrustedFilename;
            $filenames[] = $untrustedFilename;
        }

        $processArguments[] = $leafFilename;
        if ($hasCrls) {
            array_unshift($processArguments, '-crl_check');
            array_unshift($processArguments, '-crl_check_all');
            //array_unshift($processArguments, '-crl_download');
            array_unshift($processArguments, '-extended_crl');
        }
        array_unshift($processArguments, 'openssl', 'verify');

        $process = new \Akeeba\Passwordless\Symfony\Component\Process\Process($processArguments);
        $process->run();
        while ($process->isRunning()) {
            //Just wait
        }

        foreach ($filenames as $filename) {
            try {
                \Akeeba\Passwordless\Safe\unlink($filename);
            } catch (\Akeeba\Passwordless\Safe\Exceptions\FilesystemException $e) {
                continue;
            }
        }
        $this->deleteDirectory($caDirname);

        if (!$process->isSuccessful()) {
            throw new InvalidArgumentException('Invalid certificate or certificate chain');
        }
    }

    /**
     * @param string[] $certificates
     */
    private function checkCertificatesValidity(array $certificates, bool $allowRootCertificate): void
    {
        foreach ($certificates as $certificate) {
            $parsed = openssl_x509_parse($certificate);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($parsed, 'Unable to read the certificate');
            if (false === $allowRootCertificate) {
                $this->checkRootCertificate($parsed);
            }

            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($parsed, 'validTo_time_t', 'The certificate has no validity period');
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($parsed, 'validFrom_time_t', 'The certificate has no validity period');
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::lessOrEqualThan(time(), $parsed['validTo_time_t'], 'The certificate expired');
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::greaterOrEqualThan(time(), $parsed['validFrom_time_t'], 'The certificate is not usable yet');
        }
    }

    /**
     * @param array<string, mixed> $parsed
     */
    private function checkRootCertificate(array $parsed): void
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($parsed, 'subject', 'The certificate has no subject');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($parsed, 'issuer', 'The certificate has no issuer');
        $subject = $parsed['subject'];
        $issuer = $parsed['issuer'];
        \Akeeba\Passwordless\Safe\ksort($subject);
        \Akeeba\Passwordless\Safe\ksort($issuer);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notEq($subject, $issuer, 'Root certificates are not allowed');
    }

    private function createTemporaryDirectory(): string
    {
        $caDir = \Akeeba\Passwordless\Safe\tempnam(sys_get_temp_dir(), 'webauthn-ca-');
        if (file_exists($caDir)) {
            \Akeeba\Passwordless\Safe\unlink($caDir);
        }
        \Akeeba\Passwordless\Safe\mkdir($caDir);
        if (!is_dir($caDir)) {
            throw new RuntimeException(\Akeeba\Passwordless\Safe\sprintf('Directory "%s" was not created', $caDir));
        }

        return $caDir;
    }

    private function deleteDirectory(string $dirname): void
    {
        $rehashProcess = new \Akeeba\Passwordless\Symfony\Component\Process\Process(['rm', '-rf', $dirname]);
        $rehashProcess->run();
        while ($rehashProcess->isRunning()) {
            //Just wait
        }
    }

    private function saveToTemporaryFile(string $folder, string $certificate, string $prefix, string $suffix): string
    {
        $filename = \Akeeba\Passwordless\Safe\tempnam($folder, $prefix);
        \Akeeba\Passwordless\Safe\rename($filename, $filename.$suffix);
        \Akeeba\Passwordless\Safe\file_put_contents($filename.$suffix, $certificate, FILE_APPEND);

        return $filename.$suffix;
    }

    private function getCrls(string $certificate): string
    {
        $parsed = openssl_x509_parse($certificate);
        if (false === $parsed || !isset($parsed['extensions']['crlDistributionPoints'])) {
            return '';
        }
        $endpoint = $parsed['extensions']['crlDistributionPoints'];
        $pos = mb_strpos($endpoint, 'URI:');
        if (!is_int($pos)) {
            return '';
        }

        $endpoint = trim(mb_substr($endpoint, $pos + 4));
        $request = $this->requestFactory->createRequest('GET', $endpoint);
        $response = $this->client->sendRequest($request);

        if (200 !== $response->getStatusCode()) {
            return '';
        }

        return $response->getBody()->getContents();
    }
}
