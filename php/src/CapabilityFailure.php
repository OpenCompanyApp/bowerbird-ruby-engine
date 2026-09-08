<?php

declare(strict_types=1);

namespace Bowerbird\RubyEngine;

/**
 * Explicitly safe, host-authored diagnostic. Never wrap an arbitrary upstream
 * exception message in this type: provider payloads and credentials stay private.
 * The code is advisory, not authority to retry or bypass approvals.
 */
final class CapabilityFailure extends \RuntimeException
{
    public function __construct(public readonly string $errorType, string $safeMessage)
    {
        if (!preg_match('/^[a-z][a-z0-9_]{0,62}$/D', $errorType)) {
            throw new \InvalidArgumentException('Invalid capability diagnostic code.');
        }
        parent::__construct($safeMessage);
    }
}
