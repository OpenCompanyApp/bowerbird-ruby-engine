<?php

declare(strict_types=1);

namespace Bowerbird\RubyEngine;

/**
 * Immutable guest outcome. Delivery/approval/retry authority belongs to the
 * application host; this value deliberately does not declare effects safe to retry.
 */
final readonly class Execution
{
    /**
     * @param list<array<mixed>> $logs Bounded structured log entries, not protocol output
     * @param array<string,mixed>|null $error Guest or adapter diagnostic; not raw provider exceptions
     * @param array<string,mixed> $usage Reported guest usage; absent metrics are not invented
     */
    public function __construct(
        public string $executionId,
        public mixed $result,
        public ?array $error,
        public array $logs,
        public array $usage,
        public bool $validatedOnly,
        public float $wallMilliseconds,
    ) {}
}
