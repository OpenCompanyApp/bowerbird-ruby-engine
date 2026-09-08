<?php

declare(strict_types=1);

namespace Bowerbird\RubyEngine;

use Closure;
use JsonException;
use RuntimeException;
use Throwable;

/**
 * Owns one isolated engine invocation and bounded, identity-checked IPC.
 *
 * The application supplies already-scoped capabilities. Each closure must still
 * perform current actor/workspace/approval checks and record effect disposition.
 * Neither a catalog entry nor successful compilation grants execution authority.
 * The engine receives no PHP environment, credentials, model instance or callback code.
 */
final class Client
{
    private const MAX_FRAME = 8 * 1024 * 1024;

    public function __construct(private readonly string $binary, private readonly ?string $expectedSha256 = null)
    {
        if (!str_starts_with($binary, '/') || !is_file($binary) || !is_executable($binary)) {
            throw new RuntimeException('Configure an absolute, executable Ruby engine artifact path.');
        }
        if ($expectedSha256 !== null && (!preg_match('/^[a-f0-9]{64}$/D', $expectedSha256)
            || !hash_equals($expectedSha256, hash_file('sha256', $binary)))) {
            throw new RuntimeException('Ruby engine artifact digest mismatch.');
        }
    }

    /**
     * Execute or compile one Ruby source. Callbacks run synchronously in PHP;
     * provider HTTP deadlines remain the application's responsibility. A killed
     * guest cannot undo or prove cancellation of a dispatched external mutation.
     *
     * @param array<string,Closure(array<mixed>):mixed> $capabilities Exact catalog paths to guarded invokers
     * @param array<string,mixed> $globals Data-only ctx input, not executable bootstrap source
     * @param array<string,int> $limits Host-owned settings, never agent-supplied authority
     * @param Closure():bool|null $cancelled Host cancellation check, evaluated between protocol events
     */
    public function execute(
        string $source,
        array $capabilities = [],
        array $globals = [],
        bool $validateOnly = false,
        array $limits = [],
        ?Closure $cancelled = null,
        string $filename = 'opencompany-code.rb',
    ): Execution {
        $executionId = bin2hex(random_bytes(16));
        $started = hrtime(true);
        $limits = array_replace([
            'memory_bytes' => 32 * 1024 * 1024, 'instructions' => 10_000_000,
            'wall_ms' => 5000, 'cpu_ms' => 1000, 'source_bytes' => 256 * 1024, 'result_bytes' => 1024 * 1024,
            'calls' => 50, 'log_bytes' => 64 * 1024,
        ], $limits);
        $deadline = $started + (($limits['wall_ms'] + 1000) * 1_000_000);
        $logs = [];
        $logBytes = 0;
        $sequence = 0;
        $process = null;
        $pipes = [];

        try {
            // Array-form proc_open bypasses the shell. An empty environment
            // prevents inherited application credentials reaching the supervisor.
            $process = proc_open([$this->binary], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes, '/', [], ['bypass_shell' => true]);
            if (!is_resource($process)) {
                throw new RuntimeException('Unable to start the Ruby engine.');
            }
            foreach ($pipes as $pipe) {
                stream_set_blocking($pipe, false);
            }
            $request = ['protocol' => 'ruby-local-v1', 'profile' => 'opencompany-code-v1',
                'execution_id' => $executionId, 'source' => $source, 'filename' => $filename,
                'validate_only' => $validateOnly, 'globals' => (object) $globals,
                'catalog' => array_keys($capabilities), 'limits' => $limits];
            $this->writeFrame($pipes[0], $request, $deadline, $cancelled);

            while (true) {
                $event = $this->readFrame($pipes[1], $deadline, $cancelled);
                if (($event->protocol ?? null) !== 'ruby-local-v1'
                    || ($event->execution_id ?? null) !== $executionId) {
                    throw new RuntimeException('Ruby engine identity/protocol mismatch.');
                }
                switch ($event->kind ?? null) {
                    case 'log':
                        if (!is_array($event->values ?? null)) {
                            throw new RuntimeException('Malformed engine log.');
                        }
                        $logBytes += strlen(json_encode($event->values, JSON_THROW_ON_ERROR));
                        if ($logBytes > $limits['log_bytes']) {
                            throw new RuntimeException('Engine log budget exceeded.');
                        }
                        $logs[] = $event->values;
                        break;
                    case 'call':
                        if ($validateOnly || ($event->sequence ?? null) !== ++$sequence
                            || $sequence > $limits['calls'] || !is_string($event->path ?? null)
                            || !is_array($event->args ?? null) || !isset($capabilities[$event->path])) {
                            throw new RuntimeException('Invalid or unavailable engine capability request.');
                        }
                        $this->checkpoint($deadline, $cancelled);
                        try {
                            $value = $capabilities[$event->path]($event->args);
                            $reply = ['ok' => true, 'value' => $value];
                        } catch (CapabilityFailure $failure) {
                            $reply = ['ok' => false, 'code' => $failure->errorType, 'message' => $failure->getMessage()];
                        } catch (Throwable) {
                            // Provider exception text may contain secrets. The
                            // host keeps the original failure in its private trace.
                            $reply = ['ok' => false, 'message' => 'Capability failed; inspect the host trace before retrying.'];
                        }
                        $this->writeFrame($pipes[0], ['protocol' => 'ruby-local-v1', 'execution_id' => $executionId,
                            'kind' => 'reply', 'sequence' => $sequence, ...$reply], $deadline, $cancelled);
                        break;
                    case 'completed':
                        if (($event->error ?? null) !== null && !is_object($event->error)) {
                            throw new RuntimeException('Malformed engine diagnostic.');
                        }
                        return new Execution($executionId, $event->result ?? null,
                            isset($event->error) ? (array) $event->error : null, $logs,
                            (array) ($event->usage ?? []), $validateOnly, (hrtime(true) - $started) / 1_000_000);
                    default:
                        throw new RuntimeException('Unknown engine protocol event.');
                }
            }
        } catch (Throwable $exception) {
            return new Execution($executionId, null, ['type' => 'host_transport_error',
                'message' => $exception instanceof JsonException ? 'Invalid structured data at the engine boundary.' : $exception->getMessage()],
                $logs, [], $validateOnly, (hrtime(true) - $started) / 1_000_000);
        } finally {
            // Always close the process, including callback, cancellation,
            // malformed-frame and broken-pipe failures. Never reuse a guest VM.
            foreach ($pipes as $pipe) {
                if (is_resource($pipe)) {
                    fclose($pipe);
                }
            }
            if (is_resource($process)) {
                // EOF is the supervisor's cancellation signal. Allow its
                // bounded loop to kill and reap the guest before escalating;
                // immediately killing the supervisor can orphan its child.
                $cleanupDeadline = hrtime(true) + 250_000_000;
                do {
                    $status = proc_get_status($process);
                    if (!$status['running']) {
                        break;
                    }
                    usleep(1000);
                } while (hrtime(true) < $cleanupDeadline);
                if ($status['running']) {
                    proc_terminate($process, 9);
                }
                proc_close($process);
            }
        }
    }

    /** @param resource $stream @param array<string,mixed> $value */
    private function writeFrame($stream, array $value, int $deadline, ?Closure $cancelled): void
    {
        $json = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
        if (strlen($json) > self::MAX_FRAME) {
            throw new RuntimeException('Engine frame exceeds the byte limit.');
        }
        $bytes = pack('N', strlen($json)).$json;
        for ($offset = 0, $length = strlen($bytes); $offset < $length;) {
            $this->checkpoint($deadline, $cancelled);
            $written = @fwrite($stream, substr($bytes, $offset, 65536));
            if ($written === false || feof($stream)) {
                throw new RuntimeException('Ruby engine input closed.');
            }
            $offset += $written;
            if ($written === 0) {
                usleep(1000);
            }
        }
    }

    /** @param resource $stream */
    private function readFrame($stream, int $deadline, ?Closure $cancelled): \stdClass
    {
        $length = unpack('Nlength', $this->readBytes($stream, 4, $deadline, $cancelled))['length'];
        if ($length < 1 || $length > self::MAX_FRAME) {
            throw new RuntimeException('Invalid engine frame length.');
        }
        // Object decoding preserves {} versus [] and signed 64-bit integers.
        $value = json_decode($this->readBytes($stream, $length, $deadline, $cancelled), false, 128, JSON_THROW_ON_ERROR);
        if (!$value instanceof \stdClass) {
            throw new RuntimeException('Engine event must be an object.');
        }
        return $value;
    }

    /** @param resource $stream */
    private function readBytes($stream, int $length, int $deadline, ?Closure $cancelled): string
    {
        $bytes = '';
        while (strlen($bytes) < $length) {
            $this->checkpoint($deadline, $cancelled);
            $chunk = fread($stream, $length - strlen($bytes));
            if ($chunk === false || ($chunk === '' && feof($stream))) {
                throw new RuntimeException('Ruby engine ended without a complete result.');
            }
            $bytes .= $chunk;
            if ($chunk === '') {
                usleep(1000);
            }
        }
        return $bytes;
    }

    /** Host cancellation never implies rollback of an already-dispatched write. */
    private function checkpoint(int $deadline, ?Closure $cancelled): void
    {
        try {
            $isCancelled = $cancelled !== null && $cancelled();
        } catch (Throwable) {
            throw new RuntimeException('Host cancellation state is unavailable; execution stopped safely.');
        }
        if ($isCancelled) {
            throw new RuntimeException('Ruby execution cancelled; inspect any dispatched effects.');
        }
        if (hrtime(true) >= $deadline) {
            throw new RuntimeException('Ruby host deadline exceeded; inspect any dispatched effects.');
        }
    }
}
