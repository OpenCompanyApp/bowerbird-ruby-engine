<?php

declare(strict_types=1);

require __DIR__.'/../src/Client.php';
require __DIR__.'/../src/Execution.php';
require __DIR__.'/../src/CapabilityFailure.php';

use Bowerbird\RubyEngine\Client;

$engine = new Client(getenv('RUBY_ENGINE_BINARY') ?: dirname(__DIR__, 2).'/target/debug/ruby-engine');
$check = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};
$result = $engine->execute('[1, 2, 3].map { |n| n * 7 }.reduce(0) { |a, b| a + b }');
$check($result->error === null && $result->result === 42, 'PHP-to-mruby evaluation failed: '.json_encode($result));

$calls = 0;
$capabilities = ['records.list' => static function (array $args) use (&$calls, $check): object {
    $calls++;
    $check($args[0]->limit === 1, 'Keyword arguments lost their schema shape.');
    return (object) ['records' => [(object) ['id' => 1, 'active' => false]]];
}];
$result = $engine->execute('rows = app.records.list(limit: 1); rows[:records][0]', $capabilities);
$check($result->error === null && $result->result->active === false && $calls === 1, 'PHP callback/Record projection failed: '.json_encode($result));
$result = $engine->execute('app.records.list(limit: 1); raise "never execute"', $capabilities, validateOnly: true);
$check($result->error === null && $calls === 1 && $result->validatedOnly, 'Validation dispatched a capability.');
$result = $engine->execute('{empty: {}, list: [], no: false, nothing: nil, n: 9007199254740993}');
$check($result->error === null && $result->result->empty instanceof stdClass && $result->result->list === []
    && $result->result->no === false && $result->result->nothing === null
    && $result->result->n === 9007199254740993, 'Structured result coercion.');
$result = $engine->execute('loop {}', cancelled: static fn (): bool => true);
$check($result->error !== null && str_contains($result->error['message'], 'cancelled'), 'Cancellation failed.');
$result = $engine->execute('app.records.list(limit: 1)', ['records.list' => static function (): never {
    throw new Bowerbird\RubyEngine\CapabilityFailure('invalid_arguments', 'Required keyword: limit');
}]);
$check($result->error['type'] === 'invalid_arguments', 'Safe typed capability failure was flattened.');
$result = $engine->execute('app.records.list(limit: 1)', ['records.list' => static function (): never {
    throw new RuntimeException('provider-secret-fixture-must-not-leak');
}]);
$check(!str_contains(json_encode($result), 'provider-secret-fixture-must-not-leak'), 'Provider exception leaked.');
echo "PHP engine smoke: 7 scenarios passed\n";
