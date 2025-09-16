import { describe, it } from 'node:test';
import assert from 'node:assert';
import handler from './echo.js';

describe('echo handler', () => {
  it('should echo input', async () => {
    const input = { text: 'test' };
    const output = await handler(input);
    assert.strictEqual(output.ok, true);
    assert.deepStrictEqual(output.echo, input);
  });

  it('should handle empty input', async () => {
    const output = await handler({});
    assert.strictEqual(output.ok, true);
    assert.deepStrictEqual(output.echo, {});
  });
});
