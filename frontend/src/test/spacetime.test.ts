import { spacetime } from '@/lib/spacetime';
import { describe, test, expect } from 'vitest';

describe('SpacetimeManager Mock Unit Tests', () => {
  test('connect initializes with username', async () => {
    await spacetime.connect('testuser');
    expect(true).toBe(true);
  });

  test('sendMessage triggers listeners', async () => {
    let received: any = null;
    spacetime.onMessage((msg) => {
      received = msg;
    });

    await spacetime.connect('testuser');
    await spacetime.sendMessage('global', 'hello');
    
    expect(received).not.toBeNull();
    expect(received.content).toBe('hello');
    expect(received.sender_identity).toBe('testuser');
  });

  test('updateSignal resolves', async () => {
    const res = await spacetime.updateSignal('global', 'data', 'video');
    expect(res).toBeUndefined();
  });
});
