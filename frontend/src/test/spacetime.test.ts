import { spacetime } from '@/lib/spacetime';
import { vi } from 'vitest';
import { DbConnectionBuilder } from 'spacetimedb/sdk';

describe('SpacetimeManager Unit Tests', () => {
  test('connect initializes the connection', async () => {
    await spacetime.connect('testuser');
    expect(DbConnectionBuilder).toHaveBeenCalled();
  });

  test('sendMessage calls callReducer', async () => {
    // connect first to initialize this.conn
    await spacetime.connect('testuser');
    
    // Get the mocked connection object
    const mockConn = (DbConnectionBuilder as any).mock.results[0].value.build.mock.results[0].value;
    
    await spacetime.sendMessage('global', 'test content');
    expect(mockConn.callReducer).toHaveBeenCalledWith('send_message', ['global', 'test content']);
  });

  test('updateSignal calls callReducer', async () => {
    await spacetime.connect('testuser');
    const mockConn = (DbConnectionBuilder as any).mock.results[0].value.build.mock.results[0].value;
    
    await spacetime.updateSignal('global', 'signal_data', 'video');
    expect(mockConn.callReducer).toHaveBeenCalledWith('update_signal', ['global', 'signal_data', 'video']);
  });
});
