import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Mock SpacetimeDB
vi.mock('spacetimedb/sdk', () => ({
  DbConnectionBuilder: vi.fn().mockImplementation(() => ({
    withUri: vi.fn().mockReturnThis(),
    withDatabaseName: vi.fn().mockReturnThis(),
    onConnect: vi.fn().mockReturnThis(),
    onConnectError: vi.fn().mockReturnThis(),
    build: vi.fn().mockReturnValue({
      db: { message: { onInsert: vi.fn() } },
      subscriptionBuilder: vi.fn().mockReturnThis(),
      subscribe: vi.fn(),
      callReducer: vi.fn(),
    }),
  })),
  DbConnectionImpl: vi.fn(),
}));

// Mock MediaStream and MediaDevices
class MockMediaStream {
  getTracks() { return []; }
  addTrack() {}
}
(global as any).MediaStream = MockMediaStream;

// Mock RTCPeerConnection
class MockRTCPeerConnection {
  addTrack = vi.fn();
  createOffer = vi.fn().mockResolvedValue({});
  setLocalDescription = vi.fn().mockResolvedValue({});
  close = vi.fn();
  onicecandidate = null;
}
(global as any).RTCPeerConnection = MockRTCPeerConnection;

Object.defineProperty(navigator, 'mediaDevices', {
  value: {
    getUserMedia: vi.fn().mockResolvedValue(new MockMediaStream()),
    getDisplayMedia: vi.fn().mockResolvedValue(new MockMediaStream()),
  },
  configurable: true,
});
