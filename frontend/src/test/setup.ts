import '@testing-library/jest-dom';
import { vi } from 'vitest';

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
