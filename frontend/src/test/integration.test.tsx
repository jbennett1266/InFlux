import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import Home from '@/app/page';
import { spacetime } from '@/lib/spacetime';
import { vi } from 'vitest';

describe('InFlux V2 Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('User can login and view the dashboard', async () => {
    const connectSpy = vi.spyOn(spacetime, 'connect').mockResolvedValue(undefined);
    
    render(<Home />);
    
    // Check for landing page
    expect(screen.getByText(/INFLUX/)).toBeInTheDocument();
    
    const input = screen.getByPlaceholderText('IDENTITY_USERNAME');
    const button = screen.getByText('INITIALIZE_SESSION');
    
    fireEvent.change(input, { target: { value: 'testuser' } });
    fireEvent.click(button);
    
    // Should transition to dashboard
    await waitFor(() => {
      expect(screen.getByText('LocalNode_Online')).toBeInTheDocument();
    });
    
    expect(connectSpy).toHaveBeenCalledWith('testuser');
    expect(screen.getByText('# GLOBAL')).toBeInTheDocument();
  });

  test('User can send a message', async () => {
    vi.spyOn(spacetime, 'connect').mockResolvedValue(undefined);
    const sendSpy = vi.spyOn(spacetime, 'sendMessage').mockResolvedValue(undefined);
    
    render(<Home />);
    
    // Login
    fireEvent.change(screen.getByPlaceholderText('IDENTITY_USERNAME'), { target: { value: 'testuser' } });
    fireEvent.click(screen.getByText('INITIALIZE_SESSION'));
    
    await waitFor(() => {
      expect(screen.getByPlaceholderText('MSG_TO: #GLOBAL')).toBeInTheDocument();
    });
    
    const msgInput = screen.getByPlaceholderText('MSG_TO: #GLOBAL');
    fireEvent.change(msgInput, { target: { value: 'Hello Integration!' } });
    
    const sendButton = screen.getByLabelText('Send Message');
    fireEvent.click(sendButton);
    
    expect(sendSpy).toHaveBeenCalledWith('global', 'Hello Integration!');
  });

  test('UI updates when a new message is received', async () => {
    vi.spyOn(spacetime, 'connect').mockResolvedValue(undefined);
    let messageCallback: any;
    vi.spyOn(spacetime, 'onMessage').mockImplementation((cb) => {
      messageCallback = cb;
    });

    render(<Home />);
    
    // Login
    fireEvent.change(screen.getByPlaceholderText('IDENTITY_USERNAME'), { target: { value: 'testuser' } });
    fireEvent.click(screen.getByText('INITIALIZE_SESSION'));
    
    await waitFor(() => {
      expect(screen.getByText('LocalNode_Online')).toBeInTheDocument();
    });

    // Simulate message arrival
    const mockMsg = {
      id: '1',
      thread_id: 'global',
      sender_identity: 'alice',
      content: 'Hello from Spacetime!',
      timestamp: Math.floor(Date.now() / 1000)
    };
    
    act(() => {
      messageCallback(mockMsg);
    });

    expect(screen.getByText('Hello from Spacetime!')).toBeInTheDocument();
  });

  test('Streaming component can be controlled', async () => {
    vi.spyOn(spacetime, 'connect').mockResolvedValue(undefined);
    render(<Home />);
    
    // Login
    fireEvent.change(screen.getByPlaceholderText('IDENTITY_USERNAME'), { target: { value: 'testuser' } });
    fireEvent.click(screen.getByText('INITIALIZE_SESSION'));
    
    await waitFor(() => {
      expect(screen.getByText('LocalNode_Online')).toBeInTheDocument();
    });

    const videoButton = screen.getByRole('button', { name: /video/i });
    fireEvent.click(videoButton);

    await waitFor(() => {
      expect(screen.getByText(/Live video/i)).toBeInTheDocument();
    });

    const stopButton = screen.getByRole('button', { name: /PhoneOff/i });
    fireEvent.click(stopButton);

    expect(screen.queryByText(/Live video/i)).not.toBeInTheDocument();
  });
});
