import subprocess
import time
import os
import signal
import http.client
import socket

def check_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        try:
            s.connect((host, port))
            return True
        except:
            return False

def check_url(host, port, path="/"):
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", path)
        res = conn.getresponse()
        print(f"Checked {host}:{port}{path} -> Status: {res.status}")
        return res.status < 400
    except Exception:
        return False

def main():
    print("--- InFlux Environment Verification ---")
    
    # 1. Start Services
    print("Starting ./start-dev.sh...")
    # We use a process group to track ONLY what we start
    proc = subprocess.Popen(["./start-dev.sh"], 
                            preexec_fn=os.setsid, 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.STDOUT,
                            text=True,
                            bufsize=1)
    
    print("Waiting for startup sequence (120s max)...")
    start_time = time.time()
    success = False
    if proc.stdout:
        while time.time() - start_time < 120:
            line = proc.stdout.readline()
            if not line:
                break
            print(f"[Start-Dev]: {line.strip()}")
            if "Services are running!" in line:
                print("Detected service startup message.")
                success = True
                break
            time.sleep(0.1)

    if success:
        # 2. Health Checks with retries
        print("\nRunning health checks with retries (up to 180s)...")
        
        backend_up = False
        frontend_up = False
        nats_up = False
        cassandra_up = False
        
        check_start = time.time()
        while time.time() - check_start < 180:
            if not backend_up:
                backend_up = check_url("localhost", 8001)
            if not frontend_up:
                frontend_up = check_url("localhost", 8080) or check_url("localhost", 3000)
            if not nats_up:
                nats_up = check_port("localhost", 4222)
            if not cassandra_up:
                cassandra_up = check_port("localhost", 9042)
            
            if backend_up and frontend_up and nats_up and cassandra_up:
                break
            
            print(f"Status: Backend={backend_up}, Frontend={frontend_up}, NATS={nats_up}, Cassandra={cassandra_up}. Retrying in 10s...")
            time.sleep(10)
        
        print(f"\nFinal Results:")
        print(f"Backend: {'UP' if backend_up else 'DOWN'}")
        print(f"Frontend: {'UP' if frontend_up else 'DOWN'}")
        print(f"NATS: {'UP' if nats_up else 'DOWN'}")
        print(f"Cassandra: {'UP' if cassandra_up else 'DOWN'}")
        
        if backend_up and frontend_up and nats_up and cassandra_up:
            print("\nSUCCESS: Environment is healthy.")
            ret_code = 0
        else:
            print("\nFAILURE: One or more services are unhealthy.")
            ret_code = 1
    else:
        print("\nFAILURE: Services did not start in time.")
        ret_code = 1

    # 3. Cleanup
    print("\nShutting down processes started by this script...")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("Graceful shutdown timed out, killing process group...")
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    
    exit(ret_code)

if __name__ == "__main__":
    main()
