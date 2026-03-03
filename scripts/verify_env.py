import subprocess
import time
import os
import signal
import http.client
import socket

def check_url(host, port, path="/"):
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", path)
        res = conn.getresponse()
        return res.status < 400
    except Exception:
        return False

def main():
    print("--- InFlux Environment Verification (Docker Mode) ---")
    
    # 1. Start Services
    print("Starting ./start-dev.sh...")
    proc = subprocess.Popen(["./start-dev.sh"], 
                            preexec_fn=os.setsid, 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.STDOUT,
                            text=True,
                            bufsize=1)
    
    print("Waiting for stack stabilization (120s max)...")
    start_time = time.time()
    sdb_up = False
    frontend_up = False
    
    while time.time() - start_time < 120:
        if not sdb_up:
            sdb_up = check_url("localhost", 3000, "/health")
        if not frontend_up:
            frontend_up = check_url("localhost", 8080)
            
        if sdb_up and frontend_up:
            break
        
        # Read a line to keep buffer clear
        if proc.stdout:
            # Non-blocking read simulation
            line = proc.stdout.readline()
            if line: print(f"[Logs]: {line.strip()}")
            
        time.sleep(5)

    print(f"\nFinal Results:")
    print(f"SpacetimeDB: {'UP' if sdb_up else 'DOWN'}")
    print(f"Frontend:    {'UP' if frontend_up else 'DOWN'}")
    
    if sdb_up and frontend_up:
        print("\nSUCCESS: Environment verified.")
        ret_code = 0
    else:
        print("\nFAILURE: One or more services failed.")
        ret_code = 1

    # 3. Cleanup
    print("\nShutting down processes...")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        proc.wait(timeout=15)
    except Exception as e:
        print(f"Cleanup error: {e}")
    
    exit(ret_code)

if __name__ == "__main__":
    main()
