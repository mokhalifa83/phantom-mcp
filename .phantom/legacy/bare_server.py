import sys
import os
import time

LOG_FILE = os.path.join(os.path.expanduser("~"), "phantom_launch_debug.txt")

def log(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{time.ctime()}: {msg}\n")

try:
    log("Process started!")
    log(f"Executable: {sys.executable}")
    log(f"CWD: {os.getcwd()}")
    log(f"Args: {sys.argv}")
    
    # Read from stdin to keep process alive and see if we get input
    log("Waiting for stdin...")
    line = sys.stdin.readline()
    log(f"Received input: {line[:50]}...")
    
except Exception as e:
    log(f"CRASH: {e}")
