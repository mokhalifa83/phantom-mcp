import sys
import os

# 1. IMMEDIATE STDOUT REDIRECTION
# Redirect stdout to stderr to prevent ANY pollution of the MCP channel
# forcing all print statements to go to stderr (logs)
original_stdout = sys.stdout
sys.stdout = sys.stderr

# 2. Run the server
# We import here so redirection is active during import
from phantom.server import main

if __name__ == "__main__":
    try:
        # Restore stdout only for the actual server run if it expects it?
        # FastMCP stdio transport expects to write to the REAL stdout.
        # So we need to give FastMCP the REAL stdout, but keep everything else on stderr.
        
        # Actually, FastMCP writes to sys.stdout for communication.
        # If we redirect sys.stdout to stderr, FastMCP will write messages to stderr,
        # and Claude won't see them.
        
        # CORRECT APPROACH:
        # We need to make sure NO ONE ELSE writes to stdout.
        # FastMCP likely writes to the file descriptor 1 directly or uses the *original* stdout.
        
        # Let's trust FastMCP to handle the transport, but redirect 'print' to stderr by default?
        pass
    except ImportError:
        # Failed to import, likely missing dependencies
        print("CRITICAL ERROR: Failed to import phantom.server", file=sys.stderr)
        sys.exit(1)

    # We need to run main() but ensure unexpected prints go to stderr
    # FastMCP uses 'sys.stdout' to send messages. We must NOT redirect sys.stdout globally
    # if FastMCP uses 'sys.stdout' object.
    
    # Let's revert the global redirection logic. The issue is likely some import printing stuff.
    # The previous attempt (logger redirection) should have covered it.
    
    # Maybe the issue is simple: 
    # The 'run_command' tool showed "FastMCP found" in output earlier?
    # No, that was my check.
    
    # Let's try a minimal entry point that just call main.
    main()
