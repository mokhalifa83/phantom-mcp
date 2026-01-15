"""
Simple Debug Server
"""
try:
    from mcp.server.fastmcp import FastMCP
    import sys
    import logging

    # Configure logging to stderr
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    logging.info("Starting Simple Server...")

    # Initialize
    server = FastMCP("simple-debug")

    @server.tool()
    def ping() -> str:
        return "pong"

    if __name__ == "__main__":
        logging.info("Running server...")
        server.run(transport='stdio')

except Exception as e:
    import sys
    sys.stderr.write(f"CRITICAL ERROR: {e}\n")
    sys.exit(1)
