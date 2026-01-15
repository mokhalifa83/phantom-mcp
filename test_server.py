from mcp.server.fastmcp import FastMCP
import sys

# Initialize minimal server
server = FastMCP("test-phantom")

@server.tool()
def ping() -> str:
    return "pong"

if __name__ == "__main__":
    try:
        # Force stdio transport
        server.run(transport='stdio')
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
