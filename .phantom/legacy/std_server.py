import asyncio
import sys
import logging

# Configure logging to stderr
logging.basicConfig(stream=sys.stderr, level=logging.INFO)

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

async def main():
    logging.info("Starting Standard Server...")
    
    server = Server("std-debug")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="ping",
                description="Ping check",
                inputSchema={
                    "type": "object",
                    "properties": {},
                }
            )
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        if name == "ping":
            return [TextContent(type="text", text="pong")]
        return []

    logging.info("Initializing stdio server...")
    
    # Run server
    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        logging.info("Server ready. Listening on stdio...")
        await server.run(read_stream, write_stream, options)

if __name__ == "__main__":
    try:
        # Windows: default event loop policy can be problematic?
        # Usually fine for stdio, but let's just run.
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.critical(f"Crash: {e}")
