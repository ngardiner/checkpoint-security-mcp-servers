# src/firewall/server.py

import asyncio
from mcp.server.lowlevel import Server
# Import the corrected capabilities class name from capabilities.py
from .capabilities import FirewallCapabilities

# Create and run the MCP server using capabilities from capabilities.py
async def main():
    """Starts the Check Point Firewall MCP server."""
    print("Starting Check Point Firewall MCP server...")
    # Use the correctly imported capabilities class name
    server = Server(capabilities=FirewallCapabilities())
    # MCP typically communicates over standard I/O when run locally
    await server.run_stdio()
    print("Check Point Firewall MCP server stopped.")

if __name__ == "__main__":
    asyncio.run(main())