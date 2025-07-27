#!/usr/bin/env python3
"""
MCP Message Type Simulator
==========================

This utility simulates MCP message types for eBPF monitoring validation.
It sends each message type once to validate parsing capabilities.

Usage:
    # stdio transport (requires server command)
    python mcp_client.py --server "python mcp_server.py"
    python mcp_client.py --transport stdio --server "python mcp_server.py"

    # HTTP-based transports (connect to existing server)
    python mcp_client.py --transport sse (default url: http://localhost:9000/sse)
    python mcp_client.py --transport streamable-http (default url: http://localhost:9000/mcp)
    python mcp_client.py --transport sse --url "http://localhost:9000/sse"
    python mcp_client.py --transport streamable-http --url "http://localhost:9000/mcp"
"""

import argparse
import asyncio
import logging
from typing import List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.sse import sse_client
from mcp.types import (
    CreateMessageRequestParams,
    CreateMessageResult,
    TextContent,
)


class MCPMessageSimulator:
    """Simulates all MCP message types for validation."""

    def __init__(
        self,
        server_command: Optional[List[str]] = None,
        transport: str = "stdio",
        url: Optional[str] = None,
    ):
        """
        Initialize the MCP message simulator.

        Args:
            server_command: Command to start the MCP server (only used for stdio transport)
            transport: Transport layer to use ("stdio", "sse", "streamable-http")
            url: URL for HTTP-based transports (ignored for stdio)
        """
        self.server_command = server_command
        self.transport = transport
        self.url = url
        self.session: Optional[ClientSession] = None

        # Validate transport-specific requirements
        if self.transport == "stdio" and not self.server_command:
            raise ValueError("Server command is required for stdio transport")

        # Set default URLs for HTTP-based transports
        if self.transport == "sse" and self.url is None:
            self.url = "http://localhost:8000/sse"
        elif self.transport == "streamable-http" and self.url is None:
            self.url = "http://localhost:8000/mcp"

        # Configure logging
        log_level = logging.INFO
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%H:%M:%S",
        )
        self.logger = logging.getLogger(__name__)

    async def simulate_prompts(self) -> None:
        """Simulate prompt-related messages."""
        self.logger.info("=== Simulating Prompt Messages ===")

        try:
            # List prompts
            self.logger.info("Sending prompts/list request")
            prompts_response = await self.session.list_prompts()
            self.logger.info(f"Received {len(prompts_response.prompts)} prompts")

            # Get a specific prompt if available
            if prompts_response.prompts:
                prompt = prompts_response.prompts[0]
                self.logger.info(f"Sending prompts/get request for: {prompt.name}")

                # Use appropriate arguments based on prompt name
                if prompt.name == "code_review":
                    args = {
                        "code": "def hello():\n    print('Hello, World!')",
                        "language": "python",
                    }
                else:
                    # Generic args for unknown prompts
                    args = {"input": "test input"}

                _ = await self.session.get_prompt(prompt.name, args)
                self.logger.info("Received prompt response")
        except Exception as e:
            self.logger.error(f"Error simulating prompts: {e}")

    async def simulate_resources(self) -> None:
        """Simulate resource-related messages."""
        self.logger.info("=== Simulating Resource Messages ===")

        try:
            # List resources
            self.logger.info("Sending resources/list request")
            resources_response = await self.session.list_resources()
            self.logger.info(f"Received {len(resources_response.resources)} resources")

            # Read a resource if available
            if resources_response.resources:
                resource = resources_response.resources[0]
                self.logger.info(f"Sending resources/read request for: {resource.uri}")
                await self.session.read_resource(resource.uri)
                self.logger.info("Received resource content")
        except Exception as e:
            self.logger.error(f"Error simulating resources: {e}")

    async def simulate_tools(self) -> None:
        """Simulate tool-related messages."""
        self.logger.info("=== Simulating Tool Messages ===")

        try:
            # List tools
            self.logger.info("Sending tools/list request")
            tools_response = await self.session.list_tools()
            self.logger.info(f"Received {len(tools_response.tools)} tools")

            # Call the tools available, with specific arguments.
            for tool in tools_response.tools:
                self.logger.info(f"Sending tools/call request for: {tool.name}")

                # Use appropriate arguments based on tool name
                if tool.name == "get_weather":
                    args = {"city": "New York", "units": "metric"}
                elif tool.name == "process_data_with_progress":
                    args = {
                        "data": ["item1", "item2", "item3"],
                        "operation": "uppercase",
                    }
                else:
                    # Generic args for unknown tools
                    args = {"input": "test input"}

                await self.session.call_tool(tool.name, args)
                self.logger.info("Received tool call result")
        except Exception as e:
            self.logger.error(f"Error simulating tools: {e}")

    async def simulate_ping(self) -> None:
        """Simulate ping messages."""
        self.logger.info("=== Simulating Ping Messages ===")

        try:
            self.logger.info("Sending ping request")
            await self.session.send_ping()
            self.logger.info("Received ping response")
        except Exception as e:
            self.logger.error(f"Error simulating ping: {e}")

    async def run_simulation(self) -> None:
        """Run the message simulation."""
        self.logger.info("Starting MCP message simulation")
        self.logger.info(f"Transport: {self.transport}")

        if self.transport == "stdio":
            self.logger.info(f"Server command: {' '.join(self.server_command)}")
        else:
            self.logger.info(f"Target URL: {self.url}")

        try:
            # Set up sampling callback
            async def handle_sampling(
                message: CreateMessageRequestParams,
            ) -> CreateMessageResult:
                """Handle sampling requests from the server."""
                self.logger.info("Received sampling request from server")
                return CreateMessageResult(
                    role="assistant",
                    content=TextContent(
                        type="text",
                        text="Sample response for message simulation.",
                    ),
                    model="simulator-model",
                    stopReason="endTurn",
                )

            # Create client connection based on transport type
            if self.transport == "stdio":
                await self._run_stdio_simulation(handle_sampling)
            elif self.transport == "sse":
                await self._run_sse_simulation(handle_sampling)
            elif self.transport == "streamable-http":
                await self._run_streamable_http_simulation(handle_sampling)
            else:
                raise ValueError(f"Unsupported transport: {self.transport}")

        except Exception as e:
            self.logger.error(f"Error during simulation: {e}")
            raise

    async def _run_stdio_simulation(self, handle_sampling) -> None:
        """Run simulation using stdio transport."""
        server_params = StdioServerParameters(
            command=self.server_command[0],
            args=self.server_command[1:] if len(self.server_command) > 1 else [],
        )

        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(
                read_stream, write_stream, sampling_callback=handle_sampling
            ) as session:
                self.session = session
                await self._run_message_simulation()

    async def _run_sse_simulation(self, handle_sampling) -> None:
        """Run simulation using SSE transport."""
        self.logger.info(f"Connecting to SSE endpoint: {self.url}")
        async with sse_client(self.url) as (read_stream, write_stream):
            async with ClientSession(
                read_stream, write_stream, sampling_callback=handle_sampling
            ) as session:
                self.session = session
                await self._run_message_simulation()

    async def _run_streamable_http_simulation(self, handle_sampling) -> None:
        """Run simulation using streamable HTTP transport."""
        self.logger.info(f"Connecting to HTTP endpoint: {self.url}")
        async with streamablehttp_client(self.url) as (read_stream, write_stream, _):
            async with ClientSession(
                read_stream, write_stream, sampling_callback=handle_sampling
            ) as session:
                self.session = session
                await self._run_message_simulation()

    async def _run_message_simulation(self) -> None:
        """Run the actual message simulation steps."""
        # Initialize connection
        self.logger.info("Sending initialize request")
        await self.session.initialize()
        self.logger.info("Connection initialized")

        # Simulate all message types
        await self.simulate_prompts()
        await self.simulate_resources()
        await self.simulate_tools()
        await self.simulate_ping()

        self.logger.info("Message simulation completed")


async def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="MCP Message Simulator - Simulates all MCP message types for validation"
    )
    parser.add_argument(
        "--server",
        help="Command to start the MCP server (required for stdio transport)",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport layer to use (default: stdio)",
    )
    parser.add_argument(
        "--url",
        help="URL for HTTP-based transports (default: http://localhost:8000/sse for SSE, http://localhost:8000/mcp for HTTP)",
    )

    args = parser.parse_args()

    # Parse server command if provided
    server_command = None
    if args.server:
        server_command = args.server.split()

    simulator = MCPMessageSimulator(
        server_command=server_command,
        transport=args.transport,
        url=args.url,
    )

    await simulator.run_simulation()


if __name__ == "__main__":
    asyncio.run(main())
