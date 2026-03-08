#!/usr/bin/env python3
"""
Main entry point for the ABAP-Accelerator HTTP-based MCP Server.
This is the Python equivalent of the TypeScript STDIO-based MCP server.
"""

import asyncio
import logging
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from server.fastmcp_server import ABAPAcceleratorServer
from config.settings import get_settings
from utils.logger import setup_logging

def main():
    """Main entry point for the HTTP-based MCP server."""
    try:
        # Setup logging
        setup_logging()
        logger = logging.getLogger(__name__)
        
        logger.info("🚀 Starting ABAP-Accelerator HTTP-based MCP Server")
        
        # Load settings
        settings = get_settings()
        
        # Create and run server
        server = ABAPAcceleratorServer(settings)
        
        # Run as HTTP server for deployment on Bedrock AgentCore/ECS Fargate
        server.run("streamable-http")
        
    except KeyboardInterrupt:
        logger.info("👋 Server stopped by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
