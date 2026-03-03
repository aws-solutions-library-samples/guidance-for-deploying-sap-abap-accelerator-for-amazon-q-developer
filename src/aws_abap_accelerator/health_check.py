#!/usr/bin/env python3
"""
Simple health check script for Docker containers
Tests if the MCP server is responding on the expected port
Updated to work with OAuth-protected endpoints
"""

import sys
import socket
from datetime import datetime

def check_tcp_port(host="localhost", port=8000, timeout=5):
    """
    Check if the server port is open and accepting connections.
    
    This is a simple TCP check that doesn't require HTTP or OAuth authentication.
    It just verifies the server is running and listening on the port.
    
    Args:
        host: Server host (default: localhost)
        port: Server port (default: 8000)
        timeout: Connection timeout in seconds (default: 5)
    
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Try to connect to the port
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"✅ Port {port} is open and accepting connections")
            return True
        else:
            print(f"❌ Port {port} is not accepting connections (error code: {result})")
            return False
            
    except socket.gaierror as e:
        print(f"❌ DNS resolution failed for {host}: {e}")
        return False
    except socket.timeout:
        print(f"⏰ Connection timeout to {host}:{port}")
        return False
    except Exception as e:
        print(f"❌ Error checking port {host}:{port}: {e}")
        return False

def main():
    """Main health check function"""
    
    # Get host and port from environment or use defaults
    import os
    host = os.getenv('SERVER_HOST', 'localhost')
    if host == '0.0.0.0':
        host = 'localhost'  # Use localhost for health check
    
    port = int(os.getenv('SERVER_PORT', '8000'))
    
    print(f"🏥 Docker Health Check - {datetime.now().isoformat()}")
    print(f"Target: {host}:{port}")
    print(f"Method: TCP port check (OAuth-compatible)")
    
    # Perform TCP health check
    is_healthy = check_tcp_port(host, port)
    
    if is_healthy:
        print("✅ Container is healthy - server is running and accepting connections")
        sys.exit(0)
    else:
        print("❌ Container is unhealthy - server is not accepting connections")
        sys.exit(1)

if __name__ == "__main__":
    main()