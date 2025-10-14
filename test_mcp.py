import asyncio
import json
import sys

async def test_mcp_server():
    """Test if the MCP server responds to initialization."""
    # Start the server
    proc = await asyncio.create_subprocess_exec(
        'python3', 'src/server.py',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={'PYTHONPATH': '/Users/Harnish/Documents/projects/asvs-mcp'}
    )
    
    # Send initialize message
    init_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"}
        }
    }
    
    proc.stdin.write((json.dumps(init_msg) + '\n').encode())
    await proc.stdin.drain()
    
    # Wait for response
    try:
        response = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
        print("✅ Server responded:", response.decode())
        
        # Try listing tools
        list_tools_msg = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        proc.stdin.write((json.dumps(list_tools_msg) + '\n').encode())
        await proc.stdin.drain()
        
        response2 = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
        print("✅ Tools list:", response2.decode())
        
    except asyncio.TimeoutError:
        print("❌ Server did not respond within 5 seconds")
        stderr = await proc.stderr.read()
        print("STDERR:", stderr.decode())
    finally:
        proc.terminate()
        await proc.wait()

if __name__ == "__main__":
    asyncio.run(test_mcp_server())
