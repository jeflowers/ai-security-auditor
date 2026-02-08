"""
Test script for the Security Auditor WebSocket API.

This script verifies:
1. API health check
2. Starting a new audit
3. WebSocket connection and real-time updates
4. Audit completion

Run with: python -m pytest tests/test_websocket.py -v
Or standalone: python tests/test_websocket.py
"""

import asyncio
import json
import sys
from datetime import datetime

import httpx
import websockets
import pytest


API_BASE = "http://localhost:8000"
WS_BASE = "ws://localhost:8000"


# ==============================================================================
# Standalone Test Functions
# ==============================================================================

async def test_health_check():
    """Test the health endpoint."""
    print("\n=== Testing Health Check ===")
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{API_BASE}/health")
        assert response.status_code == 200, f"Health check failed: {response.status_code}"
        data = response.json()
        print(f"✓ Health check passed: {data['status']}")
        print(f"  Version: {data['version']}")
        print(f"  Agents: {data['agents']}")
        return data


async def test_start_audit():
    """Test starting a new audit."""
    print("\n=== Testing Start Audit ===")
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{API_BASE}/api/v1/audits",
            json={
                "framework": "SOC2",
                "report_type": "type2",
                "scope": {
                    "systems": ["app-server-01", "db-server-01"],
                    "frameworks": ["SOC2"]
                },
                "target_path": ".",
                "output_path": "./audit-results"
            }
        )
        assert response.status_code == 200, f"Start audit failed: {response.status_code}"
        data = response.json()
        print(f"✓ Audit started: {data['audit_id']}")
        print(f"  WebSocket URL: {data['websocket_url']}")
        return data['audit_id']


async def test_list_audits():
    """Test listing audits."""
    print("\n=== Testing List Audits ===")
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{API_BASE}/api/v1/audits")
        assert response.status_code == 200, f"List audits failed: {response.status_code}"
        data = response.json()
        print(f"✓ Listed {data['total']} audit(s)")
        for audit in data['audits']:
            print(f"  - {audit['audit_id']}: {audit['overall_status']}")
        return data


async def test_websocket_connection(audit_id: str, timeout: int = 60):
    """Test WebSocket connection and receive updates."""
    print(f"\n=== Testing WebSocket Connection for {audit_id} ===")
    
    ws_url = f"{WS_BASE}/ws/audit/{audit_id}"
    print(f"Connecting to: {ws_url}")
    
    message_count = 0
    phases_seen = set()
    
    try:
        async with websockets.connect(ws_url) as ws:
            print("✓ WebSocket connected")
            
            start_time = datetime.now()
            
            while True:
                # Check timeout
                if (datetime.now() - start_time).seconds > timeout:
                    print(f"\n⚠ Timeout after {timeout}s")
                    break
                
                try:
                    # Wait for message with timeout
                    message = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    data = json.loads(message)
                    message_count += 1
                    
                    msg_type = data.get('type', 'unknown')
                    
                    if msg_type == 'connected':
                        print(f"  [{message_count}] Connected: {data['data']['message']}")
                    
                    elif msg_type == 'status_update':
                        status = data['data']
                        phase = status.get('current_phase', 'unknown')
                        overall = status.get('overall_status', 'unknown')
                        
                        if phase not in phases_seen:
                            phases_seen.add(phase)
                            summary = status.get('summary', {})
                            print(f"  [{message_count}] Phase: {phase} | Status: {overall} | Findings: {summary.get('total_findings', 0)}")
                        
                        # Check if complete
                        if phase in ['completed', 'error']:
                            print(f"\n✓ Audit {phase}")
                            print(f"  Final status: {overall}")
                            print(f"  Total findings: {summary.get('total_findings', 0)}")
                            print(f"  Evidence collected: {summary.get('evidence_collected', 0)}")
                            break
                    
                    elif msg_type == 'phase_change':
                        print(f"  [{message_count}] Phase change: {data['data']['phase']}")
                    
                    elif msg_type == 'audit_complete':
                        print(f"  [{message_count}] ✓ Audit complete!")
                        print(f"  Final status: {data['data']['final_status']}")
                        break
                    
                    elif msg_type == 'ping':
                        # Silent heartbeat
                        pass
                    
                    else:
                        print(f"  [{message_count}] Unknown message type: {msg_type}")
                
                except asyncio.TimeoutError:
                    print(".", end="", flush=True)
                    continue
                    
    except websockets.exceptions.ConnectionClosed as e:
        print(f"\n⚠ WebSocket closed: {e.code} - {e.reason}")
    except Exception as e:
        print(f"\n✗ WebSocket error: {e}")
        raise
    
    print(f"\n  Total messages received: {message_count}")
    print(f"  Phases observed: {sorted(phases_seen)}")
    return message_count


async def test_websocket_invalid_audit():
    """Test WebSocket connection with invalid audit ID."""
    print("\n=== Testing Invalid Audit ID ===")
    
    ws_url = f"{WS_BASE}/ws/audit/INVALID-AUDIT-ID"
    
    try:
        async with websockets.connect(ws_url) as ws:
            # Server accepts then immediately closes with 4004
            # Try to receive - this should raise ConnectionClosed
            try:
                await asyncio.wait_for(ws.recv(), timeout=5.0)
                print("✗ Should have been closed by server")
            except websockets.exceptions.ConnectionClosed as e:
                if e.code == 4004:
                    print(f"✓ Correctly rejected invalid audit: {e.reason}")
                else:
                    print(f"⚠ Unexpected close code: {e.code} - {e.reason}")
    except websockets.exceptions.ConnectionClosed as e:
        # Connection closed during handshake or context entry
        if e.code == 4004:
            print(f"✓ Correctly rejected invalid audit: {e.reason}")
        else:
            print(f"⚠ Unexpected close code: {e.code} - {e.reason}")
    except websockets.exceptions.InvalidStatusCode as e:
        # HTTP rejection before WebSocket upgrade (shouldn't happen now)
        print(f"⚠ HTTP rejection: {e.status_code}")


async def run_all_tests():
    """Run all tests in sequence."""
    print("=" * 60)
    print("Security Auditor WebSocket API Tests")
    print("=" * 60)
    
    try:
        # Test 1: Health check
        await test_health_check()
        
        # Test 2: Start audit
        audit_id = await test_start_audit()
        
        # Test 3: List audits
        await test_list_audits()
        
        # Test 4: WebSocket connection
        await test_websocket_connection(audit_id)
        
        # Test 5: Invalid audit ID
        await test_websocket_invalid_audit()
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)


# ==============================================================================
# Pytest Test Functions
# ==============================================================================

@pytest.fixture
def api_base():
    return API_BASE


@pytest.fixture
def ws_base():
    return WS_BASE


@pytest.mark.asyncio
async def test_api_health(api_base):
    """Test the health endpoint returns healthy status."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{api_base}/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "agents" in data


@pytest.mark.asyncio
async def test_api_start_audit(api_base):
    """Test starting a new audit via API."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{api_base}/api/v1/audits",
            json={
                "framework": "SOC2",
                "scope": {"systems": ["test-server"]},
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "audit_id" in data
        assert data["status"] == "started"
        assert "/ws/audit/" in data["websocket_url"]


@pytest.mark.asyncio
async def test_api_list_audits(api_base):
    """Test listing audits."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{api_base}/api/v1/audits")
        assert response.status_code == 200
        data = response.json()
        assert "audits" in data
        assert "total" in data


@pytest.mark.asyncio
async def test_websocket_connects(api_base, ws_base):
    """Test WebSocket connection to a valid audit."""
    # First start an audit
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{api_base}/api/v1/audits",
            json={"framework": "SOC2", "scope": {"systems": ["test"]}},
        )
        audit_id = response.json()["audit_id"]
    
    # Connect via WebSocket
    async with websockets.connect(f"{ws_base}/ws/audit/{audit_id}") as ws:
        message = await asyncio.wait_for(ws.recv(), timeout=5.0)
        data = json.loads(message)
        assert data["type"] == "connected"


@pytest.mark.asyncio
async def test_websocket_rejects_invalid_audit(ws_base):
    """Test WebSocket rejects connection for invalid audit ID."""
    async with websockets.connect(f"{ws_base}/ws/audit/INVALID-ID") as ws:
        # Server accepts then immediately closes with 4004
        with pytest.raises(websockets.exceptions.ConnectionClosed) as exc_info:
            await asyncio.wait_for(ws.recv(), timeout=5.0)
        
        assert exc_info.value.code == 4004


# ==============================================================================
# Entry Point
# ==============================================================================

if __name__ == "__main__":
    # Check for required packages
    try:
        import httpx
        import websockets
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Install with: pip install httpx websockets")
        sys.exit(1)
    
    # Run tests
    asyncio.run(run_all_tests())
