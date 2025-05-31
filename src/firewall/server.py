from mcp.server.fastmcp import FastMCP
from typing import Dict, Any, List, Optional
from . import config
import httpx
import json
import traceback

server = FastMCP(server_name="CheckPointFirewallMCP")

async def call_checkpoint_api(endpoint: str, payload: Dict[str, Any] = None, sid: str = None) -> httpx.Response:
    """
    Makes an authenticated call to the Check Point Management API.

    Args:
        endpoint: The API endpoint (e.g., 'add-host').
        payload: The JSON payload for the request.
        sid: The session ID if using session-based authentication (optional).

    Returns:
        The httpx.Response object.
    """
    headers = {"Content-Type": "application/json"}
    if sid: headers["X-chkp-sid"] = sid
    api_url = f"{config.MANAGER_URL.rstrip('/')}/web_api/{config.API_VERSION}/{endpoint}"
    print(f"Calling Check Point API: POST {api_url}")
    if payload: print(f"Payload: {json.dumps(payload)}")
    async with httpx.AsyncClient(verify=config.API_VERIFY_SSL) as client:
        response = await client.post(api_url, headers=headers, json=payload, timeout=config.API_TIMEOUT)
    return response

@server.tool()
async def checkpoint_login_test() -> Dict[str, Any]:
    """Runs the login tool."""
    manager_url = getattr(config, 'MANAGER_URL', None)
    api_key = getattr(config, 'API_KEY', None)
    username = getattr(config, 'USERNAME', None)
    password = getattr(config, 'PASSWORD', None)
    login_endpoint = "/web_api/login"
    full_login_url = f"{manager_url.rstrip('/')}{login_endpoint}"

    if not manager_url:
        return {"success": False, "message": "Manager URL is not configured in config.py."}

    if not username and not api_key:
        return {"success": False, "message": "Either API Key or Username must be configured in config.py."}

    if api_key:
        print(f"Attempting to connect to {manager_url} and log in using configured API key...")
        headers = {"Content-Type": "application/json"}
        payload: Dict[str, Any] = {"api-key": api_key}

    if not api_key and username:
        print(f"Attempting to connect to {manager_url} and log in using configured username and password...")
        headers = {"Content-Type": "application/json"}
        payload: Dict[str, Any] = {"user": username, "password": password}

    async with httpx.AsyncClient(verify=config.API_VERIFY_SSL) as client:
        try:
            response = await client.post(full_login_url, headers=headers, json=payload, timeout=config.API_TIMEOUT)
            print(f"API Response Status Code: {response.status_code}")
            print(f"API Response Body: {response.text}")
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    session_id = response_data.get("sid")
                    if api_key:
                        return {"success": True, "message": "Successfully connected and authenticated with configured API key.", "session_id": session_id}
                    else:
                        return {"success": True, "message": "Successfully connected and authenticated with configured username and password.", "session_id": session_id}
                except json.JSONDecodeError:
                     return {"success": False, "message": f"Authentication successful but could not decode JSON response. Response: {response.text}", "session_id": None}
            else:
                try:
                    error_data = response.json()
                    error_message = error_data.get("message", response.text)
                except json.JSONDecodeError:
                    error_message = response.text
                return {"success": False, "message": f"Authentication failed. Status Code: {response.status_code}. Response: {error_message}", "session_id": None}
        except httpx.TimeoutException:
             return {"success": False, "message": f"Request timed out after {config.API_TIMEOUT} seconds while connecting to {full_login_url!r}", "session_id": None}
        except httpx.RequestError as exc:
            return {"success": False, "message": f"An error occurred while requesting {exc.request.url!r}: {exc}", "session_id": None}
        except Exception as e:
             return {"success": False, "message": f"An unexpected error occurred during login test: {e}", "session_id": None}

@server.tool()
async def block_ip(ip_address: str, reason: Optional[str] = "Blocked by AI agent") -> Dict[str, Any]:
    host_object_name = f"{config.HOST_OBJECT_PREFIX}{ip_address.replace('.', '_')}"
    if not ip_address: return {"success": False, "message": "IP address is required."}
    if not config.TARGET_GROUPS: return {"success": False, "message": "TARGET_GROUPS is not configured in config.py."}
    print(f"Attempting to block IP: {ip_address} on Check Point Manager via API...")
    print(f"Creating host object '{host_object_name}' and adding to groups: {config.TARGET_GROUPS}")
    add_host_payload = {"name": host_object_name, "ipv4-address": ip_address, "comments": f"Blocked by AI agent: {reason}"}
    try:
        add_host_response = await call_checkpoint_api("add-host", payload=add_host_payload)
        add_host_response.raise_for_status()
        print(f"Add host API call successful for {host_object_name}.")
    except httpx.TimeoutException:
         return {"success": False, "message": f"API request timed out while adding host object {host_object_name}.", "host_object_name": None, "groups_updated": [] }
    except httpx.RequestError as exc:
        if exc.response is not None and exc.response.status_code == 400:
            try:
                error_data = exc.response.json()
                if error_data.get("code") == "generic_error" and "already exists" in error_data.get("message", ""):
                    print(f"Host object {host_object_name} already exists. Proceeding to add to group(s).")
                else: return {"success": False, "message": f"Failed to add host object {host_object_name}. API Error: {exc.response.status_code} - {error_data.get('message', exc.response.text)}", "host_object_name": None, "groups_updated": []}
            except: return {"success": False, "message": f"Failed to add host object {host_object_name}. API Error: {exc.response.status_code} - {exc.response.text}", "host_object_name": None, "groups_updated": []}
        else: return {"success": False, "message": f"An error occurred while requesting add-host {exc.request.url!r}: {exc}", "host_object_name": None, "groups_updated": []}
    except Exception as e: return {"success": False, "message": f"An unexpected error occurred while adding host object: {e}", "host_object_name": None, "groups_updated": []}
    updated_groups: List[str] = []
    for group_name in config.TARGET_GROUPS:
        set_group_payload = {"name": group_name, "add": {"members": [{"name": host_object_name}]}}
        try:
            set_group_response = await call_checkpoint_api("set-group", payload=set_group_payload)
            set_group_response.raise_for_status()
            print(f"Successfully added {host_object_name} to group {group_name}.")
            updated_groups.append(group_name)
        except httpx.TimeoutException: 
            print(f"Warning: API request timed out while adding {host_object_name} to group {group_name}.")
            continue
        except httpx.RequestError as exc: 
            print(f"Warning: Failed to add {host_object_name} to group {group_name}. API Error: {exc.response.status_code if exc.response else 'N/A'} - {exc.response.text if exc.response else str(exc)}")
            continue
        except Exception as e: 
            print(f"Warning: An unexpected error occurred while adding {host_object_name} to group {group_name}: {e}")
            continue
    success_message = f"IP {ip_address} blocked. Host object '{host_object_name}' created and added to groups: {', '.join(updated_groups)}."
    if len(updated_groups) < len(config.TARGET_GROUPS): success_message += f" Note: Failed to add to {len(config.TARGET_GROUPS) - len(updated_groups)} group(s)."
    print("Publishing and installing policy changes...")
    try:
        publish_response = await call_checkpoint_api("publish")
        publish_response.raise_for_status()
        print("Publish successful.")
        install_policy_payload = {"policy-package": "Standard", "targets": [] }
        install_policy_response = await call_checkpoint_api("install-policy", payload=install_policy_payload)
        install_policy_response.raise_for_status()
        print("Install policy successful.")
        success_message += " Changes published and policy installed."
    except httpx.TimeoutException: success_message += " Warning: API request timed out during publish or install policy."
    except httpx.RequestError as exc: success_message += f" Warning: Failed during publish or install policy. API Error: {exc.response.status_code if exc.response else 'N/A'} - {exc.response.text if exc.response else str(exc)}."
    except Exception as e: success_message += f" Warning: An unexpected error occurred during publish or install policy: {e}."
    return {"success": True, "message": success_message, "host_object_name": host_object_name, "groups_updated": updated_groups}

# --- FirewallLogsResource ---
@server.resource(uri="firewall-resource:logs")
async def firewall_logs() -> str:
    """
    Retrieves recent logs from the Check Point Firewall.
    Client should send 'time_range' and 'filter' in the MCP arguments.
    This function will attempt to access them via a mechanism TBD (e.g. injected context or **kwargs if FastMCP supports it).
    For now, it uses hardcoded defaults for time_range and filter for testing server startup.
    """
    # Placeholder: How to get arguments if not in signature for FastMCP resource?
    # This is the part that needs to be figured out from FastMCP docs/examples
    # For now, using defaults to allow server to start.
    time_range = "last 1 hour"
    filter_str = None # Using filter_str to avoid conflict with builtin filter

    manager_url = config.MANAGER_URL
    api_key = config.API_KEY

    if not manager_url or not api_key:
        return json.dumps({"error": "Manager URL and API Key are not configured in config.py."})

    print(f"Attempting to retrieve firewall logs from {manager_url} for time range: {time_range}, filter: {filter_str if filter_str else 'None'}")
    
    dummy_logs = [
        {"time": "2025-05-02T10:00:00Z", "src": "1.2.3.4", "dst": "192.168.1.10", "action": "Accept", "protocol": "TCP", "dst_port": 80},
        {"time": "2025-05-02T10:05:00Z", "src": "5.6.7.8", "dst": "192.168.1.20", "action": "Drop", "protocol": "UDP", "dst_port": 53}
    ]
    print(f"Successfully simulated retrieval of firewall logs from {manager_url}.")
    return json.dumps(dummy_logs)

def main():
    print(f"Starting Check Point Firewall MCP server (FastMCP using stdio)...")
    try:
        server.run()
    except Exception as e:
        error_message = f"PYTHON SERVER CRITICAL ERROR in main server.run(): {e}\n{traceback.format_exc()}"
        print(error_message)
        with open("fastmcp_server_critical_error.log", "w") as f_err:
            f_err.write(error_message)
        raise
    print("Check Point Firewall MCP server stopped.")
    
if __name__ == "__main__":
    print("PYTHON SERVER: Script __main__ started.")
    main()
    print("PYTHON SERVER: Script __main__ finished.")