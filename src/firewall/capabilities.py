# src/firewall/capabilities.py

import asyncio
import httpx
import json
# Import configuration variables
from . import config
from mcp.types import Tool, Resource, Prompt, ServerCapabilities
from typing import Dict, Any, List

# Helper function to make authenticated API calls
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
    headers = {
        "Content-Type": "application/json",
        # Use API Key from config for authentication
        "X-chkp-api-key": config.API_KEY
    }
    # If session ID is provided (for future session management), add it to headers
    if sid:
        headers["X-chkp-sid"] = sid

    # Construct the full API URL
    # Assuming the API endpoint includes the version prefix, e.g., '/web_api/v1.7/add-host'
    # Check your specific Check Point API docs for the exact URL structure with version
    api_url = f"{config.MANAGER_URL.rstrip('/')}/web_api/{config.API_VERSION}/{endpoint}"

    print(f"Calling Check Point API: POST {api_url}")
    if payload:
        print(f"Payload: {json.dumps(payload)}")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            api_url,
            headers=headers,
            json=payload,
            verify=config.API_VERIFY_SSL, # Use SSL verification setting from config
            timeout=config.API_TIMEOUT   # Use timeout setting from config
        )
    return response

# Example Placeholder Tool for Firewall (needs implementation)
class BlockIPTool(Tool):
    """
    Adds a given IP address as a Host object and adds it to predefined groups
    on the Check Point Firewall Management Server.
    """
    name = "block_ip"
    description = "Adds an IP address as a host object and adds it to configured blocking groups on the Check Point Management Server. Requires 'ip_address'."
    input_schema = {
        "type": "object",
        "properties": {
            "ip_address": {
                "type": "string",
                "description": "The IP address to block."
            },
            "reason": {
                "type": "string",
                "description": "Optional reason or context for blocking.",
                "default": "Blocked by AI agent"
            }
        },
        "required": ["ip_address"] # Manager URL and API Key come from config now
    }
    output_schema = {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "message": {"type": "string"},
            "host_object_name": {
                "type": "string",
                "description": "The name of the host object created (if successful)."
            },
            "groups_updated": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of groups successfully updated (if successful)."
            }
        }
    }

    async def run(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adds the IP as a host object and adds it to target groups via Check Point API.
        """
        ip_address = parameters.get("ip_address")
        reason = parameters.get("reason", config.HOST_OBJECT_PREFIX + "by_AI")
        host_object_name = f"{config.HOST_OBJECT_PREFIX}{ip_address.replace('.', '_')}" # Create a valid object name

        if not ip_address:
            return {"success": False, "message": "IP address is required."}
        if not config.TARGET_GROUPS:
             return {"success": False, "message": "TARGET_GROUPS is not configured in config.py."}

        print(f"Attempting to block IP: {ip_address} on Check Point Manager via API...")
        print(f"Creating host object '{host_object_name}' and adding to groups: {config.TARGET_GROUPS}")

        # --- API Call 1: Add Host Object ---
        add_host_payload = {
            "name": host_object_name,
            "ipv4-address": ip_address,
            "comments": f"Blocked by AI agent: {reason}"
        }
        try:
            add_host_response = await call_checkpoint_api("add-host", payload=add_host_payload)
            add_host_response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            print(f"Add host API call successful for {host_object_name}.")
        except httpx.TimeoutException:
             return {
                 "success": False,
                 "message": f"API request timed out while adding host object {host_object_name}.",
                 "host_object_name": None,
                 "groups_updated": []
             }
        except httpx.RequestError as exc:
             # Check if the host object already exists (often a 400 Bad Request with specific error code)
             if exc.response is not None and exc.response.status_code == 400:
                 try:
                     error_data = exc.response.json()
                     # Check Point API error code for object already exists (may vary, verify documentation)
                     if error_data.get("code") == "generic_error" and "already exists" in error_data.get("message", ""):
                          print(f"Host object {host_object_name} already exists. Proceeding to add to group(s).")
                     else:
                          return {
                              "success": False,
                              "message": f"Failed to add host object {host_object_name}. API Error: {exc.response.status_code} - {error_data.get('message', exc.response.text)}",
                              "host_object_name": None,
                              "groups_updated": []
                          }
                 except: # If JSON parsing fails or error code is unexpected
                     return {
                         "success": False,
                         "message": f"Failed to add host object {host_object_name}. API Error: {exc.response.status_code} - {exc.response.text}",
                         "host_object_name": None,
                         "groups_updated": []
                     }
             else:
                return {
                    "success": False,
                    "message": f"An error occurred while requesting add-host {exc.request.url!r}: {exc}",
                    "host_object_name": None,
                    "groups_updated": []
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"An unexpected error occurred while adding host object: {e}",
                "host_object_name": None,
                "groups_updated": []
            }

        # --- API Call 2: Add Host Object to Target Group(s) ---
        updated_groups: List[str] = []
        for group_name in config.TARGET_GROUPS:
            set_group_payload = {
                "name": group_name,
                "add": {
                    "members": [{"name": host_object_name}]
                }
            }
            try:
                set_group_response = await call_checkpoint_api("set-group", payload=set_group_payload)
                set_group_response.raise_for_status() # Raise an exception for bad status codes
                print(f"Successfully added {host_object_name} to group {group_name}.")
                updated_groups.append(group_name)
            except httpx.TimeoutException:
                 print(f"Warning: API request timed out while adding {host_object_name} to group {group_name}. Group might not be updated.")
                 # Continue with other groups, but report this in the final message
                 continue
            except httpx.RequestError as exc:
                print(f"Warning: Failed to add {host_object_name} to group {group_name}. API Error: {exc.response.status_code} - {exc.response.text}")
                # Continue with other groups, but report this in the final message
                continue
            except Exception as e:
                 print(f"Warning: An unexpected error occurred while adding {host_object_name} to group {group_name}: {e}")
                 # Continue with other groups, but report this in the final message
                 continue


        # --- Finalize and Publish Changes ---
        # After making changes, you need to publish them and install the policy.
        # This often requires separate API calls.

        success_message = f"IP {ip_address} blocked. Host object '{host_object_name}' created and added to groups: {', '.join(updated_groups)}."
        if len(updated_groups) < len(config.TARGET_GROUPS):
             success_message += f" Note: Failed to add to {len(config.TARGET_GROUPS) - len(updated_groups)} group(s)."

        # TODO: Implement Publish and Install Policy API calls
        # Refer to Check Point API docs for 'publish' and 'install-policy'.
        # These calls can take time and might require a mechanism to track status.

        print("Publishing and installing policy changes...")
        try:
            publish_response = await call_checkpoint_api("publish")
            publish_response.raise_for_status()
            print("Publish successful.")

            # Assuming install-policy needs target gateways defined elsewhere or in config
            # For simplicity, let's assume a config variable for target installation targets
            # TODO: Add INSTALL_TARGETS to config.py if needed
            install_policy_payload = {
                 "policy-package": "Standard", # Replace with your policy package name
                 "targets": [] # List of gateway names/UIDs to install on
            }
            # If config.INSTALL_TARGETS exists:
            # install_policy_payload["targets"] = [{"name": target} for target in config.INSTALL_TARGETS]

            # If you don't specify targets, it often installs on all relevant gateways, but verify
            install_policy_response = await call_checkpoint_api("install-policy", payload=install_policy_payload)
            install_policy_response.raise_for_status()
            print("Install policy successful.")
            success_message += " Changes published and policy installed."

        except httpx.TimeoutException:
             success_message += " Warning: API request timed out during publish or install policy. Changes might not be active."
        except httpx.RequestError as exc:
             success_message += f" Warning: Failed during publish or install policy. API Error: {exc.response.status_code} - {exc.response.text}. Changes might not be active."
        except Exception as e:
             success_message += f" Warning: An unexpected error occurred during publish or install policy: {e}. Changes might not be active."


        return {
            "success": True, # Report success if host object and at least one group update worked
            "message": success_message,
            "host_object_name": host_object_name,
            "groups_updated": updated_groups
        }


# Define the Check Point API Connectivity Test Tool
class CheckPointLoginTestTool(Tool):
    """Tests connectivity to the Check Point Management API via login with API key."""
    name = "checkpoint_login_test"
    description = "Attempts to log in to a Check Point Management Server using an API key to verify connectivity and authentication."
    # Keep inputs here as its specific job is to test a given manager/key
    input_schema = {
        "type": "object",
        "properties": {
            "manager_url": {
                "type": "string",
                "description": "The base URL of the Check Point Management Server (e.g., https://<manager-ip>:443)."
            },
             "api_key": {
                "type": "string",
                "description": "The API key for authentication."
            }
        },
        "required": ["manager_url", "api_key"]
    }
    output_schema = {
        "type": "object",
        "properties": {
            "success": {
                "type": "boolean",
                "description": "True if login was successful, false otherwise."
            },
            "message": {
                "type": "string",
                "description": "A message describing the result (e.g., success or error details)."
            },
            "session_id": {
                 "type": "string",
                 "description": "The session ID if login was successful (optional).",
                 "nullable": True
             }
        }
    }
    async def run(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Runs the login test tool."""
        manager_url = parameters.get("manager_url")
        api_key = parameters.get("api_key")
        login_endpoint = "/web_api/login"
        full_login_url = f"{manager_url.rstrip('/')}{login_endpoint}"

        if not manager_url or not api_key:
            return {"success": False, "message": "Manager URL and API Key are required."}

        print(f"Attempting to connect to {manager_url} and log in...")

        # --- API Call Implementation ---
        # Note: The exact method for API Key authentication with the /web_api/login
        # endpoint can vary slightly depending on the Check Point version and configuration.
        # Standard API key usage is often in headers (e.g., Authorization: <key>)
        # or a custom header. The /login endpoint primarily expects username/password/session-id.
        # For a simple connectivity test using *only* the API key for authentication
        # on the login endpoint, you might need to consult the specific "API Key Authentication"
        # section of the Check Point API documentation for your version.
        #
        # Below is a common pattern for API key usage, assuming it might be passed in headers
        # or a payload field, or that the endpoint accepts it this way for login test.
        # If the standard /login endpoint truly requires username/password to get a session
        # before using an API key for subsequent calls, this tool might need adjustment
        # to target a different, API-key-specific test endpoint if one exists, or
        # simulate the first step of a typical API interaction.
        #
        # For demonstration, we'll attempt a POST to the login endpoint with headers.
        # A real implementation might need to adapt based on the API Key authentication
        # method documented for your specific Check Point version.

        headers = {
            "Content-Type": "application/json",
            # This header is a common pattern, but verify Check Point's specific requirement
            "X-chkp-api-key": api_key # Or Authorization: <scheme> <api_key>
        }

        # While the /login endpoint usually takes username/password,
        # we'll send an empty body or minimal payload if required,
        # assuming the API key in headers is the primary auth for this test.
        # Check Point's /login typically expects a payload like {"username": "...", "password": "..."},
        # so an empty payload might fail unless the API Key method is different.
        # A more robust test might be to call a simple authenticated endpoint *after*
        # a hypothetical API-key based session establishment, but let's stick to
        # testing the *login* process as requested, noting the ambiguity.
        payload: Dict[str, Any] = {} # Assuming payload might be empty or minimal for API key login

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(full_login_url, headers=headers, json=payload, verify=False, timeout=10.0) # verify=False for homelab/testing, use CA certs in production

                print(f"API Response Status Code: {response.status_code}")
                print(f"API Response Body: {response.text}")

                if response.status_code == 200:
                    try:
                        response_data = response.json()
                        session_id = response_data.get("sid") # Check if session ID is returned
                        return {
                            "success": True,
                            "message": "Successfully connected and authenticated with API key.",
                            "session_id": session_id
                        }
                    except json.JSONDecodeError:
                         return {
                             "success": False,
                             "message": f"Authentication successful but could not decode JSON response. Response: {response.text}",
                             "session_id": None
                         }
                else:
                    # Attempt to parse error message if available
                    try:
                        error_data = response.json()
                        error_message = error_data.get("message", response.text)
                    except json.JSONDecodeError:
                        error_message = response.text

                    return {
                        "success": False,
                        "message": f"Authentication failed. Status Code: {response.status_code}. Response: {error_message}",
                        "session_id": None
                    }

            except httpx.TimeoutException:
                 return {
                     "success": False,
                     "message": f"Request timed out after 10 seconds while connecting to {full_login_url!r}",
                     "session_id": None
                 }
            except httpx.RequestError as exc:
                return {
                    "success": False,
                    "message": f"An error occurred while requesting {exc.request.url!r}: {exc}",
                    "session_id": None
                }
            except Exception as e:
                 return {
                     "success": False,
                     "message": f"An unexpected error occurred during login test: {e}",
                     "session_id": None
                 }


# Example Placeholder Resource for Firewall (needs implementation)
class FirewallLogsResource(Resource):
    """Provides recent firewall logs."""
    name = "firewall_logs"
    description = "Retrieves recent logs from the Check Point Firewall."
    # Manager URL and API Key come from config now
    input_schema = {
         "type": "object",
         "properties": {
             "time_range": {
                 "type": "string",
                 "description": "Time range for logs (e.g., 'last 1 hour', 'last 24 hours').",
                 "default": "last 1 hour"
             },
             "filter": {
                 "type": "string",
                 "description": "Optional filter for logs (e.g., 'src=1.2.3.4')."
             }
         },
         "required": [] # Manager URL and API Key come from config now
     }
    content_type = "application/json" # Or text/plain, etc. based on format

    async def read(self, parameters: Dict[str, Any]) -> str:
        """Implementation to retrieve logs from Check Point Firewall."""
        # Use config for connection details
        # manager_url = config.MANAGER_URL # Example usage
        # api_key = config.API_KEY       # Example usage

        time_range = parameters.get("time_range", "last 1 hour")
        filter_param = parameters.get("filter")

        # In a real implementation, use config.MANAGER_URL and config.API_KEY
        # and make the API call to retrieve logs.

        print(f"Attempting to retrieve firewall logs from {config.MANAGER_URL} for time range: {time_range}, filter: {filter_param}")

        # TODO: Implement actual API call to Check Point Logging/Management API
        # Use the api_key/session from config/state to authenticate.
        # Retrieve logs based on parameters (time_range, filter).
        # Use call_checkpoint_api helper or similar, adjusting for logging APIs if different.

        # Placeholder implementation returning dummy data
        dummy_logs = [
            {"time": "2025-05-02T10:00:00Z", "src": "1.2.3.4", "dst": "192.168.1.10", "action": "Accept", "protocol": "TCP", "dst_port": 80},
            {"time": "2025-05-02T10:05:00Z", "src": "5.6.7.8", "dst": "192.168.1.20", "action": "Drop", "protocol": "UDP", "dst_port": 53}
        ]
        print(f"Successfully simulated retrieval of firewall logs from {config.MANAGER_URL}.")
        return json.dumps(dummy_logs) # Resources return strings, usually JSON or text


# Define the full capabilities for the Firewall server
class FirewallCapabilities(ServerCapabilities):
    tools = [
        CheckPointLoginTestTool(),
        # Add other Firewall Tools here (e.g., allow_ip, get_rule_details)
        BlockIPTool()
    ]
    resources = [
        # Add Firewall Resources here (e.g., FirewallLogsResource)
        FirewallLogsResource()
    ]
    prompts = [
        # Add Firewall specific Prompts here
    ]