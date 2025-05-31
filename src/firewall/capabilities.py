# src/firewall/capabilities.py

import asyncio
import httpx
import json
# Import configuration variables
from . import config
from mcp.types import Tool, Resource, Prompt, ServerCapabilities
from typing import Dict, Any, List, ClassVar


# Example Placeholder Tool for Firewall (needs implementation)
class BlockIPTool(Tool):
    """
    Adds a given IP address as a Host object and adds it to predefined groups
    on the Check Point Firewall Management Server.
    """
    name: str = "block_ip"
    description: str = "Adds an IP address as a host object and adds it to configured blocking groups on the Check Point Management Server. Requires 'ip_address'."
    input_schema: ClassVar[Dict[str, Any]] = {
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
    output_schema: ClassVar[Dict[str, Any]] = {
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
    name: str = "checkpoint_login_test"
    description: str = "Attempts to log in to a Check Point Management Server using an API key to verify connectivity and authentication."
    # Keep inputs here as its specific job is to test a given manager/key
    input_schema: ClassVar[Dict[str, Any]] = {
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
    output_schema: ClassVar[Dict[str, Any]] = {
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

# Example Placeholder Resource for Firewall (needs implementation)
class FirewallLogsResource(Resource):
    """Provides recent firewall logs."""
    name: str = "firewall_logs"
    description: str = "Retrieves recent logs from the Check Point Firewall."
    # Manager URL and API Key come from config now
    input_schema: ClassVar[Dict[str, Any]] = {
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
    content_type: str = "application/json" # Or text/plain, etc. based on format

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
        CheckPointLoginTestTool(
            # Explicitly pass the class attributes as arguments
            name=CheckPointLoginTestTool.name,
            description=CheckPointLoginTestTool.description,
            input_schema=CheckPointLoginTestTool.input_schema,
            output_schema=CheckPointLoginTestTool.output_schema
        ),
        # Add other Firewall Tools here (e.g., allow_ip, get_rule_details)
        BlockIPTool(
            # Explicitly pass the class attributes for BlockIPTool as well
            name=BlockIPTool.name,
            description=BlockIPTool.description,
            input_schema=BlockIPTool.input_schema,
            output_schema=BlockIPTool.output_schema
        )
    ]
    resources = [
        # Add Firewall Resources here (e.g., FirewallLogsResource)
        FirewallLogsResource(
             # Explicitly pass the class attributes for FirewallLogsResource
             name=FirewallLogsResource.name,
             description=FirewallLogsResource.description,
             input_schema=FirewallLogsResource.input_schema,
             content_type=FirewallLogsResource.content_type
        )
    ]
    prompts = [
        # Add Firewall specific Prompts here
    ]