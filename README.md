# checkpoint-security-mcp-servers

**Bridging AI and Check Point Security: Anthropic MCP servers to enable AI agent integration and autonomous defense for Check Point firewalls, endpoint, and more.**

---

## Project Goal

This project aims to build and maintain open-source implementations of Anthropic's Model Context Protocol (MCP) servers specifically designed for various Check Point Software Technologies security products. By exposing Check Point capabilities (like firewall management, endpoint actions, logging, etc.) through the standardized MCP, this project seeks to facilitate seamless integration with AI agents and unlock the potential for advanced AI-driven security automation and autonomous response.

This is an independent community project and is not officially affiliated with or endorsed by Check Point Software Technologies.

## What is the Model Context Protocol (MCP)?

The Model Context Protocol (MCP) is an open standard developed by Anthropic that provides a standardized way for AI applications (like LLMs and AI agents) to discover and interact with external tools and data sources. It enables AI to understand what actions it can take (Tools), what information it can access (Resources), and how to use predefined workflows (Prompts) within connected systems.

## Why Check Point and MCP?

Check Point is a widely deployed security vendor in enterprise environments. Enabling AI agents to interact with Check Point platforms via a standardized protocol like MCP addresses a critical need for enhanced automation and autonomous response in complex security infrastructures. This project aims to bridge the gap and empower AI to become a more integrated and capable part of a Check Point-centric security operation.

## Repository Structure

```
/checkpoint-security-mcp-servers
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── src/
└── firewall/          # MCP server for Check Point Firewall (Management API)
├── init.py
├── server.py      # Main server entry point
└── capabilities.py  # Defines Firewall-specific Tools, Resources, Prompts
└── harmony_endpoint/  # MCP server for Check Point Harmony Endpoint
├── init.py
├── server.py
└── capabilities.py
└── common/          # Optional: for shared code (e.g., API authentication helpers)
├── init.py
└── utils.py
```

## Getting Started

To set up and run these MCP servers, you'll need Python 3.8+ and a Check Point Management Server (for the firewall capabilities).

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/](https://github.com/)[Your-GitHub-Username]/checkpoint-security-mcp-servers.git
    cd checkpoint-security-mcp-servers
    ```
2.  **Set up a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Configure Check Point API Access:**
    * Obtain an API key from your Check Point Management Server.
    * Note the manager URL (IP address or hostname and port, e.g., `https://192.168.1.10:443`). **Note:** For initial testing with self-signed certificates in a homelab, you might use `verify=False` in the `httpx` calls (as in the example), but for any production or exposed environment, ensure proper certificate validation is configured.

5.  **Run an MCP Server (e.g., Firewall):**
    Navigate to the repository root and run the server script.
    ```bash
    python src/firewall/server.py
    ```
    The server will start and wait for an MCP client connection over standard I/O.

    By default, the server uses standard I/O (`stdio`) for communication. You can also specify other transport mechanisms using the `--transport` argument:

    *   **`stdio` (default):** Uses standard input/output.
        ```bash
        python src/firewall/server.py
        ```
    *   **`sse` (Server-Sent Events):** Runs an HTTP server that clients can connect to for Server-Sent Events.
        ```bash
        python src/firewall/server.py --transport sse
        ```
        The server will listen on `0.0.0.0:8000` by default when using `sse`.
    *   **`streamable-http`:** Runs an HTTP server that clients can connect to using a streamable HTTP mechanism.
        ```bash
        python src/firewall/server.py --transport streamable-http
        ```
        The server will listen on `0.0.0.0:8000` by default when using `streamable-http`.

    When using `sse` or `streamable-http` transports, you can also specify a custom port using the optional `--port` argument. If not provided, it defaults to `8000`.
    Example:
    ```bash
    python src/firewall/server.py --transport streamable-http --port 9999
    ```

6.  **Connect an MCP Client:**
    * Use an MCP-compatible AI application (like Anthropic's Claude Desktop, or build/configure your own client) to connect to the running server.
    * Configure the client to recognize your local server running via standard I/O. Refer to your chosen MCP client's documentation for how to add a local server.
    * Once connected, the AI should be able to discover and use the exposed Tools and Resources (like `checkpoint_login_test`).

## Implemented Capabilities (Phase 1)

* **Firewall MCP Server (`src/firewall/`)**:
    * `checkpoint_login_test` Tool: Tests connectivity to the Check Point Management API using an API key. (Requires `manager_url` and `api_key` as input parameters).

## To Be Implemented (Future Phases)

* Full implementation of `BlockIPTool` to interact with the Check Point Management API.
* Implementation of `FirewallLogsResource` to retrieve logs.
* Development of the Harmony Endpoint MCP server (`src/harmony_endpoint/`) and its capabilities.
* Addition of more Tools and Resources for both platforms (e.g., managing network objects, policies, getting endpoint status, isolating endpoints, etc.).
* Robust error handling and state management (e.g., handling API sessions established by the login tool).
* Improved documentation and examples.

## Contributing

This is an open-source project, and contributions are welcome! If you'd like to contribute:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes and ensure code passes any tests (add tests!).
4.  Submit a pull request with a clear description of your changes.

## License

This project is licensed under the [Choose Your License, e.g., MIT License](LICENSE).
