# Code Documentation

## InMemoryTokenStorage

**Type**: Class

**Description**: class InMemoryTokenStorage(TokenStorage):
    """Simple in-memory token storage implementation."""

    def __init__(self):
        self._tokens: OAuthToken | None = None
        self._client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info

## CallbackHandler

**Type**: Class

**Description**: class CallbackHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler to capture OAuth callback."""

    def __init__(self, request, client_address, server, callback_data):
        """Initialize with callback data storage."""
        self.callback_data = callback_data
        super().__init__(request, client_address, server)

    def do_GET(self):
        """Handle GET request from OAuth redirect."""
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        if "code" in query_params:
            self.callback_data["authorization_code"] = query_params["code"][0]
            self.callback_data["state"] = query_params.get("state", [None])[0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html>
            <body>
                <h1>Authorization Successful!</h1>
                <p>You can close this window and return to the terminal.</p>
                <script>setTimeout(() => window.close(), 2000);</script>
            </body>
            </html>
            """)
        elif "error" in query_params:
            self.callback_data["error"] = query_params["error"][0]
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"""
            <html>
            <body>
                <h1>Authorization Failed</h1>
                <p>Error: {query_params['error'][0]}</p>
                <p>You can close this window and return to the terminal.</p>
            </body>
            </html>
            """.encode()
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

## CallbackServer

**Type**: Class

**Description**: class CallbackServer:
    """Simple server to handle OAuth callbacks."""

    def __init__(self, port=3000):
        self.port = port
        self.server = None
        self.thread = None
        self.callback_data = {"authorization_code": None, "state": None, "error": None}

    def _create_handler_with_data(self):
        """Create a handler class with access to callback data."""
        callback_data = self.callback_data

        class DataCallbackHandler(CallbackHandler):
            def __init__(self, request, client_address, server):
                super().__init__(request, client_address, server, callback_data)

        return DataCallbackHandler

    def start(self):
        """Start the callback server in a background thread."""
        handler_class = self._create_handler_with_data()
        self.server = HTTPServer(("localhost", self.port), handler_class)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        print(f"🖥️  Started callback server on http://localhost:{self.port}")

    def stop(self):
        """Stop the callback server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1)

    def wait_for_callback(self, timeout=300):
        """Wait for OAuth callback with timeout."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.callback_data["authorization_code"]:
                return self.callback_data["authorization_code"]
            elif self.callback_data["error"]:
                raise Exception(f"OAuth error: {self.callback_data['error']}")
            time.sleep(0.1)
        raise Exception("Timeout waiting for OAuth callback")

    def get_state(self):
        """Get the received state parameter."""
        return self.callback_data["state"]

## SimpleAuthClient

**Type**: Class

**Description**: class SimpleAuthClient:
    """Simple MCP client with auth support."""

    def __init__(self, server_url: str, transport_type: str = "streamable_http"):
        self.server_url = server_url
        self.transport_type = transport_type
        self.session: ClientSession | None = None

    async def connect(self):
        """Connect to the MCP server."""
        print(f"🔗 Attempting to connect to {self.server_url}...")

        try:
            callback_server = CallbackServer(port=3030)
            callback_server.start()

            async def callback_handler() -> tuple[str, str | None]:
                """Wait for OAuth callback and return auth code and state."""
                print("⏳ Waiting for authorization callback...")
                try:
                    auth_code = callback_server.wait_for_callback(timeout=300)
                    return auth_code, callback_server.get_state()
                finally:
                    callback_server.stop()

            client_metadata_dict = {
                "client_name": "Simple Auth Client",
                "redirect_uris": ["http://localhost:3030/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_post",
            }

            async def _default_redirect_handler(authorization_url: str) -> None:
                """Default redirect handler that opens the URL in a browser."""
                print(f"Opening browser for authorization: {authorization_url}")
                webbrowser.open(authorization_url)

            # Create OAuth authentication handler using the new interface
            oauth_auth = OAuthClientProvider(
                server_url=self.server_url.replace("/mcp", ""),
                client_metadata=OAuthClientMetadata.model_validate(
                    client_metadata_dict
                ),
                storage=InMemoryTokenStorage(),
                redirect_handler=_default_redirect_handler,
                callback_handler=callback_handler,
            )

            # Create transport with auth handler based on transport type
            if self.transport_type == "sse":
                print("📡 Opening SSE transport connection with auth...")
                async with sse_client(
                    url=self.server_url,
                    auth=oauth_auth,
                    timeout=60,
                ) as (read_stream, write_stream):
                    await self._run_session(read_stream, write_stream, None)
            else:
                print("📡 Opening StreamableHTTP transport connection with auth...")
                async with streamablehttp_client(
                    url=self.server_url,
                    auth=oauth_auth,
                    timeout=timedelta(seconds=60),
                ) as (read_stream, write_stream, get_session_id):
                    await self._run_session(read_stream, write_stream, get_session_id)

        except Exception as e:
            print(f"❌ Failed to connect: {e}")
            import traceback

            traceback.print_exc()

    async def _run_session(self, read_stream, write_stream, get_session_id):
        """Run the MCP session with the given streams."""
        print("🤝 Initializing MCP session...")
        async with ClientSession(read_stream, write_stream) as session:
            self.session = session
            print("⚡ Starting session initialization...")
            await session.initialize()
            print("✨ Session initialization complete!")

            print(f"\n✅ Connected to MCP server at {self.server_url}")
            if get_session_id:
                session_id = get_session_id()
                if session_id:
                    print(f"Session ID: {session_id}")

            # Run interactive loop
            await self.interactive_loop()

    async def list_tools(self):
        """List available tools from the server."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            result = await self.session.list_tools()
            if hasattr(result, "tools") and result.tools:
                print("\n📋 Available tools:")
                for i, tool in enumerate(result.tools, 1):
                    print(f"{i}. {tool.name}")
                    if tool.description:
                        print(f"   Description: {tool.description}")
                    print()
            else:
                print("No tools available")
        except Exception as e:
            print(f"❌ Failed to list tools: {e}")

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None):
        """Call a specific tool."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            result = await self.session.call_tool(tool_name, arguments or {})
            print(f"\n🔧 Tool '{tool_name}' result:")
            if hasattr(result, "content"):
                for content in result.content:
                    if content.type == "text":
                        print(content.text)
                    else:
                        print(content)
            else:
                print(result)
        except Exception as e:
            print(f"❌ Failed to call tool '{tool_name}': {e}")

    async def interactive_loop(self):
        """Run interactive command loop."""
        print("\n🎯 Interactive MCP Client")
        print("Commands:")
        print("  list - List available tools")
        print("  call <tool_name> [args] - Call a tool")
        print("  quit - Exit the client")
        print()

        while True:
            try:
                command = input("mcp> ").strip()

                if not command:
                    continue

                if command == "quit":
                    break

                elif command == "list":
                    await self.list_tools()

                elif command.startswith("call "):
                    parts = command.split(maxsplit=2)
                    tool_name = parts[1] if len(parts) > 1 else ""

                    if not tool_name:
                        print("❌ Please specify a tool name")
                        continue

                    # Parse arguments (simple JSON-like format)
                    arguments = {}
                    if len(parts) > 2:
                        import json

                        try:
                            arguments = json.loads(parts[2])
                        except json.JSONDecodeError:
                            print("❌ Invalid arguments format (expected JSON)")
                            continue

                    await self.call_tool(tool_name, arguments)

                else:
                    print(
                        "❌ Unknown command. Try 'list', 'call <tool_name>', or 'quit'"
                    )

            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except EOFError:
                break

## main

**Type**: Function

**Description**: async def main():
    """Main entry point."""
    # Default server URL - can be overridden with environment variable
    # Most MCP streamable HTTP servers use /mcp as the endpoint
    server_url = os.getenv("MCP_SERVER_PORT", 8000)
    transport_type = os.getenv("MCP_TRANSPORT_TYPE", "streamable_http")
    server_url = (
        f"http://localhost:{server_url}/mcp"
        if transport_type == "streamable_http"
        else f"http://localhost:{server_url}/sse"
    )

    print("🚀 Simple MCP Auth Client")
    print(f"Connecting to: {server_url}")
    print(f"Transport type: {transport_type}")

    # Start connection flow - OAuth will be handled automatically
    client = SimpleAuthClient(server_url, transport_type)
    await client.connect()

## cli

**Type**: Function

**Description**: def cli():
    """CLI entry point for uv script."""
    asyncio.run(main())

## Configuration

**Type**: Class

**Description**: class Configuration:
    """Manages configuration and environment variables for the MCP client."""

    def __init__(self) -> None:
        """Initialize configuration with environment variables."""
        self.load_env()
        self.api_key = os.getenv("LLM_API_KEY")

    @staticmethod
    def load_env() -> None:
        """Load environment variables from .env file."""
        load_dotenv()

    @staticmethod
    def load_config(file_path: str) -> dict[str, Any]:
        """Load server configuration from JSON file.

        Args:
            file_path: Path to the JSON configuration file.

        Returns:
            Dict containing server configuration.

        Raises:
            FileNotFoundError: If configuration file doesn't exist.
            JSONDecodeError: If configuration file is invalid JSON.
        """
        with open(file_path, "r") as f:
            return json.load(f)

    @property
    def llm_api_key(self) -> str:
        """Get the LLM API key.

        Returns:
            The API key as a string.

        Raises:
            ValueError: If the API key is not found in environment variables.
        """
        if not self.api_key:
            raise ValueError("LLM_API_KEY not found in environment variables")
        return self.api_key

## Server

**Type**: Class

**Description**: class Server:
    """Manages MCP server connections and tool execution."""

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        self.name: str = name
        self.config: dict[str, Any] = config
        self.stdio_context: Any | None = None
        self.session: ClientSession | None = None
        self._cleanup_lock: asyncio.Lock = asyncio.Lock()
        self.exit_stack: AsyncExitStack = AsyncExitStack()

    async def initialize(self) -> None:
        """Initialize the server connection."""
        command = (
            shutil.which("npx")
            if self.config["command"] == "npx"
            else self.config["command"]
        )
        if command is None:
            raise ValueError("The command must be a valid string and cannot be None.")

        server_params = StdioServerParameters(
            command=command,
            args=self.config["args"],
            env={**os.environ, **self.config["env"]}
            if self.config.get("env")
            else None,
        )
        try:
            stdio_transport = await self.exit_stack.enter_async_context(
                stdio_client(server_params)
            )
            read, write = stdio_transport
            session = await self.exit_stack.enter_async_context(
                ClientSession(read, write)
            )
            await session.initialize()
            self.session = session
        except Exception as e:
            logging.error(f"Error initializing server {self.name}: {e}")
            await self.cleanup()
            raise

    async def list_tools(self) -> list[Any]:
        """List available tools from the server.

        Returns:
            A list of available tools.

        Raises:
            RuntimeError: If the server is not initialized.
        """
        if not self.session:
            raise RuntimeError(f"Server {self.name} not initialized")

        tools_response = await self.session.list_tools()
        tools = []

        for item in tools_response:
            if isinstance(item, tuple) and item[0] == "tools":
                tools.extend(
                    Tool(tool.name, tool.description, tool.inputSchema, tool.title)
                    for tool in item[1]
                )

        return tools

    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        retries: int = 2,
        delay: float = 1.0,
    ) -> Any:
        """Execute a tool with retry mechanism.

        Args:
            tool_name: Name of the tool to execute.
            arguments: Tool arguments.
            retries: Number of retry attempts.
            delay: Delay between retries in seconds.

        Returns:
            Tool execution result.

        Raises:
            RuntimeError: If server is not initialized.
            Exception: If tool execution fails after all retries.
        """
        if not self.session:
            raise RuntimeError(f"Server {self.name} not initialized")

        attempt = 0
        while attempt < retries:
            try:
                logging.info(f"Executing {tool_name}...")
                result = await self.session.call_tool(tool_name, arguments)

                return result

            except Exception as e:
                attempt += 1
                logging.warning(
                    f"Error executing tool: {e}. Attempt {attempt} of {retries}."
                )
                if attempt < retries:
                    logging.info(f"Retrying in {delay} seconds...")
                    await asyncio.sleep(delay)
                else:
                    logging.error("Max retries reached. Failing.")
                    raise

    async def cleanup(self) -> None:
        """Clean up server resources."""
        async with self._cleanup_lock:
            try:
                await self.exit_stack.aclose()
                self.session = None
                self.stdio_context = None
            except Exception as e:
                logging.error(f"Error during cleanup of server {self.name}: {e}")

## Tool

**Type**: Class

**Description**: class Tool:
    """Represents a tool with its properties and formatting."""

    def __init__(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        title: str | None = None,
    ) -> None:
        self.name: str = name
        self.title: str | None = title
        self.description: str = description
        self.input_schema: dict[str, Any] = input_schema

    def format_for_llm(self) -> str:
        """Format tool information for LLM.

        Returns:
            A formatted string describing the tool.
        """
        args_desc = []
        if "properties" in self.input_schema:
            for param_name, param_info in self.input_schema["properties"].items():
                arg_desc = (
                    f"- {param_name}: {param_info.get('description', 'No description')}"
                )
                if param_name in self.input_schema.get("required", []):
                    arg_desc += " (required)"
                args_desc.append(arg_desc)

        # Build the formatted output with title as a separate field
        output = f"Tool: {self.name}\n"

        # Add human-readable title if available
        if self.title:
            output += f"User-readable title: {self.title}\n"

        output += f"""Description: {self.description}
Arguments:
{chr(10).join(args_desc)}
"""

        return output

## LLMClient

**Type**: Class

**Description**: class LLMClient:
    """Manages communication with the LLM provider."""

    def __init__(self, api_key: str) -> None:
        self.api_key: str = api_key

    def get_response(self, messages: list[dict[str, str]]) -> str:
        """Get a response from the LLM.

        Args:
            messages: A list of message dictionaries.

        Returns:
            The LLM's response as a string.

        Raises:
            httpx.RequestError: If the request to the LLM fails.
        """
        url = "https://api.groq.com/openai/v1/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "messages": messages,
            "model": "meta-llama/llama-4-scout-17b-16e-instruct",
            "temperature": 0.7,
            "max_tokens": 4096,
            "top_p": 1,
            "stream": False,
            "stop": None,
        }

        try:
            with httpx.Client() as client:
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]

        except httpx.RequestError as e:
            error_message = f"Error getting LLM response: {str(e)}"
            logging.error(error_message)

            if isinstance(e, httpx.HTTPStatusError):
                status_code = e.response.status_code
                logging.error(f"Status code: {status_code}")
                logging.error(f"Response details: {e.response.text}")

            return (
                f"I encountered an error: {error_message}. "
                "Please try again or rephrase your request."
            )

## ChatSession

**Type**: Class

**Description**: class ChatSession:
    """Orchestrates the interaction between user, LLM, and tools."""

    def __init__(self, servers: list[Server], llm_client: LLMClient) -> None:
        self.servers: list[Server] = servers
        self.llm_client: LLMClient = llm_client

    async def cleanup_servers(self) -> None:
        """Clean up all servers properly."""
        for server in reversed(self.servers):
            try:
                await server.cleanup()
            except Exception as e:
                logging.warning(f"Warning during final cleanup: {e}")

    async def process_llm_response(self, llm_response: str) -> str:
        """Process the LLM response and execute tools if needed.

        Args:
            llm_response: The response from the LLM.

        Returns:
            The result of tool execution or the original response.
        """
        import json

        try:
            tool_call = json.loads(llm_response)
            if "tool" in tool_call and "arguments" in tool_call:
                logging.info(f"Executing tool: {tool_call['tool']}")
                logging.info(f"With arguments: {tool_call['arguments']}")

                for server in self.servers:
                    tools = await server.list_tools()
                    if any(tool.name == tool_call["tool"] for tool in tools):
                        try:
                            result = await server.execute_tool(
                                tool_call["tool"], tool_call["arguments"]
                            )

                            if isinstance(result, dict) and "progress" in result:
                                progress = result["progress"]
                                total = result["total"]
                                percentage = (progress / total) * 100
                                logging.info(
                                    f"Progress: {progress}/{total} ({percentage:.1f}%)"
                                )

                            return f"Tool execution result: {result}"
                        except Exception as e:
                            error_msg = f"Error executing tool: {str(e)}"
                            logging.error(error_msg)
                            return error_msg

                return f"No server found with tool: {tool_call['tool']}"
            return llm_response
        except json.JSONDecodeError:
            return llm_response

    async def start(self) -> None:
        """Main chat session handler."""
        try:
            for server in self.servers:
                try:
                    await server.initialize()
                except Exception as e:
                    logging.error(f"Failed to initialize server: {e}")
                    await self.cleanup_servers()
                    return

            all_tools = []
            for server in self.servers:
                tools = await server.list_tools()
                all_tools.extend(tools)

            tools_description = "\n".join([tool.format_for_llm() for tool in all_tools])

            system_message = (
                "You are a helpful assistant with access to these tools:\n\n"
                f"{tools_description}\n"
                "Choose the appropriate tool based on the user's question. "
                "If no tool is needed, reply directly.\n\n"
                "IMPORTANT: When you need to use a tool, you must ONLY respond with "
                "the exact JSON object format below, nothing else:\n"
                "{\n"
                '    "tool": "tool-name",\n'
                '    "arguments": {\n'
                '        "argument-name": "value"\n'
                "    }\n"
                "}\n\n"
                "After receiving a tool's response:\n"
                "1. Transform the raw data into a natural, conversational response\n"
                "2. Keep responses concise but informative\n"
                "3. Focus on the most relevant information\n"
                "4. Use appropriate context from the user's question\n"
                "5. Avoid simply repeating the raw data\n\n"
                "Please use only the tools that are explicitly defined above."
            )

            messages = [{"role": "system", "content": system_message}]

            while True:
                try:
                    user_input = input("You: ").strip().lower()
                    if user_input in ["quit", "exit"]:
                        logging.info("\nExiting...")
                        break

                    messages.append({"role": "user", "content": user_input})

                    llm_response = self.llm_client.get_response(messages)
                    logging.info("\nAssistant: %s", llm_response)

                    result = await self.process_llm_response(llm_response)

                    if result != llm_response:
                        messages.append({"role": "assistant", "content": llm_response})
                        messages.append({"role": "system", "content": result})

                        final_response = self.llm_client.get_response(messages)
                        logging.info("\nFinal response: %s", final_response)
                        messages.append(
                            {"role": "assistant", "content": final_response}
                        )
                    else:
                        messages.append({"role": "assistant", "content": llm_response})

                except KeyboardInterrupt:
                    logging.info("\nExiting...")
                    break

        finally:
            await self.cleanup_servers()

## main

**Type**: Function

**Description**: async def main() -> None:
    """Initialize and run the chat session."""
    config = Configuration()
    server_config = config.load_config("servers_config.json")
    servers = [
        Server(name, srv_config)
        for name, srv_config in server_config["mcpServers"].items()
    ]
    llm_client = LLMClient(config.llm_api_key)
    chat_session = ChatSession(servers, llm_client)
    await chat_session.start()

## ShrimpTank

**Type**: Class

**Description**: class ShrimpTank(BaseModel):
    class Shrimp(BaseModel):
        name: Annotated[str, Field(max_length=10)]

    shrimp: list[Shrimp]

## cosine_similarity

**Type**: Function

**Description**: def cosine_similarity(a: list[float], b: list[float]) -> float:
    a_array = np.array(a, dtype=np.float64)
    b_array = np.array(b, dtype=np.float64)
    return np.dot(a_array, b_array) / (np.linalg.norm(a_array) * np.linalg.norm(b_array))

## do_ai

**Type**: Function

**Description**: async def do_ai[T](
    user_prompt: str,
    system_prompt: str,
    result_type: type[T] | Annotated,
    deps=None,
) -> T:
    agent = Agent(
        DEFAULT_LLM_MODEL,
        system_prompt=system_prompt,
        result_type=result_type,
    )
    result = await agent.run(user_prompt, deps=deps)
    return result.data

## get_db_pool

**Type**: Function

**Description**: async def get_db_pool() -> asyncpg.Pool:
    async def init(conn):
        await conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        await register_vector(conn)

    pool = await asyncpg.create_pool(DB_DSN, init=init)
    return pool

## MemoryNode

**Type**: Class

**Description**: class MemoryNode(BaseModel):
    id: int | None = None
    content: str
    summary: str = ""
    importance: float = 1.0
    access_count: int = 0
    timestamp: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    embedding: list[float]

    @classmethod
    async def from_content(cls, content: str, deps: Deps):
        embedding = await get_embedding(content, deps)
        return cls(content=content, embedding=embedding)

    async def save(self, deps: Deps):
        async with deps.pool.acquire() as conn:
            if self.id is None:
                result = await conn.fetchrow(
                    """
                    INSERT INTO memories (content, summary, importance, access_count,
                        timestamp, embedding)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    RETURNING id
                    """,
                    self.content,
                    self.summary,
                    self.importance,
                    self.access_count,
                    self.timestamp,
                    self.embedding,
                )
                self.id = result["id"]
            else:
                await conn.execute(
                    """
                    UPDATE memories
                    SET content = $1, summary = $2, importance = $3,
                        access_count = $4, timestamp = $5, embedding = $6
                    WHERE id = $7
                    """,
                    self.content,
                    self.summary,
                    self.importance,
                    self.access_count,
                    self.timestamp,
                    self.embedding,
                    self.id,
                )

    async def merge_with(self, other: Self, deps: Deps):
        self.content = await do_ai(
            f"{self.content}\n\n{other.content}",
            "Combine the following two texts into a single, coherent text.",
            str,
            deps,
        )
        self.importance += other.importance
        self.access_count += other.access_count
        self.embedding = [(a + b) / 2 for a, b in zip(self.embedding, other.embedding)]
        self.summary = await do_ai(self.content, "Summarize the following text concisely.", str, deps)
        await self.save(deps)
        # Delete the merged node from the database
        if other.id is not None:
            await delete_memory(other.id, deps)

    def get_effective_importance(self):
        return self.importance * (1 + math.log(self.access_count + 1))

## get_embedding

**Type**: Function

**Description**: async def get_embedding(text: str, deps: Deps) -> list[float]:
    embedding_response = await deps.openai.embeddings.create(
        input=text,
        model=DEFAULT_EMBEDDING_MODEL,
    )
    return embedding_response.data[0].embedding

## delete_memory

**Type**: Function

**Description**: async def delete_memory(memory_id: int, deps: Deps):
    async with deps.pool.acquire() as conn:
        await conn.execute("DELETE FROM memories WHERE id = $1", memory_id)

## add_memory

**Type**: Function

**Description**: async def add_memory(content: str, deps: Deps):
    new_memory = await MemoryNode.from_content(content, deps)
    await new_memory.save(deps)

    similar_memories = await find_similar_memories(new_memory.embedding, deps)
    for memory in similar_memories:
        if memory.id != new_memory.id:
            await new_memory.merge_with(memory, deps)

    await update_importance(new_memory.embedding, deps)

    await prune_memories(deps)

    return f"Remembered: {content}"

## find_similar_memories

**Type**: Function

**Description**: async def find_similar_memories(embedding: list[float], deps: Deps) -> list[MemoryNode]:
    async with deps.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, content, summary, importance, access_count, timestamp, embedding
            FROM memories
            ORDER BY embedding <-> $1
            LIMIT 5
            """,
            embedding,
        )
    memories = [
        MemoryNode(
            id=row["id"],
            content=row["content"],
            summary=row["summary"],
            importance=row["importance"],
            access_count=row["access_count"],
            timestamp=row["timestamp"],
            embedding=row["embedding"],
        )
        for row in rows
    ]
    return memories

## update_importance

**Type**: Function

**Description**: async def update_importance(user_embedding: list[float], deps: Deps):
    async with deps.pool.acquire() as conn:
        rows = await conn.fetch("SELECT id, importance, access_count, embedding FROM memories")
        for row in rows:
            memory_embedding = row["embedding"]
            similarity = cosine_similarity(user_embedding, memory_embedding)
            if similarity > SIMILARITY_THRESHOLD:
                new_importance = row["importance"] * REINFORCEMENT_FACTOR
                new_access_count = row["access_count"] + 1
            else:
                new_importance = row["importance"] * DECAY_FACTOR
                new_access_count = row["access_count"]
            await conn.execute(
                """
                UPDATE memories
                SET importance = $1, access_count = $2
                WHERE id = $3
                """,
                new_importance,
                new_access_count,
                row["id"],
            )

## prune_memories

**Type**: Function

**Description**: async def prune_memories(deps: Deps):
    async with deps.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, importance, access_count
            FROM memories
            ORDER BY importance DESC
            OFFSET $1
            """,
            MAX_DEPTH,
        )
        for row in rows:
            await conn.execute("DELETE FROM memories WHERE id = $1", row["id"])

## display_memory_tree

**Type**: Function

**Description**: async def display_memory_tree(deps: Deps) -> str:
    async with deps.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT content, summary, importance, access_count
            FROM memories
            ORDER BY importance DESC
            LIMIT $1
            """,
            MAX_DEPTH,
        )
    result = ""
    for row in rows:
        effective_importance = row["importance"] * (1 + math.log(row["access_count"] + 1))
        summary = row["summary"] or row["content"]
        result += f"- {summary} (Importance: {effective_importance:.2f})\n"
    return result

## initialize_database

**Type**: Function

**Description**: async def initialize_database():
    pool = await asyncpg.create_pool("postgresql://postgres:postgres@localhost:54320/postgres")
    try:
        async with pool.acquire() as conn:
            await conn.execute("""
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = 'memory_db'
                AND pid <> pg_backend_pid();
            """)
            await conn.execute("DROP DATABASE IF EXISTS memory_db;")
            await conn.execute("CREATE DATABASE memory_db;")
    finally:
        await pool.close()

    pool = await asyncpg.create_pool(DB_DSN)
    try:
        async with pool.acquire() as conn:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")

            await register_vector(conn)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS memories (
                    id SERIAL PRIMARY KEY,
                    content TEXT NOT NULL,
                    summary TEXT,
                    importance REAL NOT NULL,
                    access_count INT NOT NULL,
                    timestamp DOUBLE PRECISION NOT NULL,
                    embedding vector(1536) NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_memories_embedding ON memories
                    USING hnsw (embedding vector_l2_ops);
            """)
    finally:
        await pool.close()

## SurgeSettings

**Type**: Class

**Description**: class SurgeSettings(BaseSettings):
    model_config: SettingsConfigDict = SettingsConfigDict(env_prefix="SURGE_", env_file=".env")

    api_key: str
    account_id: str
    my_phone_number: Annotated[str, BeforeValidator(lambda v: "+" + v if not v.startswith("+") else v)]
    my_first_name: str
    my_last_name: str

## WeatherData

**Type**: Class

**Description**: class WeatherData(BaseModel):
    """Structured weather data response"""

    temperature: float = Field(description="Temperature in Celsius")
    humidity: float = Field(description="Humidity percentage (0-100)")
    condition: str = Field(description="Weather condition (sunny, cloudy, rainy, etc.)")
    wind_speed: float = Field(description="Wind speed in km/h")
    location: str = Field(description="Location name")
    timestamp: datetime = Field(default_factory=datetime.now, description="Observation time")

## WeatherSummary

**Type**: Class

**Description**: class WeatherSummary(TypedDict):
    """Simple weather summary"""

    city: str
    temp_c: float
    description: str

## DailyStats

**Type**: Class

**Description**: class DailyStats(BaseModel):
    """Statistics for a single day"""

    high: float
    low: float
    mean: float

## WeatherStats

**Type**: Class

**Description**: class WeatherStats(BaseModel):
    """Weather statistics over a period"""

    location: str
    period_days: int
    temperature: DailyStats
    humidity: DailyStats
    precipitation_mm: float = Field(description="Total precipitation in millimeters")

## run

**Type**: Function

**Description**: async def run():
    """Run the low-level server using stdio transport."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="structured-output-lowlevel-example",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

## AuthServerSettings

**Type**: Class

**Description**: class AuthServerSettings(BaseModel):
    """Settings for the Authorization Server."""

    # Server settings
    host: str = "localhost"
    port: int = 9000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:9000")
    auth_callback_path: str = "http://localhost:9000/login/callback"

## SimpleAuthProvider

**Type**: Class

**Description**: class SimpleAuthProvider(SimpleOAuthProvider):
    """
    Authorization Server provider with simple demo authentication.

    This provider:
    1. Issues MCP tokens after simple credential authentication
    2. Stores token state for introspection by Resource Servers
    """

    def __init__(self, auth_settings: SimpleAuthSettings, auth_callback_path: str, server_url: str):
        super().__init__(auth_settings, auth_callback_path, server_url)

## create_authorization_server

**Type**: Function

**Description**: def create_authorization_server(server_settings: AuthServerSettings, auth_settings: SimpleAuthSettings) -> Starlette:
    """Create the Authorization Server application."""
    oauth_provider = SimpleAuthProvider(
        auth_settings, server_settings.auth_callback_path, str(server_settings.server_url)
    )

    mcp_auth_settings = AuthSettings(
        issuer_url=server_settings.server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[auth_settings.mcp_scope],
            default_scopes=[auth_settings.mcp_scope],
        ),
        required_scopes=[auth_settings.mcp_scope],
        resource_server_url=None,
    )

    # Create OAuth routes
    routes = create_auth_routes(
        provider=oauth_provider,
        issuer_url=mcp_auth_settings.issuer_url,
        service_documentation_url=mcp_auth_settings.service_documentation_url,
        client_registration_options=mcp_auth_settings.client_registration_options,
        revocation_options=mcp_auth_settings.revocation_options,
    )

    # Add login page route (GET)
    async def login_page_handler(request: Request) -> Response:
        """Show login form."""
        state = request.query_params.get("state")
        if not state:
            raise HTTPException(400, "Missing state parameter")
        return await oauth_provider.get_login_page(state)

    routes.append(Route("/login", endpoint=login_page_handler, methods=["GET"]))

    # Add login callback route (POST)
    async def login_callback_handler(request: Request) -> Response:
        """Handle simple authentication callback."""
        return await oauth_provider.handle_login_callback(request)

    routes.append(Route("/login/callback", endpoint=login_callback_handler, methods=["POST"]))

    # Add token introspection endpoint (RFC 7662) for Resource Servers
    async def introspect_handler(request: Request) -> Response:
        """
        Token introspection endpoint for Resource Servers.

        Resource Servers call this endpoint to validate tokens without
        needing direct access to token storage.
        """
        form = await request.form()
        token = form.get("token")
        if not token or not isinstance(token, str):
            return JSONResponse({"active": False}, status_code=400)

        # Look up token in provider
        access_token = await oauth_provider.load_access_token(token)
        if not access_token:
            return JSONResponse({"active": False})

        return JSONResponse(
            {
                "active": True,
                "client_id": access_token.client_id,
                "scope": " ".join(access_token.scopes),
                "exp": access_token.expires_at,
                "iat": int(time.time()),
                "token_type": "Bearer",
                "aud": access_token.resource,  # RFC 8707 audience claim
            }
        )

    routes.append(
        Route(
            "/introspect",
            endpoint=cors_middleware(introspect_handler, ["POST", "OPTIONS"]),
            methods=["POST", "OPTIONS"],
        )
    )

    return Starlette(routes=routes)

## run_server

**Type**: Function

**Description**: async def run_server(server_settings: AuthServerSettings, auth_settings: SimpleAuthSettings):
    """Run the Authorization Server."""
    auth_server = create_authorization_server(server_settings, auth_settings)

    config = Config(
        auth_server,
        host=server_settings.host,
        port=server_settings.port,
        log_level="info",
    )
    server = Server(config)

    logger.info(f"🚀 MCP Authorization Server running on {server_settings.server_url}")

    await server.serve()

## ServerSettings

**Type**: Class

**Description**: class ServerSettings(BaseModel):
    """Settings for the simple auth MCP server."""

    # Server settings
    host: str = "localhost"
    port: int = 8000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8000")
    auth_callback_path: str = "http://localhost:8000/login/callback"

## LegacySimpleOAuthProvider

**Type**: Class

**Description**: class LegacySimpleOAuthProvider(SimpleOAuthProvider):
    """Simple OAuth provider for legacy MCP server."""

    def __init__(self, auth_settings: SimpleAuthSettings, auth_callback_path: str, server_url: str):
        super().__init__(auth_settings, auth_callback_path, server_url)

## create_simple_mcp_server

**Type**: Function

**Description**: def create_simple_mcp_server(server_settings: ServerSettings, auth_settings: SimpleAuthSettings) -> FastMCP:
    """Create a simple FastMCP server with simple authentication."""
    oauth_provider = LegacySimpleOAuthProvider(
        auth_settings, server_settings.auth_callback_path, str(server_settings.server_url)
    )

    mcp_auth_settings = AuthSettings(
        issuer_url=server_settings.server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[auth_settings.mcp_scope],
            default_scopes=[auth_settings.mcp_scope],
        ),
        required_scopes=[auth_settings.mcp_scope],
        # No resource_server_url parameter in legacy mode
        resource_server_url=None,
    )

    app = FastMCP(
        name="Simple Auth MCP Server",
        instructions="A simple MCP server with simple credential authentication",
        auth_server_provider=oauth_provider,
        host=server_settings.host,
        port=server_settings.port,
        debug=True,
        auth=mcp_auth_settings,
    )

    @app.custom_route("/login", methods=["GET"])
    async def login_page_handler(request: Request) -> Response:
        """Show login form."""
        state = request.query_params.get("state")
        if not state:
            raise HTTPException(400, "Missing state parameter")
        return await oauth_provider.get_login_page(state)

    @app.custom_route("/login/callback", methods=["POST"])
    async def login_callback_handler(request: Request) -> Response:
        """Handle simple authentication callback."""
        return await oauth_provider.handle_login_callback(request)

    @app.tool()
    async def get_time() -> dict[str, Any]:
        """
        Get the current server time.

        This tool demonstrates that system information can be protected
        by OAuth authentication. User must be authenticated to access it.
        """

        now = datetime.datetime.now()

        return {
            "current_time": now.isoformat(),
            "timezone": "UTC",  # Simplified for demo
            "timestamp": now.timestamp(),
            "formatted": now.strftime("%Y-%m-%d %H:%M:%S"),
        }

    return app

## ResourceServerSettings

**Type**: Class

**Description**: class ResourceServerSettings(BaseSettings):
    """Settings for the MCP Resource Server."""

    model_config = SettingsConfigDict(env_prefix="MCP_RESOURCE_")

    # Server settings
    host: str = "localhost"
    port: int = 8001
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8001")

    # Authorization Server settings
    auth_server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:9000")
    auth_server_introspection_endpoint: str = "http://localhost:9000/introspect"
    # No user endpoint needed - we get user data from token introspection

    # MCP settings
    mcp_scope: str = "user"

    # RFC 8707 resource validation
    oauth_strict: bool = False

    def __init__(self, **data):
        """Initialize settings with values from environment variables."""
        super().__init__(**data)

## create_resource_server

**Type**: Function

**Description**: def create_resource_server(settings: ResourceServerSettings) -> FastMCP:
    """
    Create MCP Resource Server with token introspection.

    This server:
    1. Provides protected resource metadata (RFC 9728)
    2. Validates tokens via Authorization Server introspection
    3. Serves MCP tools and resources
    """
    # Create token verifier for introspection with RFC 8707 resource validation
    token_verifier = IntrospectionTokenVerifier(
        introspection_endpoint=settings.auth_server_introspection_endpoint,
        server_url=str(settings.server_url),
        validate_resource=settings.oauth_strict,  # Only validate when --oauth-strict is set
    )

    # Create FastMCP server as a Resource Server
    app = FastMCP(
        name="MCP Resource Server",
        instructions="Resource Server that validates tokens via Authorization Server introspection",
        host=settings.host,
        port=settings.port,
        debug=True,
        # Auth configuration for RS mode
        token_verifier=token_verifier,
        auth=AuthSettings(
            issuer_url=settings.auth_server_url,
            required_scopes=[settings.mcp_scope],
            resource_server_url=settings.server_url,
        ),
    )

    @app.tool()
    async def get_time() -> dict[str, Any]:
        """
        Get the current server time.

        This tool demonstrates that system information can be protected
        by OAuth authentication. User must be authenticated to access it.
        """

        now = datetime.datetime.now()

        return {
            "current_time": now.isoformat(),
            "timezone": "UTC",  # Simplified for demo
            "timestamp": now.timestamp(),
            "formatted": now.strftime("%Y-%m-%d %H:%M:%S"),
        }

    return app

## SimpleAuthSettings

**Type**: Class

**Description**: class SimpleAuthSettings(BaseSettings):
    """Simple OAuth settings for demo purposes."""

    model_config = SettingsConfigDict(env_prefix="MCP_")

    # Demo user credentials
    demo_username: str = "demo_user"
    demo_password: str = "demo_password"

    # MCP OAuth scope
    mcp_scope: str = "user"

## SimpleOAuthProvider

**Type**: Class

**Description**: class SimpleOAuthProvider(OAuthAuthorizationServerProvider):
    """
    Simple OAuth provider for demo purposes.

    This provider handles the OAuth flow by:
    1. Providing a simple login form for demo credentials
    2. Issuing MCP tokens after successful authentication
    3. Maintaining token state for introspection
    """

    def __init__(self, settings: SimpleAuthSettings, auth_callback_url: str, server_url: str):
        self.settings = settings
        self.auth_callback_url = auth_callback_url
        self.server_url = server_url
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str | None]] = {}
        # Store authenticated user information
        self.user_data: dict[str, dict[str, Any]] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Register a new OAuth client."""
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Generate an authorization URL for simple login flow."""
        state = params.state or secrets.token_hex(16)

        # Store state mapping for callback
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,  # RFC 8707
        }

        # Build simple login URL that points to login page
        auth_url = f"{self.auth_callback_url}" f"?state={state}" f"&client_id={client.client_id}"

        return auth_url

    async def get_login_page(self, state: str) -> HTMLResponse:
        """Generate login page HTML for the given state."""
        if not state:
            raise HTTPException(400, "Missing state parameter")

        # Create simple login form HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MCP Demo Authentication</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }}
                .form-group {{ margin-bottom: 15px; }}
                input {{ width: 100%; padding: 8px; margin-top: 5px; }}
                button {{ background-color: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }}
            </style>
        </head>
        <body>
            <h2>MCP Demo Authentication</h2>
            <p>This is a simplified authentication demo. Use the demo credentials below:</p>
            <p><strong>Username:</strong> demo_user<br>
            <strong>Password:</strong> demo_password</p>
            
            <form action="{self.server_url.rstrip('/')}/login/callback" method="post">
                <input type="hidden" name="state" value="{state}">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" value="demo_user" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" value="demo_password" required>
                </div>
                <button type="submit">Sign In</button>
            </form>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    async def handle_login_callback(self, request: Request) -> Response:
        """Handle login form submission callback."""
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        state = form.get("state")

        if not username or not password or not state:
            raise HTTPException(400, "Missing username, password, or state parameter")

        # Ensure we have strings, not UploadFile objects
        if not isinstance(username, str) or not isinstance(password, str) or not isinstance(state, str):
            raise HTTPException(400, "Invalid parameter types")

        redirect_uri = await self.handle_simple_callback(username, password, state)
        return RedirectResponse(url=redirect_uri, status_code=302)

    async def handle_simple_callback(self, username: str, password: str, state: str) -> str:
        """Handle simple authentication callback and return redirect URI."""
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = state_data["redirect_uri_provided_explicitly"] == "True"
        client_id = state_data["client_id"]
        resource = state_data.get("resource")  # RFC 8707

        # These are required values from our own state mapping
        assert redirect_uri is not None
        assert code_challenge is not None
        assert client_id is not None

        # Validate demo credentials
        if username != self.settings.demo_username or password != self.settings.demo_password:
            raise HTTPException(401, "Invalid credentials")

        # Create MCP authorization code
        new_code = f"mcp_{secrets.token_hex(16)}"
        auth_code = AuthorizationCode(
            code=new_code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=[self.settings.mcp_scope],
            code_challenge=code_challenge,
            resource=resource,  # RFC 8707
        )
        self.auth_codes[new_code] = auth_code

        # Store user data
        self.user_data[username] = {
            "username": username,
            "user_id": f"user_{secrets.token_hex(8)}",
            "authenticated_at": time.time(),
        }

        del self.state_mapping[state]
        return construct_redirect_uri(redirect_uri, code=new_code, state=state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store MCP token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
            resource=authorization_code.resource,  # RFC 8707
        )

        # Store user data mapping for this token
        self.user_data[mcp_token] = {
            "username": self.settings.demo_username,
            "user_id": f"user_{secrets.token_hex(8)}",
            "authenticated_at": time.time(),
        }

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        # Check if expired
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        """Load a refresh token - not supported in this example."""
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token - not supported in this example."""
        raise NotImplementedError("Refresh tokens not supported")

    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]

## IntrospectionTokenVerifier

**Type**: Class

**Description**: class IntrospectionTokenVerifier(TokenVerifier):
    """Example token verifier that uses OAuth 2.0 Token Introspection (RFC 7662).

    This is a simple example implementation for demonstration purposes.
    Production implementations should consider:
    - Connection pooling and reuse
    - More sophisticated error handling
    - Rate limiting and retry logic
    - Comprehensive configuration options
    """

    def __init__(
        self,
        introspection_endpoint: str,
        server_url: str,
        validate_resource: bool = False,
    ):
        self.introspection_endpoint = introspection_endpoint
        self.server_url = server_url
        self.validate_resource = validate_resource
        self.resource_url = resource_url_from_server_url(server_url)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify token via introspection endpoint."""
        import httpx

        # Validate URL to prevent SSRF attacks
        if not self.introspection_endpoint.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            logger.warning(f"Rejecting introspection endpoint with unsafe scheme: {self.introspection_endpoint}")
            return None

        # Configure secure HTTP client
        timeout = httpx.Timeout(10.0, connect=5.0)
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            verify=True,  # Enforce SSL verification
        ) as client:
            try:
                response = await client.post(
                    self.introspection_endpoint,
                    data={"token": token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code != 200:
                    logger.debug(f"Token introspection returned status {response.status_code}")
                    return None

                data = response.json()
                if not data.get("active", False):
                    return None

                # RFC 8707 resource validation (only when --oauth-strict is set)
                if self.validate_resource and not self._validate_resource(data):
                    logger.warning(f"Token resource validation failed. Expected: {self.resource_url}")
                    return None

                return AccessToken(
                    token=token,
                    client_id=data.get("client_id", "unknown"),
                    scopes=data.get("scope", "").split() if data.get("scope") else [],
                    expires_at=data.get("exp"),
                    resource=data.get("aud"),  # Include resource in token
                )
            except Exception as e:
                logger.warning(f"Token introspection failed: {e}")
                return None

    def _validate_resource(self, token_data: dict) -> bool:
        """Validate token was issued for this resource server."""
        if not self.server_url or not self.resource_url:
            return False  # Fail if strict validation requested but URLs missing

        # Check 'aud' claim first (standard JWT audience)
        aud = token_data.get("aud")
        if isinstance(aud, list):
            for audience in aud:
                if self._is_valid_resource(audience):
                    return True
            return False
        elif aud:
            return self._is_valid_resource(aud)

        # No resource binding - invalid per RFC 8707
        return False

    def _is_valid_resource(self, resource: str) -> bool:
        """Check if resource matches this server using hierarchical matching."""
        if not self.resource_url:
            return False

        return check_resource_allowed(requested_resource=self.resource_url, configured_resource=resource)

## create_messages

**Type**: Function

**Description**: def create_messages(
    context: str | None = None, topic: str | None = None
) -> list[types.PromptMessage]:
    """Create the messages for the prompt."""
    messages = []

    # Add context if provided
    if context:
        messages.append(
            types.PromptMessage(
                role="user",
                content=types.TextContent(
                    type="text", text=f"Here is some relevant context: {context}"
                ),
            )
        )

    # Add the main prompt
    prompt = "Please help me with "
    if topic:
        prompt += f"the following topic: {topic}"
    else:
        prompt += "whatever questions I may have."

    messages.append(
        types.PromptMessage(
            role="user", content=types.TextContent(type="text", text=prompt)
        )
    )

    return messages

## InMemoryEventStore

**Type**: Class

**Description**: class InMemoryEventStore(EventStore):
    """
    Simple in-memory implementation of the EventStore interface for resumability.
    This is primarily intended for examples and testing, not for production use
    where a persistent storage solution would be more appropriate.

    This implementation keeps only the last N events per stream for memory efficiency.
    """

    def __init__(self, max_events_per_stream: int = 100):
        """Initialize the event store.

        Args:
            max_events_per_stream: Maximum number of events to keep per stream
        """
        self.max_events_per_stream = max_events_per_stream
        # for maintaining last N events per stream
        self.streams: dict[StreamId, deque[EventEntry]] = {}
        # event_id -> EventEntry for quick lookup
        self.event_index: dict[EventId, EventEntry] = {}

    async def store_event(
        self, stream_id: StreamId, message: JSONRPCMessage
    ) -> EventId:
        """Stores an event with a generated event ID."""
        event_id = str(uuid4())
        event_entry = EventEntry(
            event_id=event_id, stream_id=stream_id, message=message
        )

        # Get or create deque for this stream
        if stream_id not in self.streams:
            self.streams[stream_id] = deque(maxlen=self.max_events_per_stream)

        # If deque is full, the oldest event will be automatically removed
        # We need to remove it from the event_index as well
        if len(self.streams[stream_id]) == self.max_events_per_stream:
            oldest_event = self.streams[stream_id][0]
            self.event_index.pop(oldest_event.event_id, None)

        # Add new event
        self.streams[stream_id].append(event_entry)
        self.event_index[event_id] = event_entry

        return event_id

    async def replay_events_after(
        self,
        last_event_id: EventId,
        send_callback: EventCallback,
    ) -> StreamId | None:
        """Replays events that occurred after the specified event ID."""
        if last_event_id not in self.event_index:
            logger.warning(f"Event ID {last_event_id} not found in store")
            return None

        # Get the stream and find events after the last one
        last_event = self.event_index[last_event_id]
        stream_id = last_event.stream_id
        stream_events = self.streams.get(last_event.stream_id, deque())

        # Events in deque are already in chronological order
        found_last = False
        for event in stream_events:
            if found_last:
                await send_callback(EventMessage(event.message, event.event_id))
            elif event.event_id == last_event_id:
                found_last = True

        return stream_id

## fetch_website

**Type**: Function

**Description**: async def fetch_website(
    url: str,
) -> list[types.ContentBlock]:
    headers = {
        "User-Agent": "MCP Test Server (github.com/modelcontextprotocol/python-sdk)"
    }
    async with create_mcp_http_client(headers=headers) as client:
        response = await client.get(url)
        response.raise_for_status()
        return [types.TextContent(type="text", text=response.text)]

## RequestParams

**Type**: Class

**Description**: class RequestParams(BaseModel):
    class Meta(BaseModel):
        progressToken: ProgressToken | None = None
        """
        If specified, the caller requests out-of-band progress notifications for
        this request (as represented by notifications/progress). The value of this
        parameter is an opaque token that will be attached to any subsequent
        notifications. The receiver is not obligated to provide these notifications.
        """

        model_config = ConfigDict(extra="allow")

    meta: Meta | None = Field(alias="_meta", default=None)

## PaginatedRequestParams

**Type**: Class

**Description**: class PaginatedRequestParams(RequestParams):
    cursor: Cursor | None = None
    """
    An opaque token representing the current pagination position.
    If provided, the server should return results starting after this cursor.
    """

## NotificationParams

**Type**: Class

**Description**: class NotificationParams(BaseModel):
    class Meta(BaseModel):
        model_config = ConfigDict(extra="allow")

    meta: Meta | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """

## Request

**Type**: Class

**Description**: class Request(BaseModel, Generic[RequestParamsT, MethodT]):
    """Base class for JSON-RPC requests."""

    method: MethodT
    params: RequestParamsT
    model_config = ConfigDict(extra="allow")

## PaginatedRequest

**Type**: Class

**Description**: class PaginatedRequest(Request[PaginatedRequestParams | None, MethodT], Generic[MethodT]):
    """Base class for paginated requests,
    matching the schema's PaginatedRequest interface."""

    params: PaginatedRequestParams | None = None

## Notification

**Type**: Class

**Description**: class Notification(BaseModel, Generic[NotificationParamsT, MethodT]):
    """Base class for JSON-RPC notifications."""

    method: MethodT
    params: NotificationParamsT
    model_config = ConfigDict(extra="allow")

## Result

**Type**: Class

**Description**: class Result(BaseModel):
    """Base class for JSON-RPC results."""

    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## PaginatedResult

**Type**: Class

**Description**: class PaginatedResult(Result):
    nextCursor: Cursor | None = None
    """
    An opaque token representing the pagination position after the last returned result.
    If present, there may be more results available.
    """

## JSONRPCRequest

**Type**: Class

**Description**: class JSONRPCRequest(Request[dict[str, Any] | None, str]):
    """A request that expects a response."""

    jsonrpc: Literal["2.0"]
    id: RequestId
    method: str
    params: dict[str, Any] | None = None

## JSONRPCNotification

**Type**: Class

**Description**: class JSONRPCNotification(Notification[dict[str, Any] | None, str]):
    """A notification which does not expect a response."""

    jsonrpc: Literal["2.0"]
    params: dict[str, Any] | None = None

## JSONRPCResponse

**Type**: Class

**Description**: class JSONRPCResponse(BaseModel):
    """A successful (non-error) response to a request."""

    jsonrpc: Literal["2.0"]
    id: RequestId
    result: dict[str, Any]
    model_config = ConfigDict(extra="allow")

## ErrorData

**Type**: Class

**Description**: class ErrorData(BaseModel):
    """Error information for JSON-RPC error responses."""

    code: int
    """The error type that occurred."""

    message: str
    """
    A short description of the error. The message SHOULD be limited to a concise single
    sentence.
    """

    data: Any | None = None
    """
    Additional information about the error. The value of this member is defined by the
    sender (e.g. detailed error information, nested errors etc.).
    """

    model_config = ConfigDict(extra="allow")

## JSONRPCError

**Type**: Class

**Description**: class JSONRPCError(BaseModel):
    """A response to a request that indicates an error occurred."""

    jsonrpc: Literal["2.0"]
    id: str | int
    error: ErrorData
    model_config = ConfigDict(extra="allow")

## JSONRPCMessage

**Type**: Class

**Description**: class JSONRPCMessage(RootModel[JSONRPCRequest | JSONRPCNotification | JSONRPCResponse | JSONRPCError]):
    pass

## EmptyResult

**Type**: Class

**Description**: class EmptyResult(Result):
    """A response that indicates success but carries no data."""

## BaseMetadata

**Type**: Class

**Description**: class BaseMetadata(BaseModel):
    """Base class for entities with name and optional title fields."""

    name: str
    """The programmatic name of the entity."""

    title: str | None = None
    """
    Intended for UI and end-user contexts — optimized to be human-readable and easily understood,
    even by those unfamiliar with domain-specific terminology.

    If not provided, the name should be used for display (except for Tool,
    where `annotations.title` should be given precedence over using `name`,
    if present).
    """

## Implementation

**Type**: Class

**Description**: class Implementation(BaseMetadata):
    """Describes the name and version of an MCP implementation."""

    version: str
    model_config = ConfigDict(extra="allow")

## RootsCapability

**Type**: Class

**Description**: class RootsCapability(BaseModel):
    """Capability for root operations."""

    listChanged: bool | None = None
    """Whether the client supports notifications for changes to the roots list."""
    model_config = ConfigDict(extra="allow")

## SamplingCapability

**Type**: Class

**Description**: class SamplingCapability(BaseModel):
    """Capability for sampling operations."""

    model_config = ConfigDict(extra="allow")

## ElicitationCapability

**Type**: Class

**Description**: class ElicitationCapability(BaseModel):
    """Capability for elicitation operations."""

    model_config = ConfigDict(extra="allow")

## ClientCapabilities

**Type**: Class

**Description**: class ClientCapabilities(BaseModel):
    """Capabilities a client may support."""

    experimental: dict[str, dict[str, Any]] | None = None
    """Experimental, non-standard capabilities that the client supports."""
    sampling: SamplingCapability | None = None
    """Present if the client supports sampling from an LLM."""
    elicitation: ElicitationCapability | None = None
    """Present if the client supports elicitation from the user."""
    roots: RootsCapability | None = None
    """Present if the client supports listing roots."""
    model_config = ConfigDict(extra="allow")

## PromptsCapability

**Type**: Class

**Description**: class PromptsCapability(BaseModel):
    """Capability for prompts operations."""

    listChanged: bool | None = None
    """Whether this server supports notifications for changes to the prompt list."""
    model_config = ConfigDict(extra="allow")

## ResourcesCapability

**Type**: Class

**Description**: class ResourcesCapability(BaseModel):
    """Capability for resources operations."""

    subscribe: bool | None = None
    """Whether this server supports subscribing to resource updates."""
    listChanged: bool | None = None
    """Whether this server supports notifications for changes to the resource list."""
    model_config = ConfigDict(extra="allow")

## ToolsCapability

**Type**: Class

**Description**: class ToolsCapability(BaseModel):
    """Capability for tools operations."""

    listChanged: bool | None = None
    """Whether this server supports notifications for changes to the tool list."""
    model_config = ConfigDict(extra="allow")

## LoggingCapability

**Type**: Class

**Description**: class LoggingCapability(BaseModel):
    """Capability for logging operations."""

    model_config = ConfigDict(extra="allow")

## ServerCapabilities

**Type**: Class

**Description**: class ServerCapabilities(BaseModel):
    """Capabilities that a server may support."""

    experimental: dict[str, dict[str, Any]] | None = None
    """Experimental, non-standard capabilities that the server supports."""
    logging: LoggingCapability | None = None
    """Present if the server supports sending log messages to the client."""
    prompts: PromptsCapability | None = None
    """Present if the server offers any prompt templates."""
    resources: ResourcesCapability | None = None
    """Present if the server offers any resources to read."""
    tools: ToolsCapability | None = None
    """Present if the server offers any tools to call."""
    model_config = ConfigDict(extra="allow")

## InitializeRequestParams

**Type**: Class

**Description**: class InitializeRequestParams(RequestParams):
    """Parameters for the initialize request."""

    protocolVersion: str | int
    """The latest version of the Model Context Protocol that the client supports."""
    capabilities: ClientCapabilities
    clientInfo: Implementation
    model_config = ConfigDict(extra="allow")

## InitializeRequest

**Type**: Class

**Description**: class InitializeRequest(Request[InitializeRequestParams, Literal["initialize"]]):
    """
    This request is sent from the client to the server when it first connects, asking it
    to begin initialization.
    """

    method: Literal["initialize"]
    params: InitializeRequestParams

## InitializeResult

**Type**: Class

**Description**: class InitializeResult(Result):
    """After receiving an initialize request from the client, the server sends this."""

    protocolVersion: str | int
    """The version of the Model Context Protocol that the server wants to use."""
    capabilities: ServerCapabilities
    serverInfo: Implementation
    instructions: str | None = None
    """Instructions describing how to use the server and its features."""

## InitializedNotification

**Type**: Class

**Description**: class InitializedNotification(Notification[NotificationParams | None, Literal["notifications/initialized"]]):
    """
    This notification is sent from the client to the server after initialization has
    finished.
    """

    method: Literal["notifications/initialized"]
    params: NotificationParams | None = None

## PingRequest

**Type**: Class

**Description**: class PingRequest(Request[RequestParams | None, Literal["ping"]]):
    """
    A ping, issued by either the server or the client, to check that the other party is
    still alive.
    """

    method: Literal["ping"]
    params: RequestParams | None = None

## ProgressNotificationParams

**Type**: Class

**Description**: class ProgressNotificationParams(NotificationParams):
    """Parameters for progress notifications."""

    progressToken: ProgressToken
    """
    The progress token which was given in the initial request, used to associate this
    notification with the request that is proceeding.
    """
    progress: float
    """
    The progress thus far. This should increase every time progress is made, even if the
    total is unknown.
    """
    total: float | None = None
    """Total number of items to process (or total progress required), if known."""
    message: str | None = None
    """
    Message related to progress. This should provide relevant human readable
    progress information.
    """
    model_config = ConfigDict(extra="allow")

## ProgressNotification

**Type**: Class

**Description**: class ProgressNotification(Notification[ProgressNotificationParams, Literal["notifications/progress"]]):
    """
    An out-of-band notification used to inform the receiver of a progress update for a
    long-running request.
    """

    method: Literal["notifications/progress"]
    params: ProgressNotificationParams

## ListResourcesRequest

**Type**: Class

**Description**: class ListResourcesRequest(PaginatedRequest[Literal["resources/list"]]):
    """Sent from the client to request a list of resources the server has."""

    method: Literal["resources/list"]

## Annotations

**Type**: Class

**Description**: class Annotations(BaseModel):
    audience: list[Role] | None = None
    priority: Annotated[float, Field(ge=0.0, le=1.0)] | None = None
    model_config = ConfigDict(extra="allow")

## Resource

**Type**: Class

**Description**: class Resource(BaseMetadata):
    """A known resource that the server is capable of reading."""

    uri: Annotated[AnyUrl, UrlConstraints(host_required=False)]
    """The URI of this resource."""
    description: str | None = None
    """A description of what this resource represents."""
    mimeType: str | None = None
    """The MIME type of this resource, if known."""
    size: int | None = None
    """
    The size of the raw resource content, in bytes (i.e., before base64 encoding
    or any tokenization), if known.

    This can be used by Hosts to display file sizes and estimate context window usage.
    """
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## ResourceTemplate

**Type**: Class

**Description**: class ResourceTemplate(BaseMetadata):
    """A template description for resources available on the server."""

    uriTemplate: str
    """
    A URI template (according to RFC 6570) that can be used to construct resource
    URIs.
    """
    description: str | None = None
    """A human-readable description of what this template is for."""
    mimeType: str | None = None
    """
    The MIME type for all resources that match this template. This should only be
    included if all resources matching this template have the same type.
    """
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## ListResourcesResult

**Type**: Class

**Description**: class ListResourcesResult(PaginatedResult):
    """The server's response to a resources/list request from the client."""

    resources: list[Resource]

## ListResourceTemplatesRequest

**Type**: Class

**Description**: class ListResourceTemplatesRequest(PaginatedRequest[Literal["resources/templates/list"]]):
    """Sent from the client to request a list of resource templates the server has."""

    method: Literal["resources/templates/list"]

## ListResourceTemplatesResult

**Type**: Class

**Description**: class ListResourceTemplatesResult(PaginatedResult):
    """The server's response to a resources/templates/list request from the client."""

    resourceTemplates: list[ResourceTemplate]

## ReadResourceRequestParams

**Type**: Class

**Description**: class ReadResourceRequestParams(RequestParams):
    """Parameters for reading a resource."""

    uri: Annotated[AnyUrl, UrlConstraints(host_required=False)]
    """
    The URI of the resource to read. The URI can use any protocol; it is up to the
    server how to interpret it.
    """
    model_config = ConfigDict(extra="allow")

## ReadResourceRequest

**Type**: Class

**Description**: class ReadResourceRequest(Request[ReadResourceRequestParams, Literal["resources/read"]]):
    """Sent from the client to the server, to read a specific resource URI."""

    method: Literal["resources/read"]
    params: ReadResourceRequestParams

## ResourceContents

**Type**: Class

**Description**: class ResourceContents(BaseModel):
    """The contents of a specific resource or sub-resource."""

    uri: Annotated[AnyUrl, UrlConstraints(host_required=False)]
    """The URI of this resource."""
    mimeType: str | None = None
    """The MIME type of this resource, if known."""
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## TextResourceContents

**Type**: Class

**Description**: class TextResourceContents(ResourceContents):
    """Text contents of a resource."""

    text: str
    """
    The text of the item. This must only be set if the item can actually be represented
    as text (not binary data).
    """

## BlobResourceContents

**Type**: Class

**Description**: class BlobResourceContents(ResourceContents):
    """Binary contents of a resource."""

    blob: str
    """A base64-encoded string representing the binary data of the item."""

## ReadResourceResult

**Type**: Class

**Description**: class ReadResourceResult(Result):
    """The server's response to a resources/read request from the client."""

    contents: list[TextResourceContents | BlobResourceContents]

## ResourceListChangedNotification

**Type**: Class

**Description**: class ResourceListChangedNotification(
    Notification[NotificationParams | None, Literal["notifications/resources/list_changed"]]
):
    """
    An optional notification from the server to the client, informing it that the list
    of resources it can read from has changed.
    """

    method: Literal["notifications/resources/list_changed"]
    params: NotificationParams | None = None

## SubscribeRequestParams

**Type**: Class

**Description**: class SubscribeRequestParams(RequestParams):
    """Parameters for subscribing to a resource."""

    uri: Annotated[AnyUrl, UrlConstraints(host_required=False)]
    """
    The URI of the resource to subscribe to. The URI can use any protocol; it is up to
    the server how to interpret it.
    """
    model_config = ConfigDict(extra="allow")

## SubscribeRequest

**Type**: Class

**Description**: class SubscribeRequest(Request[SubscribeRequestParams, Literal["resources/subscribe"]]):
    """
    Sent from the client to request resources/updated notifications from the server
    whenever a particular resource changes.
    """

    method: Literal["resources/subscribe"]
    params: SubscribeRequestParams

## UnsubscribeRequestParams

**Type**: Class

**Description**: class UnsubscribeRequestParams(RequestParams):
    """Parameters for unsubscribing from a resource."""

    uri: Annotated[AnyUrl, UrlConstraints(host_required=False)]
    """The URI of the resource to unsubscribe from."""
    model_config = ConfigDict(extra="allow")

## UnsubscribeRequest

**Type**: Class

**Description**: class UnsubscribeRequest(Request[UnsubscribeRequestParams, Literal["resources/unsubscribe"]]):
    """
    Sent from the client to request cancellation of resources/updated notifications from
    the server.
    """

    method: Literal["resources/unsubscribe"]
    params: UnsubscribeRequestParams

## ResourceUpdatedNotificationParams

**Type**: Class

**Description**: class ResourceUpdatedNotificationParams(NotificationParams):
    """Parameters for resource update notifications."""

    uri: Annotated[AnyUrl, UrlConstraints(host_required=False)]
    """
    The URI of the resource that has been updated. This might be a sub-resource of the
    one that the client actually subscribed to.
    """
    model_config = ConfigDict(extra="allow")

## ResourceUpdatedNotification

**Type**: Class

**Description**: class ResourceUpdatedNotification(
    Notification[ResourceUpdatedNotificationParams, Literal["notifications/resources/updated"]]
):
    """
    A notification from the server to the client, informing it that a resource has
    changed and may need to be read again.
    """

    method: Literal["notifications/resources/updated"]
    params: ResourceUpdatedNotificationParams

## ListPromptsRequest

**Type**: Class

**Description**: class ListPromptsRequest(PaginatedRequest[Literal["prompts/list"]]):
    """Sent from the client to request a list of prompts and prompt templates."""

    method: Literal["prompts/list"]

## PromptArgument

**Type**: Class

**Description**: class PromptArgument(BaseModel):
    """An argument for a prompt template."""

    name: str
    """The name of the argument."""
    description: str | None = None
    """A human-readable description of the argument."""
    required: bool | None = None
    """Whether this argument must be provided."""
    model_config = ConfigDict(extra="allow")

## Prompt

**Type**: Class

**Description**: class Prompt(BaseMetadata):
    """A prompt or prompt template that the server offers."""

    description: str | None = None
    """An optional description of what this prompt provides."""
    arguments: list[PromptArgument] | None = None
    """A list of arguments to use for templating the prompt."""
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## ListPromptsResult

**Type**: Class

**Description**: class ListPromptsResult(PaginatedResult):
    """The server's response to a prompts/list request from the client."""

    prompts: list[Prompt]

## GetPromptRequestParams

**Type**: Class

**Description**: class GetPromptRequestParams(RequestParams):
    """Parameters for getting a prompt."""

    name: str
    """The name of the prompt or prompt template."""
    arguments: dict[str, str] | None = None
    """Arguments to use for templating the prompt."""
    model_config = ConfigDict(extra="allow")

## GetPromptRequest

**Type**: Class

**Description**: class GetPromptRequest(Request[GetPromptRequestParams, Literal["prompts/get"]]):
    """Used by the client to get a prompt provided by the server."""

    method: Literal["prompts/get"]
    params: GetPromptRequestParams

## TextContent

**Type**: Class

**Description**: class TextContent(BaseModel):
    """Text content for a message."""

    type: Literal["text"]
    text: str
    """The text content of the message."""
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## ImageContent

**Type**: Class

**Description**: class ImageContent(BaseModel):
    """Image content for a message."""

    type: Literal["image"]
    data: str
    """The base64-encoded image data."""
    mimeType: str
    """
    The MIME type of the image. Different providers may support different
    image types.
    """
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## AudioContent

**Type**: Class

**Description**: class AudioContent(BaseModel):
    """Audio content for a message."""

    type: Literal["audio"]
    data: str
    """The base64-encoded audio data."""
    mimeType: str
    """
    The MIME type of the audio. Different providers may support different
    audio types.
    """
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## SamplingMessage

**Type**: Class

**Description**: class SamplingMessage(BaseModel):
    """Describes a message issued to or received from an LLM API."""

    role: Role
    content: TextContent | ImageContent | AudioContent
    model_config = ConfigDict(extra="allow")

## EmbeddedResource

**Type**: Class

**Description**: class EmbeddedResource(BaseModel):
    """
    The contents of a resource, embedded into a prompt or tool call result.

    It is up to the client how best to render embedded resources for the benefit
    of the LLM and/or the user.
    """

    type: Literal["resource"]
    resource: TextResourceContents | BlobResourceContents
    annotations: Annotations | None = None
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## ResourceLink

**Type**: Class

**Description**: class ResourceLink(Resource):
    """
    A resource that the server is capable of reading, included in a prompt or tool call result.

    Note: resource links returned by tools are not guaranteed to appear in the results of `resources/list` requests.
    """

    type: Literal["resource_link"]

## PromptMessage

**Type**: Class

**Description**: class PromptMessage(BaseModel):
    """Describes a message returned as part of a prompt."""

    role: Role
    content: ContentBlock
    model_config = ConfigDict(extra="allow")

## GetPromptResult

**Type**: Class

**Description**: class GetPromptResult(Result):
    """The server's response to a prompts/get request from the client."""

    description: str | None = None
    """An optional description for the prompt."""
    messages: list[PromptMessage]

## PromptListChangedNotification

**Type**: Class

**Description**: class PromptListChangedNotification(
    Notification[NotificationParams | None, Literal["notifications/prompts/list_changed"]]
):
    """
    An optional notification from the server to the client, informing it that the list
    of prompts it offers has changed.
    """

    method: Literal["notifications/prompts/list_changed"]
    params: NotificationParams | None = None

## ListToolsRequest

**Type**: Class

**Description**: class ListToolsRequest(PaginatedRequest[Literal["tools/list"]]):
    """Sent from the client to request a list of tools the server has."""

    method: Literal["tools/list"]

## ToolAnnotations

**Type**: Class

**Description**: class ToolAnnotations(BaseModel):
    """
    Additional properties describing a Tool to clients.

    NOTE: all properties in ToolAnnotations are **hints**.
    They are not guaranteed to provide a faithful description of
    tool behavior (including descriptive properties like `title`).

    Clients should never make tool use decisions based on ToolAnnotations
    received from untrusted servers.
    """

    title: str | None = None
    """A human-readable title for the tool."""

    readOnlyHint: bool | None = None
    """
    If true, the tool does not modify its environment.
    Default: false
    """

    destructiveHint: bool | None = None
    """
    If true, the tool may perform destructive updates to its environment.
    If false, the tool performs only additive updates.
    (This property is meaningful only when `readOnlyHint == false`)
    Default: true
    """

    idempotentHint: bool | None = None
    """
    If true, calling the tool repeatedly with the same arguments
    will have no additional effect on the its environment.
    (This property is meaningful only when `readOnlyHint == false`)
    Default: false
    """

    openWorldHint: bool | None = None
    """
    If true, this tool may interact with an "open world" of external
    entities. If false, the tool's domain of interaction is closed.
    For example, the world of a web search tool is open, whereas that
    of a memory tool is not.
    Default: true
    """
    model_config = ConfigDict(extra="allow")

## Tool

**Type**: Class

**Description**: class Tool(BaseMetadata):
    """Definition for a tool the client can call."""

    description: str | None = None
    """A human-readable description of the tool."""
    inputSchema: dict[str, Any]
    """A JSON Schema object defining the expected parameters for the tool."""
    outputSchema: dict[str, Any] | None = None
    """
    An optional JSON Schema object defining the structure of the tool's output 
    returned in the structuredContent field of a CallToolResult.
    """
    annotations: ToolAnnotations | None = None
    """Optional additional tool information."""
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## ListToolsResult

**Type**: Class

**Description**: class ListToolsResult(PaginatedResult):
    """The server's response to a tools/list request from the client."""

    tools: list[Tool]

## CallToolRequestParams

**Type**: Class

**Description**: class CallToolRequestParams(RequestParams):
    """Parameters for calling a tool."""

    name: str
    arguments: dict[str, Any] | None = None
    model_config = ConfigDict(extra="allow")

## CallToolRequest

**Type**: Class

**Description**: class CallToolRequest(Request[CallToolRequestParams, Literal["tools/call"]]):
    """Used by the client to invoke a tool provided by the server."""

    method: Literal["tools/call"]
    params: CallToolRequestParams

## CallToolResult

**Type**: Class

**Description**: class CallToolResult(Result):
    """The server's response to a tool call."""

    content: list[ContentBlock]
    structuredContent: dict[str, Any] | None = None
    """An optional JSON object that represents the structured result of the tool call."""
    isError: bool = False

## ToolListChangedNotification

**Type**: Class

**Description**: class ToolListChangedNotification(Notification[NotificationParams | None, Literal["notifications/tools/list_changed"]]):
    """
    An optional notification from the server to the client, informing it that the list
    of tools it offers has changed.
    """

    method: Literal["notifications/tools/list_changed"]
    params: NotificationParams | None = None

## SetLevelRequestParams

**Type**: Class

**Description**: class SetLevelRequestParams(RequestParams):
    """Parameters for setting the logging level."""

    level: LoggingLevel
    """The level of logging that the client wants to receive from the server."""
    model_config = ConfigDict(extra="allow")

## SetLevelRequest

**Type**: Class

**Description**: class SetLevelRequest(Request[SetLevelRequestParams, Literal["logging/setLevel"]]):
    """A request from the client to the server, to enable or adjust logging."""

    method: Literal["logging/setLevel"]
    params: SetLevelRequestParams

## LoggingMessageNotificationParams

**Type**: Class

**Description**: class LoggingMessageNotificationParams(NotificationParams):
    """Parameters for logging message notifications."""

    level: LoggingLevel
    """The severity of this log message."""
    logger: str | None = None
    """An optional name of the logger issuing this message."""
    data: Any
    """
    The data to be logged, such as a string message or an object. Any JSON serializable
    type is allowed here.
    """
    model_config = ConfigDict(extra="allow")

## LoggingMessageNotification

**Type**: Class

**Description**: class LoggingMessageNotification(Notification[LoggingMessageNotificationParams, Literal["notifications/message"]]):
    """Notification of a log message passed from server to client."""

    method: Literal["notifications/message"]
    params: LoggingMessageNotificationParams

## ModelHint

**Type**: Class

**Description**: class ModelHint(BaseModel):
    """Hints to use for model selection."""

    name: str | None = None
    """A hint for a model name."""

    model_config = ConfigDict(extra="allow")

## ModelPreferences

**Type**: Class

**Description**: class ModelPreferences(BaseModel):
    """
    The server's preferences for model selection, requested by the client during
    sampling.

    Because LLMs can vary along multiple dimensions, choosing the "best" model is
    rarely straightforward.  Different models excel in different areas—some are
    faster but less capable, others are more capable but more expensive, and so
    on. This interface allows servers to express their priorities across multiple
    dimensions to help clients make an appropriate selection for their use case.

    These preferences are always advisory. The client MAY ignore them. It is also
    up to the client to decide how to interpret these preferences and how to
    balance them against other considerations.
    """

    hints: list[ModelHint] | None = None
    """
    Optional hints to use for model selection.

    If multiple hints are specified, the client MUST evaluate them in order
    (such that the first match is taken).

    The client SHOULD prioritize these hints over the numeric priorities, but
    MAY still use the priorities to select from ambiguous matches.
    """

    costPriority: float | None = None
    """
    How much to prioritize cost when selecting a model. A value of 0 means cost
    is not important, while a value of 1 means cost is the most important
    factor.
    """

    speedPriority: float | None = None
    """
    How much to prioritize sampling speed (latency) when selecting a model. A
    value of 0 means speed is not important, while a value of 1 means speed is
    the most important factor.
    """

    intelligencePriority: float | None = None
    """
    How much to prioritize intelligence and capabilities when selecting a
    model. A value of 0 means intelligence is not important, while a value of 1
    means intelligence is the most important factor.
    """

    model_config = ConfigDict(extra="allow")

## CreateMessageRequestParams

**Type**: Class

**Description**: class CreateMessageRequestParams(RequestParams):
    """Parameters for creating a message."""

    messages: list[SamplingMessage]
    modelPreferences: ModelPreferences | None = None
    """
    The server's preferences for which model to select. The client MAY ignore
    these preferences.
    """
    systemPrompt: str | None = None
    """An optional system prompt the server wants to use for sampling."""
    includeContext: IncludeContext | None = None
    """
    A request to include context from one or more MCP servers (including the caller), to
    be attached to the prompt.
    """
    temperature: float | None = None
    maxTokens: int
    """The maximum number of tokens to sample, as requested by the server."""
    stopSequences: list[str] | None = None
    metadata: dict[str, Any] | None = None
    """Optional metadata to pass through to the LLM provider."""
    model_config = ConfigDict(extra="allow")

## CreateMessageRequest

**Type**: Class

**Description**: class CreateMessageRequest(Request[CreateMessageRequestParams, Literal["sampling/createMessage"]]):
    """A request from the server to sample an LLM via the client."""

    method: Literal["sampling/createMessage"]
    params: CreateMessageRequestParams

## CreateMessageResult

**Type**: Class

**Description**: class CreateMessageResult(Result):
    """The client's response to a sampling/create_message request from the server."""

    role: Role
    content: TextContent | ImageContent | AudioContent
    model: str
    """The name of the model that generated the message."""
    stopReason: StopReason | None = None
    """The reason why sampling stopped, if known."""

## ResourceTemplateReference

**Type**: Class

**Description**: class ResourceTemplateReference(BaseModel):
    """A reference to a resource or resource template definition."""

    type: Literal["ref/resource"]
    uri: str
    """The URI or URI template of the resource."""
    model_config = ConfigDict(extra="allow")

## PromptReference

**Type**: Class

**Description**: class PromptReference(BaseModel):
    """Identifies a prompt."""

    type: Literal["ref/prompt"]
    name: str
    """The name of the prompt or prompt template"""
    model_config = ConfigDict(extra="allow")

## CompletionArgument

**Type**: Class

**Description**: class CompletionArgument(BaseModel):
    """The argument's information for completion requests."""

    name: str
    """The name of the argument"""
    value: str
    """The value of the argument to use for completion matching."""
    model_config = ConfigDict(extra="allow")

## CompletionContext

**Type**: Class

**Description**: class CompletionContext(BaseModel):
    """Additional, optional context for completions."""

    arguments: dict[str, str] | None = None
    """Previously-resolved variables in a URI template or prompt."""
    model_config = ConfigDict(extra="allow")

## CompleteRequestParams

**Type**: Class

**Description**: class CompleteRequestParams(RequestParams):
    """Parameters for completion requests."""

    ref: ResourceTemplateReference | PromptReference
    argument: CompletionArgument
    context: CompletionContext | None = None
    """Additional, optional context for completions"""
    model_config = ConfigDict(extra="allow")

## CompleteRequest

**Type**: Class

**Description**: class CompleteRequest(Request[CompleteRequestParams, Literal["completion/complete"]]):
    """A request from the client to the server, to ask for completion options."""

    method: Literal["completion/complete"]
    params: CompleteRequestParams

## Completion

**Type**: Class

**Description**: class Completion(BaseModel):
    """Completion information."""

    values: list[str]
    """An array of completion values. Must not exceed 100 items."""
    total: int | None = None
    """
    The total number of completion options available. This can exceed the number of
    values actually sent in the response.
    """
    hasMore: bool | None = None
    """
    Indicates whether there are additional completion options beyond those provided in
    the current response, even if the exact total is unknown.
    """
    model_config = ConfigDict(extra="allow")

## CompleteResult

**Type**: Class

**Description**: class CompleteResult(Result):
    """The server's response to a completion/complete request"""

    completion: Completion

## ListRootsRequest

**Type**: Class

**Description**: class ListRootsRequest(Request[RequestParams | None, Literal["roots/list"]]):
    """
    Sent from the server to request a list of root URIs from the client. Roots allow
    servers to ask for specific directories or files to operate on. A common example
    for roots is providing a set of repositories or directories a server should operate
    on.

    This request is typically used when the server needs to understand the file system
    structure or access specific locations that the client has permission to read from.
    """

    method: Literal["roots/list"]
    params: RequestParams | None = None

## Root

**Type**: Class

**Description**: class Root(BaseModel):
    """Represents a root directory or file that the server can operate on."""

    uri: FileUrl
    """
    The URI identifying the root. This *must* start with file:// for now.
    This restriction may be relaxed in future versions of the protocol to allow
    other URI schemes.
    """
    name: str | None = None
    """
    An optional name for the root. This can be used to provide a human-readable
    identifier for the root, which may be useful for display purposes or for
    referencing the root in other parts of the application.
    """
    meta: dict[str, Any] | None = Field(alias="_meta", default=None)
    """
    See [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/47339c03c143bb4ec01a26e721a1b8fe66634ebe/docs/specification/draft/basic/index.mdx#general-fields)
    for notes on _meta usage.
    """
    model_config = ConfigDict(extra="allow")

## ListRootsResult

**Type**: Class

**Description**: class ListRootsResult(Result):
    """
    The client's response to a roots/list request from the server.
    This result contains an array of Root objects, each representing a root directory
    or file that the server can operate on.
    """

    roots: list[Root]

## RootsListChangedNotification

**Type**: Class

**Description**: class RootsListChangedNotification(
    Notification[NotificationParams | None, Literal["notifications/roots/list_changed"]]
):
    """
    A notification from the client to the server, informing it that the list of
    roots has changed.

    This notification should be sent whenever the client adds, removes, or
    modifies any root. The server should then request an updated list of roots
    using the ListRootsRequest.
    """

    method: Literal["notifications/roots/list_changed"]
    params: NotificationParams | None = None

## CancelledNotificationParams

**Type**: Class

**Description**: class CancelledNotificationParams(NotificationParams):
    """Parameters for cancellation notifications."""

    requestId: RequestId
    """The ID of the request to cancel."""
    reason: str | None = None
    """An optional string describing the reason for the cancellation."""
    model_config = ConfigDict(extra="allow")

## CancelledNotification

**Type**: Class

**Description**: class CancelledNotification(Notification[CancelledNotificationParams, Literal["notifications/cancelled"]]):
    """
    This notification can be sent by either side to indicate that it is canceling a
    previously-issued request.
    """

    method: Literal["notifications/cancelled"]
    params: CancelledNotificationParams

## ClientRequest

**Type**: Class

**Description**: class ClientRequest(
    RootModel[
        PingRequest
        | InitializeRequest
        | CompleteRequest
        | SetLevelRequest
        | GetPromptRequest
        | ListPromptsRequest
        | ListResourcesRequest
        | ListResourceTemplatesRequest
        | ReadResourceRequest
        | SubscribeRequest
        | UnsubscribeRequest
        | CallToolRequest
        | ListToolsRequest
    ]
):
    pass

## ClientNotification

**Type**: Class

**Description**: class ClientNotification(
    RootModel[CancelledNotification | ProgressNotification | InitializedNotification | RootsListChangedNotification]
):
    pass

## ElicitRequestParams

**Type**: Class

**Description**: class ElicitRequestParams(RequestParams):
    """Parameters for elicitation requests."""

    message: str
    requestedSchema: ElicitRequestedSchema
    model_config = ConfigDict(extra="allow")

## ElicitRequest

**Type**: Class

**Description**: class ElicitRequest(Request[ElicitRequestParams, Literal["elicitation/create"]]):
    """A request from the server to elicit information from the client."""

    method: Literal["elicitation/create"]
    params: ElicitRequestParams

## ElicitResult

**Type**: Class

**Description**: class ElicitResult(Result):
    """The client's response to an elicitation request."""

    action: Literal["accept", "decline", "cancel"]
    """
    The user action in response to the elicitation.
    - "accept": User submitted the form/confirmed the action
    - "decline": User explicitly declined the action
    - "cancel": User dismissed without making an explicit choice
    """

    content: dict[str, str | int | float | bool | None] | None = None
    """
    The submitted form data, only present when action is "accept".
    Contains values matching the requested schema.
    """

## ClientResult

**Type**: Class

**Description**: class ClientResult(RootModel[EmptyResult | CreateMessageResult | ListRootsResult | ElicitResult]):
    pass

## ServerRequest

**Type**: Class

**Description**: class ServerRequest(RootModel[PingRequest | CreateMessageRequest | ListRootsRequest | ElicitRequest]):
    pass

## ServerNotification

**Type**: Class

**Description**: class ServerNotification(
    RootModel[
        CancelledNotification
        | ProgressNotification
        | LoggingMessageNotification
        | ResourceUpdatedNotification
        | ResourceListChangedNotification
        | ToolListChangedNotification
        | PromptListChangedNotification
    ]
):
    pass

## ServerResult

**Type**: Class

**Description**: class ServerResult(
    RootModel[
        EmptyResult
        | InitializeResult
        | CompleteResult
        | GetPromptResult
        | ListPromptsResult
        | ListResourcesResult
        | ListResourceTemplatesResult
        | ReadResourceResult
        | CallToolResult
        | ListToolsResult
    ]
):
    pass

## get_claude_config_path

**Type**: Function

**Description**: def get_claude_config_path() -> Path | None:
    """Get the Claude config directory based on platform."""
    if sys.platform == "win32":
        path = Path(Path.home(), "AppData", "Roaming", "Claude")
    elif sys.platform == "darwin":
        path = Path(Path.home(), "Library", "Application Support", "Claude")
    elif sys.platform.startswith("linux"):
        path = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"), "Claude")
    else:
        return None

    if path.exists():
        return path
    return None

## get_uv_path

**Type**: Function

**Description**: def get_uv_path() -> str:
    """Get the full path to the uv executable."""
    uv_path = shutil.which("uv")
    if not uv_path:
        logger.error(
            "uv executable not found in PATH, falling back to 'uv'. " "Please ensure uv is installed and in your PATH"
        )
        return "uv"  # Fall back to just "uv" if not found
    return uv_path

## update_claude_config

**Type**: Function

**Description**: def update_claude_config(
    file_spec: str,
    server_name: str,
    *,
    with_editable: Path | None = None,
    with_packages: list[str] | None = None,
    env_vars: dict[str, str] | None = None,
) -> bool:
    """Add or update a FastMCP server in Claude's configuration.

    Args:
        file_spec: Path to the server file, optionally with :object suffix
        server_name: Name for the server in Claude's config
        with_editable: Optional directory to install in editable mode
        with_packages: Optional list of additional packages to install
        env_vars: Optional dictionary of environment variables. These are merged with
            any existing variables, with new values taking precedence.

    Raises:
        RuntimeError: If Claude Desktop's config directory is not found, indicating
            Claude Desktop may not be installed or properly set up.
    """
    config_dir = get_claude_config_path()
    uv_path = get_uv_path()
    if not config_dir:
        raise RuntimeError(
            "Claude Desktop config directory not found. Please ensure Claude Desktop"
            " is installed and has been run at least once to initialize its config."
        )

    config_file = config_dir / "claude_desktop_config.json"
    if not config_file.exists():
        try:
            config_file.write_text("{}")
        except Exception as e:
            logger.error(
                "Failed to create Claude config file",
                extra={
                    "error": str(e),
                    "config_file": str(config_file),
                },
            )
            return False

    try:
        config = json.loads(config_file.read_text())
        if "mcpServers" not in config:
            config["mcpServers"] = {}

        # Always preserve existing env vars and merge with new ones
        if server_name in config["mcpServers"] and "env" in config["mcpServers"][server_name]:
            existing_env = config["mcpServers"][server_name]["env"]
            if env_vars:
                # New vars take precedence over existing ones
                env_vars = {**existing_env, **env_vars}
            else:
                env_vars = existing_env

        # Build uv run command
        args = ["run"]

        # Collect all packages in a set to deduplicate
        packages = {MCP_PACKAGE}
        if with_packages:
            packages.update(pkg for pkg in with_packages if pkg)

        # Add all packages with --with
        for pkg in sorted(packages):
            args.extend(["--with", pkg])

        if with_editable:
            args.extend(["--with-editable", str(with_editable)])

        # Convert file path to absolute before adding to command
        # Split off any :object suffix first
        if ":" in file_spec:
            file_path, server_object = file_spec.rsplit(":", 1)
            file_spec = f"{Path(file_path).resolve()}:{server_object}"
        else:
            file_spec = str(Path(file_spec).resolve())

        # Add fastmcp run command
        args.extend(["mcp", "run", file_spec])

        server_config: dict[str, Any] = {"command": uv_path, "args": args}

        # Add environment variables if specified
        if env_vars:
            server_config["env"] = env_vars

        config["mcpServers"][server_name] = server_config

        config_file.write_text(json.dumps(config, indent=2))
        logger.info(
            f"Added server '{server_name}' to Claude config",
            extra={"config_file": str(config_file)},
        )
        return True
    except Exception as e:
        logger.error(
            "Failed to update Claude config",
            extra={
                "error": str(e),
                "config_file": str(config_file),
            },
        )
        return False

## _get_npx_command

**Type**: Function

**Description**: def _get_npx_command():
    """Get the correct npx command for the current platform."""
    if sys.platform == "win32":
        # Try both npx.cmd and npx.exe on Windows
        for cmd in ["npx.cmd", "npx.exe", "npx"]:
            try:
                subprocess.run([cmd, "--version"], check=True, capture_output=True, shell=True)
                return cmd
            except subprocess.CalledProcessError:
                continue
        return None
    return "npx"  # On Unix-like systems, just use npx

## _parse_env_var

**Type**: Function

**Description**: def _parse_env_var(env_var: str) -> tuple[str, str]:
    """Parse environment variable string in format KEY=VALUE."""
    if "=" not in env_var:
        logger.error(f"Invalid environment variable format: {env_var}. Must be KEY=VALUE")
        sys.exit(1)
    key, value = env_var.split("=", 1)
    return key.strip(), value.strip()

## _build_uv_command

**Type**: Function

**Description**: def _build_uv_command(
    file_spec: str,
    with_editable: Path | None = None,
    with_packages: list[str] | None = None,
) -> list[str]:
    """Build the uv run command that runs a MCP server through mcp run."""
    cmd = ["uv"]

    cmd.extend(["run", "--with", "mcp"])

    if with_editable:
        cmd.extend(["--with-editable", str(with_editable)])

    if with_packages:
        for pkg in with_packages:
            if pkg:
                cmd.extend(["--with", pkg])

    # Add mcp run command
    cmd.extend(["mcp", "run", file_spec])
    return cmd

## _parse_file_path

**Type**: Function

**Description**: def _parse_file_path(file_spec: str) -> tuple[Path, str | None]:
    """Parse a file path that may include a server object specification.

    Args:
        file_spec: Path to file, optionally with :object suffix

    Returns:
        Tuple of (file_path, server_object)
    """
    # First check if we have a Windows path (e.g., C:\...)
    has_windows_drive = len(file_spec) > 1 and file_spec[1] == ":"

    # Split on the last colon, but only if it's not part of the Windows drive letter
    # and there's actually another colon in the string after the drive letter
    if ":" in (file_spec[2:] if has_windows_drive else file_spec):
        file_str, server_object = file_spec.rsplit(":", 1)
    else:
        file_str, server_object = file_spec, None

    # Resolve the file path
    file_path = Path(file_str).expanduser().resolve()
    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        sys.exit(1)
    if not file_path.is_file():
        logger.error(f"Not a file: {file_path}")
        sys.exit(1)

    return file_path, server_object

## _import_server

**Type**: Function

**Description**: def _import_server(file: Path, server_object: str | None = None):
    """Import a MCP server from a file.

    Args:
        file: Path to the file
        server_object: Optional object name in format "module:object" or just "object"

    Returns:
        The server object
    """
    # Add parent directory to Python path so imports can be resolved
    file_dir = str(file.parent)
    if file_dir not in sys.path:
        sys.path.insert(0, file_dir)

    # Import the module
    spec = importlib.util.spec_from_file_location("server_module", file)
    if not spec or not spec.loader:
        logger.error("Could not load module", extra={"file": str(file)})
        sys.exit(1)

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def _check_server_object(server_object: Any, object_name: str):
        """Helper function to check that the server object is supported

        Args:
            server_object: The server object to check.

        Returns:
            True if it's supported.
        """
        if not isinstance(server_object, FastMCP):
            logger.error(f"The server object {object_name} is of type " f"{type(server_object)} (expecting {FastMCP}).")
            if isinstance(server_object, LowLevelServer):
                logger.warning(
                    "Note that only FastMCP server is supported. Low level " "Server class is not yet supported."
                )
            return False
        return True

    # If no object specified, try common server names
    if not server_object:
        # Look for the most common server object names
        for name in ["mcp", "server", "app"]:
            if hasattr(module, name):
                if not _check_server_object(getattr(module, name), f"{file}:{name}"):
                    logger.error(f"Ignoring object '{file}:{name}' as it's not a valid " "server object")
                    continue
                return getattr(module, name)

        logger.error(
            f"No server object found in {file}. Please either:\n"
            "1. Use a standard variable name (mcp, server, or app)\n"
            "2. Specify the object name with file:object syntax"
            "3. If the server creates the FastMCP object within main() "
            "   or another function, refactor the FastMCP object to be a "
            "   global variable named mcp, server, or app.",
            extra={"file": str(file)},
        )
        sys.exit(1)

    # Handle module:object syntax
    if ":" in server_object:
        module_name, object_name = server_object.split(":", 1)
        try:
            server_module = importlib.import_module(module_name)
            server = getattr(server_module, object_name, None)
        except ImportError:
            logger.error(
                f"Could not import module '{module_name}'",
                extra={"file": str(file)},
            )
            sys.exit(1)
    else:
        # Just object name
        server = getattr(module, server_object, None)

    if server is None:
        logger.error(
            f"Server object '{server_object}' not found",
            extra={"file": str(file)},
        )
        sys.exit(1)

    if not _check_server_object(server, server_object):
        sys.exit(1)

    return server

## OAuthFlowError

**Type**: Class

**Description**: class OAuthFlowError(Exception):
    """Base exception for OAuth flow errors."""

## OAuthTokenError

**Type**: Class

**Description**: class OAuthTokenError(OAuthFlowError):
    """Raised when token operations fail."""

## OAuthRegistrationError

**Type**: Class

**Description**: class OAuthRegistrationError(OAuthFlowError):
    """Raised when client registration fails."""

## PKCEParameters

**Type**: Class

**Description**: class PKCEParameters(BaseModel):
    """PKCE (Proof Key for Code Exchange) parameters."""

    code_verifier: str = Field(..., min_length=43, max_length=128)
    code_challenge: str = Field(..., min_length=43, max_length=128)

    @classmethod
    def generate(cls) -> "PKCEParameters":
        """Generate new PKCE parameters."""
        code_verifier = "".join(secrets.choice(string.ascii_letters + string.digits + "-._~") for _ in range(128))
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return cls(code_verifier=code_verifier, code_challenge=code_challenge)

## TokenStorage

**Type**: Class

**Description**: class TokenStorage(Protocol):
    """Protocol for token storage implementations."""

    async def get_tokens(self) -> OAuthToken | None:
        """Get stored tokens."""
        ...

    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Store tokens."""
        ...

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        """Get stored client information."""
        ...

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store client information."""
        ...

## OAuthClientProvider

**Type**: Class

**Description**: class OAuthClientProvider(httpx.Auth):
    """
    OAuth2 authentication for httpx.
    Handles OAuth flow with automatic client registration and token storage.
    """

    requires_response_body = True

    def __init__(
        self,
        server_url: str,
        client_metadata: OAuthClientMetadata,
        storage: TokenStorage,
        redirect_handler: Callable[[str], Awaitable[None]],
        callback_handler: Callable[[], Awaitable[tuple[str, str | None]]],
        timeout: float = 300.0,
    ):
        """Initialize OAuth2 authentication."""
        self.context = OAuthContext(
            server_url=server_url,
            client_metadata=client_metadata,
            storage=storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
            timeout=timeout,
        )
        self._initialized = False

    async def _discover_protected_resource(self) -> httpx.Request:
        """Build discovery request for protected resource metadata."""
        auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
        url = urljoin(auth_base_url, "/.well-known/oauth-protected-resource")
        return httpx.Request("GET", url, headers={MCP_PROTOCOL_VERSION: LATEST_PROTOCOL_VERSION})

    async def _handle_protected_resource_response(self, response: httpx.Response) -> None:
        """Handle discovery response."""
        if response.status_code == 200:
            try:
                content = await response.aread()
                metadata = ProtectedResourceMetadata.model_validate_json(content)
                self.context.protected_resource_metadata = metadata
                if metadata.authorization_servers:
                    self.context.auth_server_url = str(metadata.authorization_servers[0])
            except ValidationError:
                pass

    def _build_well_known_path(self, pathname: str) -> str:
        """Construct well-known path for OAuth metadata discovery."""
        well_known_path = f"/.well-known/oauth-authorization-server{pathname}"
        if pathname.endswith("/"):
            # Strip trailing slash from pathname to avoid double slashes
            well_known_path = well_known_path[:-1]
        return well_known_path

    def _should_attempt_fallback(self, response_status: int, pathname: str) -> bool:
        """Determine if fallback to root discovery should be attempted."""
        return response_status == 404 and pathname != "/"

    async def _try_metadata_discovery(self, url: str) -> httpx.Request:
        """Build metadata discovery request for a specific URL."""
        return httpx.Request("GET", url, headers={MCP_PROTOCOL_VERSION: LATEST_PROTOCOL_VERSION})

    async def _discover_oauth_metadata(self) -> httpx.Request:
        """Build OAuth metadata discovery request with fallback support."""
        if self.context.auth_server_url:
            auth_server_url = self.context.auth_server_url
        else:
            auth_server_url = self.context.server_url

        # Per RFC 8414, try path-aware discovery first
        parsed = urlparse(auth_server_url)
        well_known_path = self._build_well_known_path(parsed.path)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        url = urljoin(base_url, well_known_path)

        # Store fallback info for use in response handler
        self.context.discovery_base_url = base_url
        self.context.discovery_pathname = parsed.path

        return await self._try_metadata_discovery(url)

    async def _discover_oauth_metadata_fallback(self) -> httpx.Request:
        """Build fallback OAuth metadata discovery request for legacy servers."""
        base_url = getattr(self.context, "discovery_base_url", "")
        if not base_url:
            raise OAuthFlowError("No base URL available for fallback discovery")

        # Fallback to root discovery for legacy servers
        url = urljoin(base_url, "/.well-known/oauth-authorization-server")
        return await self._try_metadata_discovery(url)

    async def _handle_oauth_metadata_response(self, response: httpx.Response, is_fallback: bool = False) -> bool:
        """Handle OAuth metadata response. Returns True if handled successfully."""
        if response.status_code == 200:
            try:
                content = await response.aread()
                metadata = OAuthMetadata.model_validate_json(content)
                self.context.oauth_metadata = metadata
                # Apply default scope if none specified
                if self.context.client_metadata.scope is None and metadata.scopes_supported is not None:
                    self.context.client_metadata.scope = " ".join(metadata.scopes_supported)
                return True
            except ValidationError:
                pass

        # Check if we should attempt fallback (404 on path-aware discovery)
        if not is_fallback and self._should_attempt_fallback(
            response.status_code, getattr(self.context, "discovery_pathname", "/")
        ):
            return False  # Signal that fallback should be attempted

        return True  # Signal no fallback needed (either success or non-404 error)

    async def _register_client(self) -> httpx.Request | None:
        """Build registration request or skip if already registered."""
        if self.context.client_info:
            return None

        if self.context.oauth_metadata and self.context.oauth_metadata.registration_endpoint:
            registration_url = str(self.context.oauth_metadata.registration_endpoint)
        else:
            auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
            registration_url = urljoin(auth_base_url, "/register")

        registration_data = self.context.client_metadata.model_dump(by_alias=True, mode="json", exclude_none=True)

        return httpx.Request(
            "POST", registration_url, json=registration_data, headers={"Content-Type": "application/json"}
        )

    async def _handle_registration_response(self, response: httpx.Response) -> None:
        """Handle registration response."""
        if response.status_code not in (200, 201):
            raise OAuthRegistrationError(f"Registration failed: {response.status_code} {response.text}")

        try:
            content = await response.aread()
            client_info = OAuthClientInformationFull.model_validate_json(content)
            self.context.client_info = client_info
            await self.context.storage.set_client_info(client_info)
        except ValidationError as e:
            raise OAuthRegistrationError(f"Invalid registration response: {e}")

    async def _perform_authorization(self) -> tuple[str, str]:
        """Perform the authorization redirect and get auth code."""
        if self.context.oauth_metadata and self.context.oauth_metadata.authorization_endpoint:
            auth_endpoint = str(self.context.oauth_metadata.authorization_endpoint)
        else:
            auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
            auth_endpoint = urljoin(auth_base_url, "/authorize")

        if not self.context.client_info:
            raise OAuthFlowError("No client info available for authorization")

        # Generate PKCE parameters
        pkce_params = PKCEParameters.generate()
        state = secrets.token_urlsafe(32)

        auth_params = {
            "response_type": "code",
            "client_id": self.context.client_info.client_id,
            "redirect_uri": str(self.context.client_metadata.redirect_uris[0]),
            "state": state,
            "code_challenge": pkce_params.code_challenge,
            "code_challenge_method": "S256",
        }

        # Only include resource param if conditions are met
        if self.context.should_include_resource_param(self.context.protocol_version):
            auth_params["resource"] = self.context.get_resource_url()  # RFC 8707

        if self.context.client_metadata.scope:
            auth_params["scope"] = self.context.client_metadata.scope

        authorization_url = f"{auth_endpoint}?{urlencode(auth_params)}"
        await self.context.redirect_handler(authorization_url)

        # Wait for callback
        auth_code, returned_state = await self.context.callback_handler()

        if returned_state is None or not secrets.compare_digest(returned_state, state):
            raise OAuthFlowError(f"State parameter mismatch: {returned_state} != {state}")

        if not auth_code:
            raise OAuthFlowError("No authorization code received")

        # Return auth code and code verifier for token exchange
        return auth_code, pkce_params.code_verifier

    async def _exchange_token(self, auth_code: str, code_verifier: str) -> httpx.Request:
        """Build token exchange request."""
        if not self.context.client_info:
            raise OAuthFlowError("Missing client info")

        if self.context.oauth_metadata and self.context.oauth_metadata.token_endpoint:
            token_url = str(self.context.oauth_metadata.token_endpoint)
        else:
            auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
            token_url = urljoin(auth_base_url, "/token")

        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": str(self.context.client_metadata.redirect_uris[0]),
            "client_id": self.context.client_info.client_id,
            "code_verifier": code_verifier,
        }

        # Only include resource param if conditions are met
        if self.context.should_include_resource_param(self.context.protocol_version):
            token_data["resource"] = self.context.get_resource_url()  # RFC 8707

        if self.context.client_info.client_secret:
            token_data["client_secret"] = self.context.client_info.client_secret

        return httpx.Request(
            "POST", token_url, data=token_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    async def _handle_token_response(self, response: httpx.Response) -> None:
        """Handle token exchange response."""
        if response.status_code != 200:
            raise OAuthTokenError(f"Token exchange failed: {response.status_code}")

        try:
            content = await response.aread()
            token_response = OAuthToken.model_validate_json(content)

            # Validate scopes
            if token_response.scope and self.context.client_metadata.scope:
                requested_scopes = set(self.context.client_metadata.scope.split())
                returned_scopes = set(token_response.scope.split())
                unauthorized_scopes = returned_scopes - requested_scopes
                if unauthorized_scopes:
                    raise OAuthTokenError(f"Server granted unauthorized scopes: {unauthorized_scopes}")

            self.context.current_tokens = token_response
            self.context.update_token_expiry(token_response)
            await self.context.storage.set_tokens(token_response)
        except ValidationError as e:
            raise OAuthTokenError(f"Invalid token response: {e}")

    async def _refresh_token(self) -> httpx.Request:
        """Build token refresh request."""
        if not self.context.current_tokens or not self.context.current_tokens.refresh_token:
            raise OAuthTokenError("No refresh token available")

        if not self.context.client_info:
            raise OAuthTokenError("No client info available")

        if self.context.oauth_metadata and self.context.oauth_metadata.token_endpoint:
            token_url = str(self.context.oauth_metadata.token_endpoint)
        else:
            auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
            token_url = urljoin(auth_base_url, "/token")

        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": self.context.current_tokens.refresh_token,
            "client_id": self.context.client_info.client_id,
        }

        # Only include resource param if conditions are met
        if self.context.should_include_resource_param(self.context.protocol_version):
            refresh_data["resource"] = self.context.get_resource_url()  # RFC 8707

        if self.context.client_info.client_secret:
            refresh_data["client_secret"] = self.context.client_info.client_secret

        return httpx.Request(
            "POST", token_url, data=refresh_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    async def _handle_refresh_response(self, response: httpx.Response) -> bool:
        """Handle token refresh response. Returns True if successful."""
        if response.status_code != 200:
            logger.warning(f"Token refresh failed: {response.status_code}")
            self.context.clear_tokens()
            return False

        try:
            content = await response.aread()
            token_response = OAuthToken.model_validate_json(content)

            self.context.current_tokens = token_response
            self.context.update_token_expiry(token_response)
            await self.context.storage.set_tokens(token_response)

            return True
        except ValidationError as e:
            logger.error(f"Invalid refresh response: {e}")
            self.context.clear_tokens()
            return False

    async def _initialize(self) -> None:
        """Load stored tokens and client info."""
        self.context.current_tokens = await self.context.storage.get_tokens()
        self.context.client_info = await self.context.storage.get_client_info()
        self._initialized = True

    def _add_auth_header(self, request: httpx.Request) -> None:
        """Add authorization header to request if we have valid tokens."""
        if self.context.current_tokens and self.context.current_tokens.access_token:
            request.headers["Authorization"] = f"Bearer {self.context.current_tokens.access_token}"

    async def async_auth_flow(self, request: httpx.Request) -> AsyncGenerator[httpx.Request, httpx.Response]:
        """HTTPX auth flow integration."""
        async with self.context.lock:
            if not self._initialized:
                await self._initialize()

            # Capture protocol version from request headers
            self.context.protocol_version = request.headers.get(MCP_PROTOCOL_VERSION)

            # Perform OAuth flow if not authenticated
            if not self.context.is_token_valid():
                try:
                    # OAuth flow must be inline due to generator constraints
                    # Step 1: Discover protected resource metadata (spec revision 2025-06-18)
                    discovery_request = await self._discover_protected_resource()
                    discovery_response = yield discovery_request
                    await self._handle_protected_resource_response(discovery_response)

                    # Step 2: Discover OAuth metadata (with fallback for legacy servers)
                    oauth_request = await self._discover_oauth_metadata()
                    oauth_response = yield oauth_request
                    handled = await self._handle_oauth_metadata_response(oauth_response, is_fallback=False)

                    # If path-aware discovery failed with 404, try fallback to root
                    if not handled:
                        fallback_request = await self._discover_oauth_metadata_fallback()
                        fallback_response = yield fallback_request
                        await self._handle_oauth_metadata_response(fallback_response, is_fallback=True)

                    # Step 3: Register client if needed
                    registration_request = await self._register_client()
                    if registration_request:
                        registration_response = yield registration_request
                        await self._handle_registration_response(registration_response)

                    # Step 4: Perform authorization
                    auth_code, code_verifier = await self._perform_authorization()

                    # Step 5: Exchange authorization code for tokens
                    token_request = await self._exchange_token(auth_code, code_verifier)
                    token_response = yield token_request
                    await self._handle_token_response(token_response)
                except Exception as e:
                    logger.error(f"OAuth flow error: {e}")
                    raise

            # Add authorization header and make request
            self._add_auth_header(request)
            response = yield request

            # Handle 401 responses
            if response.status_code == 401 and self.context.can_refresh_token():
                # Try to refresh token
                refresh_request = await self._refresh_token()
                refresh_response = yield refresh_request

                if await self._handle_refresh_response(refresh_response):
                    # Retry original request with new token
                    self._add_auth_header(request)
                    yield request
                else:
                    # Refresh failed, need full re-authentication
                    self._initialized = False

                    # OAuth flow must be inline due to generator constraints
                    # Step 1: Discover protected resource metadata (spec revision 2025-06-18)
                    discovery_request = await self._discover_protected_resource()
                    discovery_response = yield discovery_request
                    await self._handle_protected_resource_response(discovery_response)

                    # Step 2: Discover OAuth metadata (with fallback for legacy servers)
                    oauth_request = await self._discover_oauth_metadata()
                    oauth_response = yield oauth_request
                    handled = await self._handle_oauth_metadata_response(oauth_response, is_fallback=False)

                    # If path-aware discovery failed with 404, try fallback to root
                    if not handled:
                        fallback_request = await self._discover_oauth_metadata_fallback()
                        fallback_response = yield fallback_request
                        await self._handle_oauth_metadata_response(fallback_response, is_fallback=True)

                    # Step 3: Register client if needed
                    registration_request = await self._register_client()
                    if registration_request:
                        registration_response = yield registration_request
                        await self._handle_registration_response(registration_response)

                    # Step 4: Perform authorization
                    auth_code, code_verifier = await self._perform_authorization()

                    # Step 5: Exchange authorization code for tokens
                    token_request = await self._exchange_token(auth_code, code_verifier)
                    token_response = yield token_request
                    await self._handle_token_response(token_response)

                    # Retry with new tokens
                    self._add_auth_header(request)
                    yield request

## SamplingFnT

**Type**: Class

**Description**: class SamplingFnT(Protocol):
    async def __call__(
        self,
        context: RequestContext["ClientSession", Any],
        params: types.CreateMessageRequestParams,
    ) -> types.CreateMessageResult | types.ErrorData: ...

## ElicitationFnT

**Type**: Class

**Description**: class ElicitationFnT(Protocol):
    async def __call__(
        self,
        context: RequestContext["ClientSession", Any],
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult | types.ErrorData: ...

## ListRootsFnT

**Type**: Class

**Description**: class ListRootsFnT(Protocol):
    async def __call__(
        self, context: RequestContext["ClientSession", Any]
    ) -> types.ListRootsResult | types.ErrorData: ...

## LoggingFnT

**Type**: Class

**Description**: class LoggingFnT(Protocol):
    async def __call__(
        self,
        params: types.LoggingMessageNotificationParams,
    ) -> None: ...

## MessageHandlerFnT

**Type**: Class

**Description**: class MessageHandlerFnT(Protocol):
    async def __call__(
        self,
        message: RequestResponder[types.ServerRequest, types.ClientResult] | types.ServerNotification | Exception,
    ) -> None: ...

## _default_message_handler

**Type**: Function

**Description**: async def _default_message_handler(
    message: RequestResponder[types.ServerRequest, types.ClientResult] | types.ServerNotification | Exception,
) -> None:
    await anyio.lowlevel.checkpoint()

## _default_sampling_callback

**Type**: Function

**Description**: async def _default_sampling_callback(
    context: RequestContext["ClientSession", Any],
    params: types.CreateMessageRequestParams,
) -> types.CreateMessageResult | types.ErrorData:
    return types.ErrorData(
        code=types.INVALID_REQUEST,
        message="Sampling not supported",
    )

## _default_elicitation_callback

**Type**: Function

**Description**: async def _default_elicitation_callback(
    context: RequestContext["ClientSession", Any],
    params: types.ElicitRequestParams,
) -> types.ElicitResult | types.ErrorData:
    return types.ErrorData(
        code=types.INVALID_REQUEST,
        message="Elicitation not supported",
    )

## _default_list_roots_callback

**Type**: Function

**Description**: async def _default_list_roots_callback(
    context: RequestContext["ClientSession", Any],
) -> types.ListRootsResult | types.ErrorData:
    return types.ErrorData(
        code=types.INVALID_REQUEST,
        message="List roots not supported",
    )

## _default_logging_callback

**Type**: Function

**Description**: async def _default_logging_callback(
    params: types.LoggingMessageNotificationParams,
) -> None:
    pass

## ClientSession

**Type**: Class

**Description**: class ClientSession(
    BaseSession[
        types.ClientRequest,
        types.ClientNotification,
        types.ClientResult,
        types.ServerRequest,
        types.ServerNotification,
    ]
):
    def __init__(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        read_timeout_seconds: timedelta | None = None,
        sampling_callback: SamplingFnT | None = None,
        elicitation_callback: ElicitationFnT | None = None,
        list_roots_callback: ListRootsFnT | None = None,
        logging_callback: LoggingFnT | None = None,
        message_handler: MessageHandlerFnT | None = None,
        client_info: types.Implementation | None = None,
    ) -> None:
        super().__init__(
            read_stream,
            write_stream,
            types.ServerRequest,
            types.ServerNotification,
            read_timeout_seconds=read_timeout_seconds,
        )
        self._client_info = client_info or DEFAULT_CLIENT_INFO
        self._sampling_callback = sampling_callback or _default_sampling_callback
        self._elicitation_callback = elicitation_callback or _default_elicitation_callback
        self._list_roots_callback = list_roots_callback or _default_list_roots_callback
        self._logging_callback = logging_callback or _default_logging_callback
        self._message_handler = message_handler or _default_message_handler
        self._tool_output_schemas: dict[str, dict[str, Any] | None] = {}

    async def initialize(self) -> types.InitializeResult:
        sampling = types.SamplingCapability() if self._sampling_callback is not _default_sampling_callback else None
        elicitation = (
            types.ElicitationCapability() if self._elicitation_callback is not _default_elicitation_callback else None
        )
        roots = (
            # TODO: Should this be based on whether we
            # _will_ send notifications, or only whether
            # they're supported?
            types.RootsCapability(listChanged=True)
            if self._list_roots_callback is not _default_list_roots_callback
            else None
        )

        result = await self.send_request(
            types.ClientRequest(
                types.InitializeRequest(
                    method="initialize",
                    params=types.InitializeRequestParams(
                        protocolVersion=types.LATEST_PROTOCOL_VERSION,
                        capabilities=types.ClientCapabilities(
                            sampling=sampling,
                            elicitation=elicitation,
                            experimental=None,
                            roots=roots,
                        ),
                        clientInfo=self._client_info,
                    ),
                )
            ),
            types.InitializeResult,
        )

        if result.protocolVersion not in SUPPORTED_PROTOCOL_VERSIONS:
            raise RuntimeError("Unsupported protocol version from the server: " f"{result.protocolVersion}")

        await self.send_notification(
            types.ClientNotification(types.InitializedNotification(method="notifications/initialized"))
        )

        return result

    async def send_ping(self) -> types.EmptyResult:
        """Send a ping request."""
        return await self.send_request(
            types.ClientRequest(
                types.PingRequest(
                    method="ping",
                )
            ),
            types.EmptyResult,
        )

    async def send_progress_notification(
        self,
        progress_token: str | int,
        progress: float,
        total: float | None = None,
        message: str | None = None,
    ) -> None:
        """Send a progress notification."""
        await self.send_notification(
            types.ClientNotification(
                types.ProgressNotification(
                    method="notifications/progress",
                    params=types.ProgressNotificationParams(
                        progressToken=progress_token,
                        progress=progress,
                        total=total,
                        message=message,
                    ),
                ),
            )
        )

    async def set_logging_level(self, level: types.LoggingLevel) -> types.EmptyResult:
        """Send a logging/setLevel request."""
        return await self.send_request(
            types.ClientRequest(
                types.SetLevelRequest(
                    method="logging/setLevel",
                    params=types.SetLevelRequestParams(level=level),
                )
            ),
            types.EmptyResult,
        )

    async def list_resources(self, cursor: str | None = None) -> types.ListResourcesResult:
        """Send a resources/list request."""
        return await self.send_request(
            types.ClientRequest(
                types.ListResourcesRequest(
                    method="resources/list",
                    params=types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None,
                )
            ),
            types.ListResourcesResult,
        )

    async def list_resource_templates(self, cursor: str | None = None) -> types.ListResourceTemplatesResult:
        """Send a resources/templates/list request."""
        return await self.send_request(
            types.ClientRequest(
                types.ListResourceTemplatesRequest(
                    method="resources/templates/list",
                    params=types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None,
                )
            ),
            types.ListResourceTemplatesResult,
        )

    async def read_resource(self, uri: AnyUrl) -> types.ReadResourceResult:
        """Send a resources/read request."""
        return await self.send_request(
            types.ClientRequest(
                types.ReadResourceRequest(
                    method="resources/read",
                    params=types.ReadResourceRequestParams(uri=uri),
                )
            ),
            types.ReadResourceResult,
        )

    async def subscribe_resource(self, uri: AnyUrl) -> types.EmptyResult:
        """Send a resources/subscribe request."""
        return await self.send_request(
            types.ClientRequest(
                types.SubscribeRequest(
                    method="resources/subscribe",
                    params=types.SubscribeRequestParams(uri=uri),
                )
            ),
            types.EmptyResult,
        )

    async def unsubscribe_resource(self, uri: AnyUrl) -> types.EmptyResult:
        """Send a resources/unsubscribe request."""
        return await self.send_request(
            types.ClientRequest(
                types.UnsubscribeRequest(
                    method="resources/unsubscribe",
                    params=types.UnsubscribeRequestParams(uri=uri),
                )
            ),
            types.EmptyResult,
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
        progress_callback: ProgressFnT | None = None,
    ) -> types.CallToolResult:
        """Send a tools/call request with optional progress callback support."""

        result = await self.send_request(
            types.ClientRequest(
                types.CallToolRequest(
                    method="tools/call",
                    params=types.CallToolRequestParams(
                        name=name,
                        arguments=arguments,
                    ),
                )
            ),
            types.CallToolResult,
            request_read_timeout_seconds=read_timeout_seconds,
            progress_callback=progress_callback,
        )

        if not result.isError:
            await self._validate_tool_result(name, result)

        return result

    async def _validate_tool_result(self, name: str, result: types.CallToolResult) -> None:
        """Validate the structured content of a tool result against its output schema."""
        if name not in self._tool_output_schemas:
            # refresh output schema cache
            await self.list_tools()

        output_schema = None
        if name in self._tool_output_schemas:
            output_schema = self._tool_output_schemas.get(name)
        else:
            logger.warning(f"Tool {name} not listed by server, cannot validate any structured content")

        if output_schema is not None:
            if result.structuredContent is None:
                raise RuntimeError(f"Tool {name} has an output schema but did not return structured content")
            try:
                validate(result.structuredContent, output_schema)
            except ValidationError as e:
                raise RuntimeError(f"Invalid structured content returned by tool {name}: {e}")
            except SchemaError as e:
                raise RuntimeError(f"Invalid schema for tool {name}: {e}")

    async def list_prompts(self, cursor: str | None = None) -> types.ListPromptsResult:
        """Send a prompts/list request."""
        return await self.send_request(
            types.ClientRequest(
                types.ListPromptsRequest(
                    method="prompts/list",
                    params=types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None,
                )
            ),
            types.ListPromptsResult,
        )

    async def get_prompt(self, name: str, arguments: dict[str, str] | None = None) -> types.GetPromptResult:
        """Send a prompts/get request."""
        return await self.send_request(
            types.ClientRequest(
                types.GetPromptRequest(
                    method="prompts/get",
                    params=types.GetPromptRequestParams(name=name, arguments=arguments),
                )
            ),
            types.GetPromptResult,
        )

    async def complete(
        self,
        ref: types.ResourceTemplateReference | types.PromptReference,
        argument: dict[str, str],
        context_arguments: dict[str, str] | None = None,
    ) -> types.CompleteResult:
        """Send a completion/complete request."""
        context = None
        if context_arguments is not None:
            context = types.CompletionContext(arguments=context_arguments)

        return await self.send_request(
            types.ClientRequest(
                types.CompleteRequest(
                    method="completion/complete",
                    params=types.CompleteRequestParams(
                        ref=ref,
                        argument=types.CompletionArgument(**argument),
                        context=context,
                    ),
                )
            ),
            types.CompleteResult,
        )

    async def list_tools(self, cursor: str | None = None) -> types.ListToolsResult:
        """Send a tools/list request."""
        result = await self.send_request(
            types.ClientRequest(
                types.ListToolsRequest(
                    method="tools/list",
                    params=types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None,
                )
            ),
            types.ListToolsResult,
        )

        # Cache tool output schemas for future validation
        # Note: don't clear the cache, as we may be using a cursor
        for tool in result.tools:
            self._tool_output_schemas[tool.name] = tool.outputSchema

        return result

    async def send_roots_list_changed(self) -> None:
        """Send a roots/list_changed notification."""
        await self.send_notification(
            types.ClientNotification(
                types.RootsListChangedNotification(
                    method="notifications/roots/list_changed",
                )
            )
        )

    async def _received_request(self, responder: RequestResponder[types.ServerRequest, types.ClientResult]) -> None:
        ctx = RequestContext[ClientSession, Any](
            request_id=responder.request_id,
            meta=responder.request_meta,
            session=self,
            lifespan_context=None,
        )

        match responder.request.root:
            case types.CreateMessageRequest(params=params):
                with responder:
                    response = await self._sampling_callback(ctx, params)
                    client_response = ClientResponse.validate_python(response)
                    await responder.respond(client_response)

            case types.ElicitRequest(params=params):
                with responder:
                    response = await self._elicitation_callback(ctx, params)
                    client_response = ClientResponse.validate_python(response)
                    await responder.respond(client_response)

            case types.ListRootsRequest():
                with responder:
                    response = await self._list_roots_callback(ctx)
                    client_response = ClientResponse.validate_python(response)
                    await responder.respond(client_response)

            case types.PingRequest():
                with responder:
                    return await responder.respond(types.ClientResult(root=types.EmptyResult()))

    async def _handle_incoming(
        self,
        req: RequestResponder[types.ServerRequest, types.ClientResult] | types.ServerNotification | Exception,
    ) -> None:
        """Handle incoming messages by forwarding to the message handler."""
        await self._message_handler(req)

    async def _received_notification(self, notification: types.ServerNotification) -> None:
        """Handle notifications from the server."""
        # Process specific notification types
        match notification.root:
            case types.LoggingMessageNotification(params=params):
                await self._logging_callback(params)
            case _:
                pass

## SseServerParameters

**Type**: Class

**Description**: class SseServerParameters(BaseModel):
    """Parameters for intializing a sse_client."""

    # The endpoint URL.
    url: str

    # Optional headers to include in requests.
    headers: dict[str, Any] | None = None

    # HTTP timeout for regular operations.
    timeout: float = 5

    # Timeout for SSE read operations.
    sse_read_timeout: float = 60 * 5

## StreamableHttpParameters

**Type**: Class

**Description**: class StreamableHttpParameters(BaseModel):
    """Parameters for intializing a streamablehttp_client."""

    # The endpoint URL.
    url: str

    # Optional headers to include in requests.
    headers: dict[str, Any] | None = None

    # HTTP timeout for regular operations.
    timeout: timedelta = timedelta(seconds=30)

    # Timeout for SSE read operations.
    sse_read_timeout: timedelta = timedelta(seconds=60 * 5)

    # Close the client session when the transport closes.
    terminate_on_close: bool = True

## ClientSessionGroup

**Type**: Class

**Description**: class ClientSessionGroup:
    """Client for managing connections to multiple MCP servers.

    This class is responsible for encapsulating management of server connections.
    It aggregates tools, resources, and prompts from all connected servers.

    For auxiliary handlers, such as resource subscription, this is delegated to
    the client and can be accessed via the session.

    Example Usage:
        name_fn = lambda name, server_info: f"{(server_info.name)}_{name}"
        async with ClientSessionGroup(component_name_hook=name_fn) as group:
            for server_params in server_params:
                await group.connect_to_server(server_param)
            ...

    """

    class _ComponentNames(BaseModel):
        """Used for reverse index to find components."""

        prompts: set[str] = set()
        resources: set[str] = set()
        tools: set[str] = set()

    # Standard MCP components.
    _prompts: dict[str, types.Prompt]
    _resources: dict[str, types.Resource]
    _tools: dict[str, types.Tool]

    # Client-server connection management.
    _sessions: dict[mcp.ClientSession, _ComponentNames]
    _tool_to_session: dict[str, mcp.ClientSession]
    _exit_stack: contextlib.AsyncExitStack
    _session_exit_stacks: dict[mcp.ClientSession, contextlib.AsyncExitStack]

    # Optional fn consuming (component_name, serverInfo) for custom names.
    # This is provide a means to mitigate naming conflicts across servers.
    # Example: (tool_name, serverInfo) => "{result.serverInfo.name}.{tool_name}"
    _ComponentNameHook: TypeAlias = Callable[[str, types.Implementation], str]
    _component_name_hook: _ComponentNameHook | None

    def __init__(
        self,
        exit_stack: contextlib.AsyncExitStack | None = None,
        component_name_hook: _ComponentNameHook | None = None,
    ) -> None:
        """Initializes the MCP client."""

        self._tools = {}
        self._resources = {}
        self._prompts = {}

        self._sessions = {}
        self._tool_to_session = {}
        if exit_stack is None:
            self._exit_stack = contextlib.AsyncExitStack()
            self._owns_exit_stack = True
        else:
            self._exit_stack = exit_stack
            self._owns_exit_stack = False
        self._session_exit_stacks = {}
        self._component_name_hook = component_name_hook

    async def __aenter__(self) -> Self:
        # Enter the exit stack only if we created it ourselves
        if self._owns_exit_stack:
            await self._exit_stack.__aenter__()
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> bool | None:
        """Closes session exit stacks and main exit stack upon completion."""

        # Only close the main exit stack if we created it
        if self._owns_exit_stack:
            await self._exit_stack.aclose()

        # Concurrently close session stacks.
        async with anyio.create_task_group() as tg:
            for exit_stack in self._session_exit_stacks.values():
                tg.start_soon(exit_stack.aclose)

    @property
    def sessions(self) -> list[mcp.ClientSession]:
        """Returns the list of sessions being managed."""
        return list(self._sessions.keys())

    @property
    def prompts(self) -> dict[str, types.Prompt]:
        """Returns the prompts as a dictionary of names to prompts."""
        return self._prompts

    @property
    def resources(self) -> dict[str, types.Resource]:
        """Returns the resources as a dictionary of names to resources."""
        return self._resources

    @property
    def tools(self) -> dict[str, types.Tool]:
        """Returns the tools as a dictionary of names to tools."""
        return self._tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> types.CallToolResult:
        """Executes a tool given its name and arguments."""
        session = self._tool_to_session[name]
        session_tool_name = self.tools[name].name
        return await session.call_tool(session_tool_name, args)

    async def disconnect_from_server(self, session: mcp.ClientSession) -> None:
        """Disconnects from a single MCP server."""

        session_known_for_components = session in self._sessions
        session_known_for_stack = session in self._session_exit_stacks

        if not session_known_for_components and not session_known_for_stack:
            raise McpError(
                types.ErrorData(
                    code=types.INVALID_PARAMS,
                    message="Provided session is not managed or already disconnected.",
                )
            )

        if session_known_for_components:
            component_names = self._sessions.pop(session)  # Pop from _sessions tracking

            # Remove prompts associated with the session.
            for name in component_names.prompts:
                if name in self._prompts:
                    del self._prompts[name]
            # Remove resources associated with the session.
            for name in component_names.resources:
                if name in self._resources:
                    del self._resources[name]
            # Remove tools associated with the session.
            for name in component_names.tools:
                if name in self._tools:
                    del self._tools[name]
                if name in self._tool_to_session:
                    del self._tool_to_session[name]

        # Clean up the session's resources via its dedicated exit stack
        if session_known_for_stack:
            session_stack_to_close = self._session_exit_stacks.pop(session)
            await session_stack_to_close.aclose()

    async def connect_with_session(
        self, server_info: types.Implementation, session: mcp.ClientSession
    ) -> mcp.ClientSession:
        """Connects to a single MCP server."""
        await self._aggregate_components(server_info, session)
        return session

    async def connect_to_server(
        self,
        server_params: ServerParameters,
    ) -> mcp.ClientSession:
        """Connects to a single MCP server."""
        server_info, session = await self._establish_session(server_params)
        return await self.connect_with_session(server_info, session)

    async def _establish_session(
        self, server_params: ServerParameters
    ) -> tuple[types.Implementation, mcp.ClientSession]:
        """Establish a client session to an MCP server."""

        session_stack = contextlib.AsyncExitStack()
        try:
            # Create read and write streams that facilitate io with the server.
            if isinstance(server_params, StdioServerParameters):
                client = mcp.stdio_client(server_params)
                read, write = await session_stack.enter_async_context(client)
            elif isinstance(server_params, SseServerParameters):
                client = sse_client(
                    url=server_params.url,
                    headers=server_params.headers,
                    timeout=server_params.timeout,
                    sse_read_timeout=server_params.sse_read_timeout,
                )
                read, write = await session_stack.enter_async_context(client)
            else:
                client = streamablehttp_client(
                    url=server_params.url,
                    headers=server_params.headers,
                    timeout=server_params.timeout,
                    sse_read_timeout=server_params.sse_read_timeout,
                    terminate_on_close=server_params.terminate_on_close,
                )
                read, write, _ = await session_stack.enter_async_context(client)

            session = await session_stack.enter_async_context(mcp.ClientSession(read, write))
            result = await session.initialize()

            # Session successfully initialized.
            # Store its stack and register the stack with the main group stack.
            self._session_exit_stacks[session] = session_stack
            # session_stack itself becomes a resource managed by the
            # main _exit_stack.
            await self._exit_stack.enter_async_context(session_stack)

            return result.serverInfo, session
        except Exception:
            # If anything during this setup fails, ensure the session-specific
            # stack is closed.
            await session_stack.aclose()
            raise

    async def _aggregate_components(self, server_info: types.Implementation, session: mcp.ClientSession) -> None:
        """Aggregates prompts, resources, and tools from a given session."""

        # Create a reverse index so we can find all prompts, resources, and
        # tools belonging to this session. Used for removing components from
        # the session group via self.disconnect_from_server.
        component_names = self._ComponentNames()

        # Temporary components dicts. We do not want to modify the aggregate
        # lists in case of an intermediate failure.
        prompts_temp: dict[str, types.Prompt] = {}
        resources_temp: dict[str, types.Resource] = {}
        tools_temp: dict[str, types.Tool] = {}
        tool_to_session_temp: dict[str, mcp.ClientSession] = {}

        # Query the server for its prompts and aggregate to list.
        try:
            prompts = (await session.list_prompts()).prompts
            for prompt in prompts:
                name = self._component_name(prompt.name, server_info)
                prompts_temp[name] = prompt
                component_names.prompts.add(name)
        except McpError as err:
            logging.warning(f"Could not fetch prompts: {err}")

        # Query the server for its resources and aggregate to list.
        try:
            resources = (await session.list_resources()).resources
            for resource in resources:
                name = self._component_name(resource.name, server_info)
                resources_temp[name] = resource
                component_names.resources.add(name)
        except McpError as err:
            logging.warning(f"Could not fetch resources: {err}")

        # Query the server for its tools and aggregate to list.
        try:
            tools = (await session.list_tools()).tools
            for tool in tools:
                name = self._component_name(tool.name, server_info)
                tools_temp[name] = tool
                tool_to_session_temp[name] = session
                component_names.tools.add(name)
        except McpError as err:
            logging.warning(f"Could not fetch tools: {err}")

        # Clean up exit stack for session if we couldn't retrieve anything
        # from the server.
        if not any((prompts_temp, resources_temp, tools_temp)):
            del self._session_exit_stacks[session]

        # Check for duplicates.
        matching_prompts = prompts_temp.keys() & self._prompts.keys()
        if matching_prompts:
            raise McpError(
                types.ErrorData(
                    code=types.INVALID_PARAMS,
                    message=f"{matching_prompts} already exist in group prompts.",
                )
            )
        matching_resources = resources_temp.keys() & self._resources.keys()
        if matching_resources:
            raise McpError(
                types.ErrorData(
                    code=types.INVALID_PARAMS,
                    message=f"{matching_resources} already exist in group resources.",
                )
            )
        matching_tools = tools_temp.keys() & self._tools.keys()
        if matching_tools:
            raise McpError(
                types.ErrorData(
                    code=types.INVALID_PARAMS,
                    message=f"{matching_tools} already exist in group tools.",
                )
            )

        # Aggregate components.
        self._sessions[session] = component_names
        self._prompts.update(prompts_temp)
        self._resources.update(resources_temp)
        self._tools.update(tools_temp)
        self._tool_to_session.update(tool_to_session_temp)

    def _component_name(self, name: str, server_info: types.Implementation) -> str:
        if self._component_name_hook:
            return self._component_name_hook(name, server_info)
        return name

## remove_request_params

**Type**: Function

**Description**: def remove_request_params(url: str) -> str:
    return urljoin(url, urlparse(url).path)

## StreamableHTTPError

**Type**: Class

**Description**: class StreamableHTTPError(Exception):
    """Base exception for StreamableHTTP transport errors."""

## ResumptionError

**Type**: Class

**Description**: class ResumptionError(StreamableHTTPError):
    """Raised when resumption request is invalid."""

## StreamableHTTPTransport

**Type**: Class

**Description**: class StreamableHTTPTransport:
    """StreamableHTTP client transport implementation."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float | timedelta = 30,
        sse_read_timeout: float | timedelta = 60 * 5,
        auth: httpx.Auth | None = None,
    ) -> None:
        """Initialize the StreamableHTTP transport.

        Args:
            url: The endpoint URL.
            headers: Optional headers to include in requests.
            timeout: HTTP timeout for regular operations.
            sse_read_timeout: Timeout for SSE read operations.
            auth: Optional HTTPX authentication handler.
        """
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout.total_seconds() if isinstance(timeout, timedelta) else timeout
        self.sse_read_timeout = (
            sse_read_timeout.total_seconds() if isinstance(sse_read_timeout, timedelta) else sse_read_timeout
        )
        self.auth = auth
        self.session_id = None
        self.protocol_version = None
        self.request_headers = {
            ACCEPT: f"{JSON}, {SSE}",
            CONTENT_TYPE: JSON,
            **self.headers,
        }

    def _prepare_request_headers(self, base_headers: dict[str, str]) -> dict[str, str]:
        """Update headers with session ID and protocol version if available."""
        headers = base_headers.copy()
        if self.session_id:
            headers[MCP_SESSION_ID] = self.session_id
        if self.protocol_version:
            headers[MCP_PROTOCOL_VERSION] = self.protocol_version
        return headers

    def _is_initialization_request(self, message: JSONRPCMessage) -> bool:
        """Check if the message is an initialization request."""
        return isinstance(message.root, JSONRPCRequest) and message.root.method == "initialize"

    def _is_initialized_notification(self, message: JSONRPCMessage) -> bool:
        """Check if the message is an initialized notification."""
        return isinstance(message.root, JSONRPCNotification) and message.root.method == "notifications/initialized"

    def _maybe_extract_session_id_from_response(
        self,
        response: httpx.Response,
    ) -> None:
        """Extract and store session ID from response headers."""
        new_session_id = response.headers.get(MCP_SESSION_ID)
        if new_session_id:
            self.session_id = new_session_id
            logger.info(f"Received session ID: {self.session_id}")

    def _maybe_extract_protocol_version_from_message(
        self,
        message: JSONRPCMessage,
    ) -> None:
        """Extract protocol version from initialization response message."""
        if isinstance(message.root, JSONRPCResponse) and message.root.result:
            try:
                # Parse the result as InitializeResult for type safety
                init_result = InitializeResult.model_validate(message.root.result)
                self.protocol_version = str(init_result.protocolVersion)
                logger.info(f"Negotiated protocol version: {self.protocol_version}")
            except Exception as exc:
                logger.warning(f"Failed to parse initialization response as InitializeResult: {exc}")
                logger.warning(f"Raw result: {message.root.result}")

    async def _handle_sse_event(
        self,
        sse: ServerSentEvent,
        read_stream_writer: StreamWriter,
        original_request_id: RequestId | None = None,
        resumption_callback: Callable[[str], Awaitable[None]] | None = None,
        is_initialization: bool = False,
    ) -> bool:
        """Handle an SSE event, returning True if the response is complete."""
        if sse.event == "message":
            try:
                message = JSONRPCMessage.model_validate_json(sse.data)
                logger.debug(f"SSE message: {message}")

                # Extract protocol version from initialization response
                if is_initialization:
                    self._maybe_extract_protocol_version_from_message(message)

                # If this is a response and we have original_request_id, replace it
                if original_request_id is not None and isinstance(message.root, JSONRPCResponse | JSONRPCError):
                    message.root.id = original_request_id

                session_message = SessionMessage(message)
                await read_stream_writer.send(session_message)

                # Call resumption token callback if we have an ID
                if sse.id and resumption_callback:
                    await resumption_callback(sse.id)

                # If this is a response or error return True indicating completion
                # Otherwise, return False to continue listening
                return isinstance(message.root, JSONRPCResponse | JSONRPCError)

            except Exception as exc:
                logger.exception("Error parsing SSE message")
                await read_stream_writer.send(exc)
                return False
        else:
            logger.warning(f"Unknown SSE event: {sse.event}")
            return False

    async def handle_get_stream(
        self,
        client: httpx.AsyncClient,
        read_stream_writer: StreamWriter,
    ) -> None:
        """Handle GET stream for server-initiated messages."""
        try:
            if not self.session_id:
                return

            headers = self._prepare_request_headers(self.request_headers)

            async with aconnect_sse(
                client,
                "GET",
                self.url,
                headers=headers,
                timeout=httpx.Timeout(self.timeout, read=self.sse_read_timeout),
            ) as event_source:
                event_source.response.raise_for_status()
                logger.debug("GET SSE connection established")

                async for sse in event_source.aiter_sse():
                    await self._handle_sse_event(sse, read_stream_writer)

        except Exception as exc:
            logger.debug(f"GET stream error (non-fatal): {exc}")

    async def _handle_resumption_request(self, ctx: RequestContext) -> None:
        """Handle a resumption request using GET with SSE."""
        headers = self._prepare_request_headers(ctx.headers)
        if ctx.metadata and ctx.metadata.resumption_token:
            headers[LAST_EVENT_ID] = ctx.metadata.resumption_token
        else:
            raise ResumptionError("Resumption request requires a resumption token")

        # Extract original request ID to map responses
        original_request_id = None
        if isinstance(ctx.session_message.message.root, JSONRPCRequest):
            original_request_id = ctx.session_message.message.root.id

        async with aconnect_sse(
            ctx.client,
            "GET",
            self.url,
            headers=headers,
            timeout=httpx.Timeout(self.timeout, read=self.sse_read_timeout),
        ) as event_source:
            event_source.response.raise_for_status()
            logger.debug("Resumption GET SSE connection established")

            async for sse in event_source.aiter_sse():
                is_complete = await self._handle_sse_event(
                    sse,
                    ctx.read_stream_writer,
                    original_request_id,
                    ctx.metadata.on_resumption_token_update if ctx.metadata else None,
                )
                if is_complete:
                    break

    async def _handle_post_request(self, ctx: RequestContext) -> None:
        """Handle a POST request with response processing."""
        headers = self._prepare_request_headers(ctx.headers)
        message = ctx.session_message.message
        is_initialization = self._is_initialization_request(message)

        async with ctx.client.stream(
            "POST",
            self.url,
            json=message.model_dump(by_alias=True, mode="json", exclude_none=True),
            headers=headers,
        ) as response:
            if response.status_code == 202:
                logger.debug("Received 202 Accepted")
                return

            if response.status_code == 404:
                if isinstance(message.root, JSONRPCRequest):
                    await self._send_session_terminated_error(
                        ctx.read_stream_writer,
                        message.root.id,
                    )
                return

            response.raise_for_status()
            if is_initialization:
                self._maybe_extract_session_id_from_response(response)

            content_type = response.headers.get(CONTENT_TYPE, "").lower()

            if content_type.startswith(JSON):
                await self._handle_json_response(response, ctx.read_stream_writer, is_initialization)
            elif content_type.startswith(SSE):
                await self._handle_sse_response(response, ctx, is_initialization)
            else:
                await self._handle_unexpected_content_type(
                    content_type,
                    ctx.read_stream_writer,
                )

    async def _handle_json_response(
        self,
        response: httpx.Response,
        read_stream_writer: StreamWriter,
        is_initialization: bool = False,
    ) -> None:
        """Handle JSON response from the server."""
        try:
            content = await response.aread()
            message = JSONRPCMessage.model_validate_json(content)

            # Extract protocol version from initialization response
            if is_initialization:
                self._maybe_extract_protocol_version_from_message(message)

            session_message = SessionMessage(message)
            await read_stream_writer.send(session_message)
        except Exception as exc:
            logger.error(f"Error parsing JSON response: {exc}")
            await read_stream_writer.send(exc)

    async def _handle_sse_response(
        self,
        response: httpx.Response,
        ctx: RequestContext,
        is_initialization: bool = False,
    ) -> None:
        """Handle SSE response from the server."""
        try:
            event_source = EventSource(response)
            async for sse in event_source.aiter_sse():
                is_complete = await self._handle_sse_event(
                    sse,
                    ctx.read_stream_writer,
                    resumption_callback=(ctx.metadata.on_resumption_token_update if ctx.metadata else None),
                    is_initialization=is_initialization,
                )
                # If the SSE event indicates completion, like returning respose/error
                # break the loop
                if is_complete:
                    break
        except Exception as e:
            logger.exception("Error reading SSE stream:")
            await ctx.read_stream_writer.send(e)

    async def _handle_unexpected_content_type(
        self,
        content_type: str,
        read_stream_writer: StreamWriter,
    ) -> None:
        """Handle unexpected content type in response."""
        error_msg = f"Unexpected content type: {content_type}"
        logger.error(error_msg)
        await read_stream_writer.send(ValueError(error_msg))

    async def _send_session_terminated_error(
        self,
        read_stream_writer: StreamWriter,
        request_id: RequestId,
    ) -> None:
        """Send a session terminated error response."""
        jsonrpc_error = JSONRPCError(
            jsonrpc="2.0",
            id=request_id,
            error=ErrorData(code=32600, message="Session terminated"),
        )
        session_message = SessionMessage(JSONRPCMessage(jsonrpc_error))
        await read_stream_writer.send(session_message)

    async def post_writer(
        self,
        client: httpx.AsyncClient,
        write_stream_reader: StreamReader,
        read_stream_writer: StreamWriter,
        write_stream: MemoryObjectSendStream[SessionMessage],
        start_get_stream: Callable[[], None],
        tg: TaskGroup,
    ) -> None:
        """Handle writing requests to the server."""
        try:
            async with write_stream_reader:
                async for session_message in write_stream_reader:
                    message = session_message.message
                    metadata = (
                        session_message.metadata
                        if isinstance(session_message.metadata, ClientMessageMetadata)
                        else None
                    )

                    # Check if this is a resumption request
                    is_resumption = bool(metadata and metadata.resumption_token)

                    logger.debug(f"Sending client message: {message}")

                    # Handle initialized notification
                    if self._is_initialized_notification(message):
                        start_get_stream()

                    ctx = RequestContext(
                        client=client,
                        headers=self.request_headers,
                        session_id=self.session_id,
                        session_message=session_message,
                        metadata=metadata,
                        read_stream_writer=read_stream_writer,
                        sse_read_timeout=self.sse_read_timeout,
                    )

                    async def handle_request_async():
                        if is_resumption:
                            await self._handle_resumption_request(ctx)
                        else:
                            await self._handle_post_request(ctx)

                    # If this is a request, start a new task to handle it
                    if isinstance(message.root, JSONRPCRequest):
                        tg.start_soon(handle_request_async)
                    else:
                        await handle_request_async()

        except Exception as exc:
            logger.error(f"Error in post_writer: {exc}")
        finally:
            await read_stream_writer.aclose()
            await write_stream.aclose()

    async def terminate_session(self, client: httpx.AsyncClient) -> None:
        """Terminate the session by sending a DELETE request."""
        if not self.session_id:
            return

        try:
            headers = self._prepare_request_headers(self.request_headers)
            response = await client.delete(self.url, headers=headers)

            if response.status_code == 405:
                logger.debug("Server does not allow session termination")
            elif response.status_code not in (200, 204):
                logger.warning(f"Session termination failed: {response.status_code}")
        except Exception as exc:
            logger.warning(f"Session termination failed: {exc}")

    def get_session_id(self) -> str | None:
        """Get the current session ID."""
        return self.session_id

## message_handler

**Type**: Function

**Description**: async def message_handler(
    message: RequestResponder[types.ServerRequest, types.ClientResult] | types.ServerNotification | Exception,
) -> None:
    if isinstance(message, Exception):
        logger.error("Error: %s", message)
        return

    logger.info("Received message from server: %s", message)

## run_session

**Type**: Function

**Description**: async def run_session(
    read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
    write_stream: MemoryObjectSendStream[SessionMessage],
    client_info: types.Implementation | None = None,
):
    async with ClientSession(
        read_stream,
        write_stream,
        message_handler=message_handler,
        client_info=client_info,
    ) as session:
        logger.info("Initializing session")
        await session.initialize()
        logger.info("Initialized")

## main

**Type**: Function

**Description**: async def main(command_or_url: str, args: list[str], env: list[tuple[str, str]]):
    env_dict = dict(env)

    if urlparse(command_or_url).scheme in ("http", "https"):
        # Use SSE client for HTTP(S) URLs
        async with sse_client(command_or_url) as streams:
            await run_session(*streams)
    else:
        # Use stdio client for commands
        server_parameters = StdioServerParameters(command=command_or_url, args=args, env=env_dict)
        async with stdio_client(server_parameters) as streams:
            await run_session(*streams)

## cli

**Type**: Function

**Description**: def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("command_or_url", help="Command or URL to connect to")
    parser.add_argument("args", nargs="*", help="Additional arguments")
    parser.add_argument(
        "-e",
        "--env",
        nargs=2,
        action="append",
        metavar=("KEY", "VALUE"),
        help="Environment variables to set. Can be used multiple times.",
        default=[],
    )

    args = parser.parse_args()
    anyio.run(partial(main, args.command_or_url, args.args, args.env), backend="trio")

## get_windows_executable_command

**Type**: Function

**Description**: def get_windows_executable_command(command: str) -> str:
    """
    Get the correct executable command normalized for Windows.

    On Windows, commands might exist with specific extensions (.exe, .cmd, etc.)
    that need to be located for proper execution.

    Args:
        command: Base command (e.g., 'uvx', 'npx')

    Returns:
        str: Windows-appropriate command path
    """
    try:
        # First check if command exists in PATH as-is
        if command_path := shutil.which(command):
            return command_path

        # Check for Windows-specific extensions
        for ext in [".cmd", ".bat", ".exe", ".ps1"]:
            ext_version = f"{command}{ext}"
            if ext_path := shutil.which(ext_version):
                return ext_path

        # For regular commands or if we couldn't find special versions
        return command
    except OSError:
        # Handle file system errors during path resolution
        # (permissions, broken symlinks, etc.)
        return command

## FallbackProcess

**Type**: Class

**Description**: class FallbackProcess:
    """
    A fallback process wrapper for Windows to handle async I/O
    when using subprocess.Popen, which provides sync-only FileIO objects.

    This wraps stdin and stdout into async-compatible
    streams (FileReadStream, FileWriteStream),
    so that MCP clients expecting async streams can work properly.
    """

    def __init__(self, popen_obj: subprocess.Popen[bytes]):
        self.popen: subprocess.Popen[bytes] = popen_obj
        self.stdin_raw = popen_obj.stdin  # type: ignore[assignment]
        self.stdout_raw = popen_obj.stdout  # type: ignore[assignment]
        self.stderr = popen_obj.stderr  # type: ignore[assignment]

        self.stdin = FileWriteStream(cast(BinaryIO, self.stdin_raw)) if self.stdin_raw else None
        self.stdout = FileReadStream(cast(BinaryIO, self.stdout_raw)) if self.stdout_raw else None

    async def __aenter__(self):
        """Support async context manager entry."""
        return self

    async def __aexit__(
        self,
        exc_type: BaseException | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        """Terminate and wait on process exit inside a thread."""
        self.popen.terminate()
        await to_thread.run_sync(self.popen.wait)

        # Close the file handles to prevent ResourceWarning
        if self.stdin:
            await self.stdin.aclose()
        if self.stdout:
            await self.stdout.aclose()
        if self.stdin_raw:
            self.stdin_raw.close()
        if self.stdout_raw:
            self.stdout_raw.close()
        if self.stderr:
            self.stderr.close()

    async def wait(self):
        """Async wait for process completion."""
        return await to_thread.run_sync(self.popen.wait)

    def terminate(self):
        """Terminate the subprocess immediately."""
        return self.popen.terminate()

    def kill(self) -> None:
        """Kill the subprocess immediately (alias for terminate)."""
        self.terminate()

## create_windows_process

**Type**: Function

**Description**: async def create_windows_process(
    command: str,
    args: list[str],
    env: dict[str, str] | None = None,
    errlog: TextIO | None = sys.stderr,
    cwd: Path | str | None = None,
) -> FallbackProcess:
    """
    Creates a subprocess in a Windows-compatible way.

    On Windows, asyncio.create_subprocess_exec has incomplete support
    (NotImplementedError when trying to open subprocesses).
    Therefore, we fallback to subprocess.Popen and wrap it for async usage.

    Args:
        command (str): The executable to run
        args (list[str]): List of command line arguments
        env (dict[str, str] | None): Environment variables
        errlog (TextIO | None): Where to send stderr output (defaults to sys.stderr)
        cwd (Path | str | None): Working directory for the subprocess

    Returns:
        FallbackProcess: Async-compatible subprocess with stdin and stdout streams
    """
    try:
        # Try launching with creationflags to avoid opening a new console window
        popen_obj = subprocess.Popen(
            [command, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errlog,
            env=env,
            cwd=cwd,
            bufsize=0,  # Unbuffered output
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return FallbackProcess(popen_obj)

    except Exception:
        # If creationflags failed, fallback without them
        popen_obj = subprocess.Popen(
            [command, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errlog,
            env=env,
            cwd=cwd,
            bufsize=0,
        )
        return FallbackProcess(popen_obj)

## terminate_windows_process

**Type**: Function

**Description**: async def terminate_windows_process(process: Process | FallbackProcess):
    """
    Terminate a Windows process.

    Note: On Windows, terminating a process with process.terminate() doesn't
    always guarantee immediate process termination.
    So we give it 2s to exit, or we call process.kill()
    which sends a SIGKILL equivalent signal.

    Args:
        process: The process to terminate
    """
    try:
        process.terminate()
        with anyio.fail_after(2.0):
            await process.wait()
    except TimeoutError:
        # Force kill if it doesn't terminate
        process.kill()

## get_default_environment

**Type**: Function

**Description**: def get_default_environment() -> dict[str, str]:
    """
    Returns a default environment object including only environment variables deemed
    safe to inherit.
    """
    env: dict[str, str] = {}

    for key in DEFAULT_INHERITED_ENV_VARS:
        value = os.environ.get(key)
        if value is None:
            continue

        if value.startswith("()"):
            # Skip functions, which are a security risk
            continue

        env[key] = value

    return env

## StdioServerParameters

**Type**: Class

**Description**: class StdioServerParameters(BaseModel):
    command: str
    """The executable to run to start the server."""

    args: list[str] = Field(default_factory=list)
    """Command line arguments to pass to the executable."""

    env: dict[str, str] | None = None
    """
    The environment to use when spawning the process.

    If not specified, the result of get_default_environment() will be used.
    """

    cwd: str | Path | None = None
    """The working directory to use when spawning the process."""

    encoding: str = "utf-8"
    """
    The text encoding used when sending/receiving messages to the server

    defaults to utf-8
    """

    encoding_error_handler: Literal["strict", "ignore", "replace"] = "strict"
    """
    The text encoding error handler.

    See https://docs.python.org/3/library/codecs.html#codec-base-classes for
    explanations of possible values
    """

## _get_executable_command

**Type**: Function

**Description**: def _get_executable_command(command: str) -> str:
    """
    Get the correct executable command normalized for the current platform.

    Args:
        command: Base command (e.g., 'uvx', 'npx')

    Returns:
        str: Platform-appropriate command
    """
    if sys.platform == "win32":
        return get_windows_executable_command(command)
    else:
        return command

## _create_platform_compatible_process

**Type**: Function

**Description**: async def _create_platform_compatible_process(
    command: str,
    args: list[str],
    env: dict[str, str] | None = None,
    errlog: TextIO = sys.stderr,
    cwd: Path | str | None = None,
):
    """
    Creates a subprocess in a platform-compatible way.
    Returns a process handle.
    """
    if sys.platform == "win32":
        process = await create_windows_process(command, args, env, errlog, cwd)
    else:
        process = await anyio.open_process([command, *args], env=env, stderr=errlog, cwd=cwd)

    return process

## AcceptedElicitation

**Type**: Class

**Description**: class AcceptedElicitation(BaseModel, Generic[ElicitSchemaModelT]):
    """Result when user accepts the elicitation."""

    action: Literal["accept"] = "accept"
    data: ElicitSchemaModelT

## DeclinedElicitation

**Type**: Class

**Description**: class DeclinedElicitation(BaseModel):
    """Result when user declines the elicitation."""

    action: Literal["decline"] = "decline"

## CancelledElicitation

**Type**: Class

**Description**: class CancelledElicitation(BaseModel):
    """Result when user cancels the elicitation."""

    action: Literal["cancel"] = "cancel"

## _validate_elicitation_schema

**Type**: Function

**Description**: def _validate_elicitation_schema(schema: type[BaseModel]) -> None:
    """Validate that a Pydantic model only contains primitive field types."""
    for field_name, field_info in schema.model_fields.items():
        if not _is_primitive_field(field_info):
            raise TypeError(
                f"Elicitation schema field '{field_name}' must be a primitive type "
                f"{_ELICITATION_PRIMITIVE_TYPES} or Optional of these types. "
                f"Complex types like lists, dicts, or nested models are not allowed."
            )

## _is_primitive_field

**Type**: Function

**Description**: def _is_primitive_field(field_info: FieldInfo) -> bool:
    """Check if a field is a primitive type allowed in elicitation schemas."""
    annotation = field_info.annotation

    # Handle None type
    if annotation is types.NoneType:
        return True

    # Handle basic primitive types
    if annotation in _ELICITATION_PRIMITIVE_TYPES:
        return True

    # Handle Union types
    origin = get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        args = get_args(annotation)
        # All args must be primitive types or None
        return all(arg is types.NoneType or arg in _ELICITATION_PRIMITIVE_TYPES for arg in args)

    return False

## elicit_with_validation

**Type**: Function

**Description**: async def elicit_with_validation(
    session: ServerSession,
    message: str,
    schema: type[ElicitSchemaModelT],
    related_request_id: RequestId | None = None,
) -> ElicitationResult[ElicitSchemaModelT]:
    """Elicit information from the client/user with schema validation.

    This method can be used to interactively ask for additional information from the
    client within a tool's execution. The client might display the message to the
    user and collect a response according to the provided schema. Or in case a
    client is an agent, it might decide how to handle the elicitation -- either by asking
    the user or automatically generating a response.
    """
    # Validate that schema only contains primitive types and fail loudly if not
    _validate_elicitation_schema(schema)

    json_schema = schema.model_json_schema()

    result = await session.elicit(
        message=message,
        requestedSchema=json_schema,
        related_request_id=related_request_id,
    )

    if result.action == "accept" and result.content:
        # Validate and parse the content using the schema
        validated_data = schema.model_validate(result.content)
        return AcceptedElicitation(data=validated_data)
    elif result.action == "decline":
        return DeclinedElicitation()
    elif result.action == "cancel":
        return CancelledElicitation()
    else:
        # This should never happen, but handle it just in case
        raise ValueError(f"Unexpected elicitation action: {result.action}")

## InitializationOptions

**Type**: Class

**Description**: class InitializationOptions(BaseModel):
    server_name: str
    server_version: str
    capabilities: ServerCapabilities
    instructions: str | None = None

## InitializationState

**Type**: Class

**Description**: class InitializationState(Enum):
    NotInitialized = 1
    Initializing = 2
    Initialized = 3

## ServerSession

**Type**: Class

**Description**: class ServerSession(
    BaseSession[
        types.ServerRequest,
        types.ServerNotification,
        types.ServerResult,
        types.ClientRequest,
        types.ClientNotification,
    ]
):
    _initialized: InitializationState = InitializationState.NotInitialized
    _client_params: types.InitializeRequestParams | None = None

    def __init__(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        init_options: InitializationOptions,
        stateless: bool = False,
    ) -> None:
        super().__init__(read_stream, write_stream, types.ClientRequest, types.ClientNotification)
        self._initialization_state = (
            InitializationState.Initialized if stateless else InitializationState.NotInitialized
        )

        self._init_options = init_options
        self._incoming_message_stream_writer, self._incoming_message_stream_reader = anyio.create_memory_object_stream[
            ServerRequestResponder
        ](0)
        self._exit_stack.push_async_callback(lambda: self._incoming_message_stream_reader.aclose())

    @property
    def client_params(self) -> types.InitializeRequestParams | None:
        return self._client_params

    def check_client_capability(self, capability: types.ClientCapabilities) -> bool:
        """Check if the client supports a specific capability."""
        if self._client_params is None:
            return False

        # Get client capabilities from initialization params
        client_caps = self._client_params.capabilities

        # Check each specified capability in the passed in capability object
        if capability.roots is not None:
            if client_caps.roots is None:
                return False
            if capability.roots.listChanged and not client_caps.roots.listChanged:
                return False

        if capability.sampling is not None:
            if client_caps.sampling is None:
                return False

        if capability.elicitation is not None:
            if client_caps.elicitation is None:
                return False

        if capability.experimental is not None:
            if client_caps.experimental is None:
                return False
            # Check each experimental capability
            for exp_key, exp_value in capability.experimental.items():
                if exp_key not in client_caps.experimental or client_caps.experimental[exp_key] != exp_value:
                    return False

        return True

    async def _receive_loop(self) -> None:
        async with self._incoming_message_stream_writer:
            await super()._receive_loop()

    async def _received_request(self, responder: RequestResponder[types.ClientRequest, types.ServerResult]):
        match responder.request.root:
            case types.InitializeRequest(params=params):
                requested_version = params.protocolVersion
                self._initialization_state = InitializationState.Initializing
                self._client_params = params
                with responder:
                    await responder.respond(
                        types.ServerResult(
                            types.InitializeResult(
                                protocolVersion=requested_version
                                if requested_version in SUPPORTED_PROTOCOL_VERSIONS
                                else types.LATEST_PROTOCOL_VERSION,
                                capabilities=self._init_options.capabilities,
                                serverInfo=types.Implementation(
                                    name=self._init_options.server_name,
                                    version=self._init_options.server_version,
                                ),
                                instructions=self._init_options.instructions,
                            )
                        )
                    )
            case _:
                if self._initialization_state != InitializationState.Initialized:
                    raise RuntimeError("Received request before initialization was complete")

    async def _received_notification(self, notification: types.ClientNotification) -> None:
        # Need this to avoid ASYNC910
        await anyio.lowlevel.checkpoint()
        match notification.root:
            case types.InitializedNotification():
                self._initialization_state = InitializationState.Initialized
            case _:
                if self._initialization_state != InitializationState.Initialized:
                    raise RuntimeError("Received notification before initialization was complete")

    async def send_log_message(
        self,
        level: types.LoggingLevel,
        data: Any,
        logger: str | None = None,
        related_request_id: types.RequestId | None = None,
    ) -> None:
        """Send a log message notification."""
        await self.send_notification(
            types.ServerNotification(
                types.LoggingMessageNotification(
                    method="notifications/message",
                    params=types.LoggingMessageNotificationParams(
                        level=level,
                        data=data,
                        logger=logger,
                    ),
                )
            ),
            related_request_id,
        )

    async def send_resource_updated(self, uri: AnyUrl) -> None:
        """Send a resource updated notification."""
        await self.send_notification(
            types.ServerNotification(
                types.ResourceUpdatedNotification(
                    method="notifications/resources/updated",
                    params=types.ResourceUpdatedNotificationParams(uri=uri),
                )
            )
        )

    async def create_message(
        self,
        messages: list[types.SamplingMessage],
        *,
        max_tokens: int,
        system_prompt: str | None = None,
        include_context: types.IncludeContext | None = None,
        temperature: float | None = None,
        stop_sequences: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        model_preferences: types.ModelPreferences | None = None,
        related_request_id: types.RequestId | None = None,
    ) -> types.CreateMessageResult:
        """Send a sampling/create_message request."""
        return await self.send_request(
            request=types.ServerRequest(
                types.CreateMessageRequest(
                    method="sampling/createMessage",
                    params=types.CreateMessageRequestParams(
                        messages=messages,
                        systemPrompt=system_prompt,
                        includeContext=include_context,
                        temperature=temperature,
                        maxTokens=max_tokens,
                        stopSequences=stop_sequences,
                        metadata=metadata,
                        modelPreferences=model_preferences,
                    ),
                )
            ),
            result_type=types.CreateMessageResult,
            metadata=ServerMessageMetadata(
                related_request_id=related_request_id,
            ),
        )

    async def list_roots(self) -> types.ListRootsResult:
        """Send a roots/list request."""
        return await self.send_request(
            types.ServerRequest(
                types.ListRootsRequest(
                    method="roots/list",
                )
            ),
            types.ListRootsResult,
        )

    async def elicit(
        self,
        message: str,
        requestedSchema: types.ElicitRequestedSchema,
        related_request_id: types.RequestId | None = None,
    ) -> types.ElicitResult:
        """Send an elicitation/create request.

        Args:
            message: The message to present to the user
            requestedSchema: Schema defining the expected response structure

        Returns:
            The client's response
        """
        return await self.send_request(
            types.ServerRequest(
                types.ElicitRequest(
                    method="elicitation/create",
                    params=types.ElicitRequestParams(
                        message=message,
                        requestedSchema=requestedSchema,
                    ),
                )
            ),
            types.ElicitResult,
            metadata=ServerMessageMetadata(related_request_id=related_request_id),
        )

    async def send_ping(self) -> types.EmptyResult:
        """Send a ping request."""
        return await self.send_request(
            types.ServerRequest(
                types.PingRequest(
                    method="ping",
                )
            ),
            types.EmptyResult,
        )

    async def send_progress_notification(
        self,
        progress_token: str | int,
        progress: float,
        total: float | None = None,
        message: str | None = None,
        related_request_id: str | None = None,
    ) -> None:
        """Send a progress notification."""
        await self.send_notification(
            types.ServerNotification(
                types.ProgressNotification(
                    method="notifications/progress",
                    params=types.ProgressNotificationParams(
                        progressToken=progress_token,
                        progress=progress,
                        total=total,
                        message=message,
                    ),
                )
            ),
            related_request_id,
        )

    async def send_resource_list_changed(self) -> None:
        """Send a resource list changed notification."""
        await self.send_notification(
            types.ServerNotification(
                types.ResourceListChangedNotification(
                    method="notifications/resources/list_changed",
                )
            )
        )

    async def send_tool_list_changed(self) -> None:
        """Send a tool list changed notification."""
        await self.send_notification(
            types.ServerNotification(
                types.ToolListChangedNotification(
                    method="notifications/tools/list_changed",
                )
            )
        )

    async def send_prompt_list_changed(self) -> None:
        """Send a prompt list changed notification."""
        await self.send_notification(
            types.ServerNotification(
                types.PromptListChangedNotification(
                    method="notifications/prompts/list_changed",
                )
            )
        )

    async def _handle_incoming(self, req: ServerRequestResponder) -> None:
        await self._incoming_message_stream_writer.send(req)

    @property
    def incoming_messages(
        self,
    ) -> MemoryObjectReceiveStream[ServerRequestResponder]:
        return self._incoming_message_stream_reader

## SseServerTransport

**Type**: Class

**Description**: class SseServerTransport:
    """
    SSE server transport for MCP. This class provides _two_ ASGI applications,
    suitable to be used with a framework like Starlette and a server like Hypercorn:

        1. connect_sse() is an ASGI application which receives incoming GET requests,
           and sets up a new SSE stream to send server messages to the client.
        2. handle_post_message() is an ASGI application which receives incoming POST
           requests, which should contain client messages that link to a
           previously-established SSE session.
    """

    _endpoint: str
    _read_stream_writers: dict[UUID, MemoryObjectSendStream[SessionMessage | Exception]]
    _security: TransportSecurityMiddleware

    def __init__(self, endpoint: str, security_settings: TransportSecuritySettings | None = None) -> None:
        """
        Creates a new SSE server transport, which will direct the client to POST
        messages to the relative or absolute URL given.

        Args:
            endpoint: The relative or absolute URL for POST messages.
            security_settings: Optional security settings for DNS rebinding protection.
        """

        super().__init__()
        self._endpoint = endpoint
        self._read_stream_writers = {}
        self._security = TransportSecurityMiddleware(security_settings)
        logger.debug(f"SseServerTransport initialized with endpoint: {endpoint}")

    @asynccontextmanager
    async def connect_sse(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            logger.error("connect_sse received non-HTTP request")
            raise ValueError("connect_sse can only handle HTTP requests")

        # Validate request headers for DNS rebinding protection
        request = Request(scope, receive)
        error_response = await self._security.validate_request(request, is_post=False)
        if error_response:
            await error_response(scope, receive, send)
            raise ValueError("Request validation failed")

        logger.debug("Setting up SSE connection")
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception]
        read_stream_writer: MemoryObjectSendStream[SessionMessage | Exception]

        write_stream: MemoryObjectSendStream[SessionMessage]
        write_stream_reader: MemoryObjectReceiveStream[SessionMessage]

        read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

        session_id = uuid4()
        self._read_stream_writers[session_id] = read_stream_writer
        logger.debug(f"Created new session with ID: {session_id}")

        # Determine the full path for the message endpoint to be sent to the client.
        # scope['root_path'] is the prefix where the current Starlette app
        # instance is mounted.
        # e.g., "" if top-level, or "/api_prefix" if mounted under "/api_prefix".
        root_path = scope.get("root_path", "")

        # self._endpoint is the path *within* this app, e.g., "/messages".
        # Concatenating them gives the full absolute path from the server root.
        # e.g., "" + "/messages" -> "/messages"
        # e.g., "/api_prefix" + "/messages" -> "/api_prefix/messages"
        full_message_path_for_client = root_path.rstrip("/") + self._endpoint

        # This is the URI (path + query) the client will use to POST messages.
        client_post_uri_data = f"{quote(full_message_path_for_client)}?session_id={session_id.hex}"

        sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[dict[str, Any]](0)

        async def sse_writer():
            logger.debug("Starting SSE writer")
            async with sse_stream_writer, write_stream_reader:
                await sse_stream_writer.send({"event": "endpoint", "data": client_post_uri_data})
                logger.debug(f"Sent endpoint event: {client_post_uri_data}")

                async for session_message in write_stream_reader:
                    logger.debug(f"Sending message via SSE: {session_message}")
                    await sse_stream_writer.send(
                        {
                            "event": "message",
                            "data": session_message.message.model_dump_json(by_alias=True, exclude_none=True),
                        }
                    )

        async with anyio.create_task_group() as tg:

            async def response_wrapper(scope: Scope, receive: Receive, send: Send):
                """
                The EventSourceResponse returning signals a client close / disconnect.
                In this case we close our side of the streams to signal the client that
                the connection has been closed.
                """
                await EventSourceResponse(content=sse_stream_reader, data_sender_callable=sse_writer)(
                    scope, receive, send
                )
                await read_stream_writer.aclose()
                await write_stream_reader.aclose()
                logging.debug(f"Client session disconnected {session_id}")

            logger.debug("Starting SSE response task")
            tg.start_soon(response_wrapper, scope, receive, send)

            logger.debug("Yielding read and write streams")
            yield (read_stream, write_stream)

    async def handle_post_message(self, scope: Scope, receive: Receive, send: Send) -> None:
        logger.debug("Handling POST message")
        request = Request(scope, receive)

        # Validate request headers for DNS rebinding protection
        error_response = await self._security.validate_request(request, is_post=True)
        if error_response:
            return await error_response(scope, receive, send)

        session_id_param = request.query_params.get("session_id")
        if session_id_param is None:
            logger.warning("Received request without session_id")
            response = Response("session_id is required", status_code=400)
            return await response(scope, receive, send)

        try:
            session_id = UUID(hex=session_id_param)
            logger.debug(f"Parsed session ID: {session_id}")
        except ValueError:
            logger.warning(f"Received invalid session ID: {session_id_param}")
            response = Response("Invalid session ID", status_code=400)
            return await response(scope, receive, send)

        writer = self._read_stream_writers.get(session_id)
        if not writer:
            logger.warning(f"Could not find session for ID: {session_id}")
            response = Response("Could not find session", status_code=404)
            return await response(scope, receive, send)

        body = await request.body()
        logger.debug(f"Received JSON: {body}")

        try:
            message = types.JSONRPCMessage.model_validate_json(body)
            logger.debug(f"Validated client message: {message}")
        except ValidationError as err:
            logger.error(f"Failed to parse message: {err}")
            response = Response("Could not parse message", status_code=400)
            await response(scope, receive, send)
            await writer.send(err)
            return

        # Pass the ASGI scope for framework-agnostic access to request data
        metadata = ServerMessageMetadata(request_context=request)
        session_message = SessionMessage(message, metadata=metadata)
        logger.debug(f"Sending session message to writer: {session_message}")
        response = Response("Accepted", status_code=202)
        await response(scope, receive, send)
        await writer.send(session_message)

## EventStore

**Type**: Class

**Description**: class EventStore(ABC):
    """
    Interface for resumability support via event storage.
    """

    @abstractmethod
    async def store_event(self, stream_id: StreamId, message: JSONRPCMessage) -> EventId:
        """
        Stores an event for later retrieval.

        Args:
            stream_id: ID of the stream the event belongs to
            message: The JSON-RPC message to store

        Returns:
            The generated event ID for the stored event
        """
        pass

    @abstractmethod
    async def replay_events_after(
        self,
        last_event_id: EventId,
        send_callback: EventCallback,
    ) -> StreamId | None:
        """
        Replays events that occurred after the specified event ID.

        Args:
            last_event_id: The ID of the last event the client received
            send_callback: A callback function to send events to the client

        Returns:
            The stream ID of the replayed events
        """
        pass

## StreamableHTTPServerTransport

**Type**: Class

**Description**: class StreamableHTTPServerTransport:
    """
    HTTP server transport with event streaming support for MCP.

    Handles JSON-RPC messages in HTTP POST requests with SSE streaming.
    Supports optional JSON responses and session management.
    """

    # Server notification streams for POST requests as well as standalone SSE stream
    _read_stream_writer: MemoryObjectSendStream[SessionMessage | Exception] | None = None
    _read_stream: MemoryObjectReceiveStream[SessionMessage | Exception] | None = None
    _write_stream: MemoryObjectSendStream[SessionMessage] | None = None
    _write_stream_reader: MemoryObjectReceiveStream[SessionMessage] | None = None
    _security: TransportSecurityMiddleware

    def __init__(
        self,
        mcp_session_id: str | None,
        is_json_response_enabled: bool = False,
        event_store: EventStore | None = None,
        security_settings: TransportSecuritySettings | None = None,
    ) -> None:
        """
        Initialize a new StreamableHTTP server transport.

        Args:
            mcp_session_id: Optional session identifier for this connection.
                            Must contain only visible ASCII characters (0x21-0x7E).
            is_json_response_enabled: If True, return JSON responses for requests
                                    instead of SSE streams. Default is False.
            event_store: Event store for resumability support. If provided,
                        resumability will be enabled, allowing clients to
                        reconnect and resume messages.
            security_settings: Optional security settings for DNS rebinding protection.

        Raises:
            ValueError: If the session ID contains invalid characters.
        """
        if mcp_session_id is not None and not SESSION_ID_PATTERN.fullmatch(mcp_session_id):
            raise ValueError("Session ID must only contain visible ASCII characters (0x21-0x7E)")

        self.mcp_session_id = mcp_session_id
        self.is_json_response_enabled = is_json_response_enabled
        self._event_store = event_store
        self._security = TransportSecurityMiddleware(security_settings)
        self._request_streams: dict[
            RequestId,
            tuple[
                MemoryObjectSendStream[EventMessage],
                MemoryObjectReceiveStream[EventMessage],
            ],
        ] = {}
        self._terminated = False

    def _create_error_response(
        self,
        error_message: str,
        status_code: HTTPStatus,
        error_code: int = INVALID_REQUEST,
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Create an error response with a simple string message."""
        response_headers = {"Content-Type": CONTENT_TYPE_JSON}
        if headers:
            response_headers.update(headers)

        if self.mcp_session_id:
            response_headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        # Return a properly formatted JSON error response
        error_response = JSONRPCError(
            jsonrpc="2.0",
            id="server-error",  # We don't have a request ID for general errors
            error=ErrorData(
                code=error_code,
                message=error_message,
            ),
        )

        return Response(
            error_response.model_dump_json(by_alias=True, exclude_none=True),
            status_code=status_code,
            headers=response_headers,
        )

    def _create_json_response(
        self,
        response_message: JSONRPCMessage | None,
        status_code: HTTPStatus = HTTPStatus.OK,
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Create a JSON response from a JSONRPCMessage"""
        response_headers = {"Content-Type": CONTENT_TYPE_JSON}
        if headers:
            response_headers.update(headers)

        if self.mcp_session_id:
            response_headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        return Response(
            response_message.model_dump_json(by_alias=True, exclude_none=True) if response_message else None,
            status_code=status_code,
            headers=response_headers,
        )

    def _get_session_id(self, request: Request) -> str | None:
        """Extract the session ID from request headers."""
        return request.headers.get(MCP_SESSION_ID_HEADER)

    def _create_event_data(self, event_message: EventMessage) -> dict[str, str]:
        """Create event data dictionary from an EventMessage."""
        event_data = {
            "event": "message",
            "data": event_message.message.model_dump_json(by_alias=True, exclude_none=True),
        }

        # If an event ID was provided, include it
        if event_message.event_id:
            event_data["id"] = event_message.event_id

        return event_data

    async def _clean_up_memory_streams(self, request_id: RequestId) -> None:
        """Clean up memory streams for a given request ID."""
        if request_id in self._request_streams:
            try:
                # Close the request stream
                await self._request_streams[request_id][0].aclose()
                await self._request_streams[request_id][1].aclose()
            except Exception as e:
                logger.debug(f"Error closing memory streams: {e}")
            finally:
                # Remove the request stream from the mapping
                self._request_streams.pop(request_id, None)

    async def handle_request(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Application entry point that handles all HTTP requests"""
        request = Request(scope, receive)

        # Validate request headers for DNS rebinding protection
        is_post = request.method == "POST"
        error_response = await self._security.validate_request(request, is_post=is_post)
        if error_response:
            await error_response(scope, receive, send)
            return

        if self._terminated:
            # If the session has been terminated, return 404 Not Found
            response = self._create_error_response(
                "Not Found: Session has been terminated",
                HTTPStatus.NOT_FOUND,
            )
            await response(scope, receive, send)
            return

        if request.method == "POST":
            await self._handle_post_request(scope, request, receive, send)
        elif request.method == "GET":
            await self._handle_get_request(request, send)
        elif request.method == "DELETE":
            await self._handle_delete_request(request, send)
        else:
            await self._handle_unsupported_request(request, send)

    def _check_accept_headers(self, request: Request) -> tuple[bool, bool]:
        """Check if the request accepts the required media types."""
        accept_header = request.headers.get("accept", "")
        accept_types = [media_type.strip() for media_type in accept_header.split(",")]

        has_json = any(media_type.startswith(CONTENT_TYPE_JSON) for media_type in accept_types)
        has_sse = any(media_type.startswith(CONTENT_TYPE_SSE) for media_type in accept_types)

        return has_json, has_sse

    def _check_content_type(self, request: Request) -> bool:
        """Check if the request has the correct Content-Type."""
        content_type = request.headers.get("content-type", "")
        content_type_parts = [part.strip() for part in content_type.split(";")[0].split(",")]

        return any(part == CONTENT_TYPE_JSON for part in content_type_parts)

    async def _handle_post_request(self, scope: Scope, request: Request, receive: Receive, send: Send) -> None:
        """Handle POST requests containing JSON-RPC messages."""
        writer = self._read_stream_writer
        if writer is None:
            raise ValueError("No read stream writer available. Ensure connect() is called first.")
        try:
            # Check Accept headers
            has_json, has_sse = self._check_accept_headers(request)
            if not (has_json and has_sse):
                response = self._create_error_response(
                    ("Not Acceptable: Client must accept both application/json and text/event-stream"),
                    HTTPStatus.NOT_ACCEPTABLE,
                )
                await response(scope, receive, send)
                return

            # Validate Content-Type
            if not self._check_content_type(request):
                response = self._create_error_response(
                    "Unsupported Media Type: Content-Type must be application/json",
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                )
                await response(scope, receive, send)
                return

            # Parse the body - only read it once
            body = await request.body()
            if len(body) > MAXIMUM_MESSAGE_SIZE:
                response = self._create_error_response(
                    "Payload Too Large: Message exceeds maximum size",
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
                await response(scope, receive, send)
                return

            try:
                raw_message = json.loads(body)
            except json.JSONDecodeError as e:
                response = self._create_error_response(f"Parse error: {str(e)}", HTTPStatus.BAD_REQUEST, PARSE_ERROR)
                await response(scope, receive, send)
                return

            try:
                message = JSONRPCMessage.model_validate(raw_message)
            except ValidationError as e:
                response = self._create_error_response(
                    f"Validation error: {str(e)}",
                    HTTPStatus.BAD_REQUEST,
                    INVALID_PARAMS,
                )
                await response(scope, receive, send)
                return

            # Check if this is an initialization request
            is_initialization_request = isinstance(message.root, JSONRPCRequest) and message.root.method == "initialize"

            if is_initialization_request:
                # Check if the server already has an established session
                if self.mcp_session_id:
                    # Check if request has a session ID
                    request_session_id = self._get_session_id(request)

                    # If request has a session ID but doesn't match, return 404
                    if request_session_id and request_session_id != self.mcp_session_id:
                        response = self._create_error_response(
                            "Not Found: Invalid or expired session ID",
                            HTTPStatus.NOT_FOUND,
                        )
                        await response(scope, receive, send)
                        return
            elif not await self._validate_request_headers(request, send):
                return

            # For notifications and responses only, return 202 Accepted
            if not isinstance(message.root, JSONRPCRequest):
                # Create response object and send it
                response = self._create_json_response(
                    None,
                    HTTPStatus.ACCEPTED,
                )
                await response(scope, receive, send)

                # Process the message after sending the response
                metadata = ServerMessageMetadata(request_context=request)
                session_message = SessionMessage(message, metadata=metadata)
                await writer.send(session_message)

                return

            # Extract the request ID outside the try block for proper scope
            request_id = str(message.root.id)
            # Register this stream for the request ID
            self._request_streams[request_id] = anyio.create_memory_object_stream[EventMessage](0)
            request_stream_reader = self._request_streams[request_id][1]

            if self.is_json_response_enabled:
                # Process the message
                metadata = ServerMessageMetadata(request_context=request)
                session_message = SessionMessage(message, metadata=metadata)
                await writer.send(session_message)
                try:
                    # Process messages from the request-specific stream
                    # We need to collect all messages until we get a response
                    response_message = None

                    # Use similar approach to SSE writer for consistency
                    async for event_message in request_stream_reader:
                        # If it's a response, this is what we're waiting for
                        if isinstance(event_message.message.root, JSONRPCResponse | JSONRPCError):
                            response_message = event_message.message
                            break
                        # For notifications and request, keep waiting
                        else:
                            logger.debug(f"received: {event_message.message.root.method}")

                    # At this point we should have a response
                    if response_message:
                        # Create JSON response
                        response = self._create_json_response(response_message)
                        await response(scope, receive, send)
                    else:
                        # This shouldn't happen in normal operation
                        logger.error("No response message received before stream closed")
                        response = self._create_error_response(
                            "Error processing request: No response received",
                            HTTPStatus.INTERNAL_SERVER_ERROR,
                        )
                        await response(scope, receive, send)
                except Exception as e:
                    logger.exception(f"Error processing JSON response: {e}")
                    response = self._create_error_response(
                        f"Error processing request: {str(e)}",
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        INTERNAL_ERROR,
                    )
                    await response(scope, receive, send)
                finally:
                    await self._clean_up_memory_streams(request_id)
            else:
                # Create SSE stream
                sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[dict[str, str]](0)

                async def sse_writer():
                    # Get the request ID from the incoming request message
                    try:
                        async with sse_stream_writer, request_stream_reader:
                            # Process messages from the request-specific stream
                            async for event_message in request_stream_reader:
                                # Build the event data
                                event_data = self._create_event_data(event_message)
                                await sse_stream_writer.send(event_data)

                                # If response, remove from pending streams and close
                                if isinstance(
                                    event_message.message.root,
                                    JSONRPCResponse | JSONRPCError,
                                ):
                                    break
                    except Exception as e:
                        logger.exception(f"Error in SSE writer: {e}")
                    finally:
                        logger.debug("Closing SSE writer")
                        await self._clean_up_memory_streams(request_id)

                # Create and start EventSourceResponse
                # SSE stream mode (original behavior)
                # Set up headers
                headers = {
                    "Cache-Control": "no-cache, no-transform",
                    "Connection": "keep-alive",
                    "Content-Type": CONTENT_TYPE_SSE,
                    **({MCP_SESSION_ID_HEADER: self.mcp_session_id} if self.mcp_session_id else {}),
                }
                response = EventSourceResponse(
                    content=sse_stream_reader,
                    data_sender_callable=sse_writer,
                    headers=headers,
                )

                # Start the SSE response (this will send headers immediately)
                try:
                    # First send the response to establish the SSE connection
                    async with anyio.create_task_group() as tg:
                        tg.start_soon(response, scope, receive, send)
                        # Then send the message to be processed by the server
                        metadata = ServerMessageMetadata(request_context=request)
                        session_message = SessionMessage(message, metadata=metadata)
                        await writer.send(session_message)
                except Exception:
                    logger.exception("SSE response error")
                    await sse_stream_writer.aclose()
                    await sse_stream_reader.aclose()
                    await self._clean_up_memory_streams(request_id)

        except Exception as err:
            logger.exception("Error handling POST request")
            response = self._create_error_response(
                f"Error handling POST request: {err}",
                HTTPStatus.INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
            )
            await response(scope, receive, send)
            if writer:
                await writer.send(Exception(err))
            return

    async def _handle_get_request(self, request: Request, send: Send) -> None:
        """
        Handle GET request to establish SSE.

        This allows the server to communicate to the client without the client
        first sending data via HTTP POST. The server can send JSON-RPC requests
        and notifications on this stream.
        """
        writer = self._read_stream_writer
        if writer is None:
            raise ValueError("No read stream writer available. Ensure connect() is called first.")

        # Validate Accept header - must include text/event-stream
        _, has_sse = self._check_accept_headers(request)

        if not has_sse:
            response = self._create_error_response(
                "Not Acceptable: Client must accept text/event-stream",
                HTTPStatus.NOT_ACCEPTABLE,
            )
            await response(request.scope, request.receive, send)
            return

        if not await self._validate_request_headers(request, send):
            return

        # Handle resumability: check for Last-Event-ID header
        if last_event_id := request.headers.get(LAST_EVENT_ID_HEADER):
            await self._replay_events(last_event_id, request, send)
            return

        headers = {
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "Content-Type": CONTENT_TYPE_SSE,
        }

        if self.mcp_session_id:
            headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        # Check if we already have an active GET stream
        if GET_STREAM_KEY in self._request_streams:
            response = self._create_error_response(
                "Conflict: Only one SSE stream is allowed per session",
                HTTPStatus.CONFLICT,
            )
            await response(request.scope, request.receive, send)
            return

        # Create SSE stream
        sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[dict[str, str]](0)

        async def standalone_sse_writer():
            try:
                # Create a standalone message stream for server-initiated messages

                self._request_streams[GET_STREAM_KEY] = anyio.create_memory_object_stream[EventMessage](0)
                standalone_stream_reader = self._request_streams[GET_STREAM_KEY][1]

                async with sse_stream_writer, standalone_stream_reader:
                    # Process messages from the standalone stream
                    async for event_message in standalone_stream_reader:
                        # For the standalone stream, we handle:
                        # - JSONRPCNotification (server sends notifications to client)
                        # - JSONRPCRequest (server sends requests to client)
                        # We should NOT receive JSONRPCResponse

                        # Send the message via SSE
                        event_data = self._create_event_data(event_message)
                        await sse_stream_writer.send(event_data)
            except Exception as e:
                logger.exception(f"Error in standalone SSE writer: {e}")
            finally:
                logger.debug("Closing standalone SSE writer")
                await self._clean_up_memory_streams(GET_STREAM_KEY)

        # Create and start EventSourceResponse
        response = EventSourceResponse(
            content=sse_stream_reader,
            data_sender_callable=standalone_sse_writer,
            headers=headers,
        )

        try:
            # This will send headers immediately and establish the SSE connection
            await response(request.scope, request.receive, send)
        except Exception as e:
            logger.exception(f"Error in standalone SSE response: {e}")
            await sse_stream_writer.aclose()
            await sse_stream_reader.aclose()
            await self._clean_up_memory_streams(GET_STREAM_KEY)

    async def _handle_delete_request(self, request: Request, send: Send) -> None:
        """Handle DELETE requests for explicit session termination."""
        # Validate session ID
        if not self.mcp_session_id:
            # If no session ID set, return Method Not Allowed
            response = self._create_error_response(
                "Method Not Allowed: Session termination not supported",
                HTTPStatus.METHOD_NOT_ALLOWED,
            )
            await response(request.scope, request.receive, send)
            return

        if not await self._validate_request_headers(request, send):
            return

        await self._terminate_session()

        response = self._create_json_response(
            None,
            HTTPStatus.OK,
        )
        await response(request.scope, request.receive, send)

    async def _terminate_session(self) -> None:
        """Terminate the current session, closing all streams.

        Once terminated, all requests with this session ID will receive 404 Not Found.
        """

        self._terminated = True
        logger.info(f"Terminating session: {self.mcp_session_id}")

        # We need a copy of the keys to avoid modification during iteration
        request_stream_keys = list(self._request_streams.keys())

        # Close all request streams asynchronously
        for key in request_stream_keys:
            try:
                await self._clean_up_memory_streams(key)
            except Exception as e:
                logger.debug(f"Error closing stream {key} during termination: {e}")

        # Clear the request streams dictionary immediately
        self._request_streams.clear()
        try:
            if self._read_stream_writer is not None:
                await self._read_stream_writer.aclose()
            if self._read_stream is not None:
                await self._read_stream.aclose()
            if self._write_stream_reader is not None:
                await self._write_stream_reader.aclose()
            if self._write_stream is not None:
                await self._write_stream.aclose()
        except Exception as e:
            logger.debug(f"Error closing streams: {e}")

    async def _handle_unsupported_request(self, request: Request, send: Send) -> None:
        """Handle unsupported HTTP methods."""
        headers = {
            "Content-Type": CONTENT_TYPE_JSON,
            "Allow": "GET, POST, DELETE",
        }
        if self.mcp_session_id:
            headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

        response = self._create_error_response(
            "Method Not Allowed",
            HTTPStatus.METHOD_NOT_ALLOWED,
            headers=headers,
        )
        await response(request.scope, request.receive, send)

    async def _validate_request_headers(self, request: Request, send: Send) -> bool:
        if not await self._validate_session(request, send):
            return False
        if not await self._validate_protocol_version(request, send):
            return False
        return True

    async def _validate_session(self, request: Request, send: Send) -> bool:
        """Validate the session ID in the request."""
        if not self.mcp_session_id:
            # If we're not using session IDs, return True
            return True

        # Get the session ID from the request headers
        request_session_id = self._get_session_id(request)

        # If no session ID provided but required, return error
        if not request_session_id:
            response = self._create_error_response(
                "Bad Request: Missing session ID",
                HTTPStatus.BAD_REQUEST,
            )
            await response(request.scope, request.receive, send)
            return False

        # If session ID doesn't match, return error
        if request_session_id != self.mcp_session_id:
            response = self._create_error_response(
                "Not Found: Invalid or expired session ID",
                HTTPStatus.NOT_FOUND,
            )
            await response(request.scope, request.receive, send)
            return False

        return True

    async def _validate_protocol_version(self, request: Request, send: Send) -> bool:
        """Validate the protocol version header in the request."""
        # Get the protocol version from the request headers
        protocol_version = request.headers.get(MCP_PROTOCOL_VERSION_HEADER)

        # If no protocol version provided, assume default version
        if protocol_version is None:
            protocol_version = DEFAULT_NEGOTIATED_VERSION

        # Check if the protocol version is supported
        if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            supported_versions = ", ".join(SUPPORTED_PROTOCOL_VERSIONS)
            response = self._create_error_response(
                f"Bad Request: Unsupported protocol version: {protocol_version}. "
                + f"Supported versions: {supported_versions}",
                HTTPStatus.BAD_REQUEST,
            )
            await response(request.scope, request.receive, send)
            return False

        return True

    async def _replay_events(self, last_event_id: str, request: Request, send: Send) -> None:
        """
        Replays events that would have been sent after the specified event ID.
        Only used when resumability is enabled.
        """
        event_store = self._event_store
        if not event_store:
            return

        try:
            headers = {
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                "Content-Type": CONTENT_TYPE_SSE,
            }

            if self.mcp_session_id:
                headers[MCP_SESSION_ID_HEADER] = self.mcp_session_id

            # Create SSE stream for replay
            sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[dict[str, str]](0)

            async def replay_sender():
                try:
                    async with sse_stream_writer:
                        # Define an async callback for sending events
                        async def send_event(event_message: EventMessage) -> None:
                            event_data = self._create_event_data(event_message)
                            await sse_stream_writer.send(event_data)

                        # Replay past events and get the stream ID
                        stream_id = await event_store.replay_events_after(last_event_id, send_event)

                        # If stream ID not in mapping, create it
                        if stream_id and stream_id not in self._request_streams:
                            self._request_streams[stream_id] = anyio.create_memory_object_stream[EventMessage](0)
                            msg_reader = self._request_streams[stream_id][1]

                            # Forward messages to SSE
                            async with msg_reader:
                                async for event_message in msg_reader:
                                    event_data = self._create_event_data(event_message)

                                    await sse_stream_writer.send(event_data)
                except Exception as e:
                    logger.exception(f"Error in replay sender: {e}")

            # Create and start EventSourceResponse
            response = EventSourceResponse(
                content=sse_stream_reader,
                data_sender_callable=replay_sender,
                headers=headers,
            )

            try:
                await response(request.scope, request.receive, send)
            except Exception as e:
                logger.exception(f"Error in replay response: {e}")
            finally:
                await sse_stream_writer.aclose()
                await sse_stream_reader.aclose()

        except Exception as e:
            logger.exception(f"Error replaying events: {e}")
            response = self._create_error_response(
                f"Error replaying events: {str(e)}",
                HTTPStatus.INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR,
            )
            await response(request.scope, request.receive, send)

    @asynccontextmanager
    async def connect(
        self,
    ) -> AsyncGenerator[
        tuple[
            MemoryObjectReceiveStream[SessionMessage | Exception],
            MemoryObjectSendStream[SessionMessage],
        ],
        None,
    ]:
        """Context manager that provides read and write streams for a connection.

        Yields:
            Tuple of (read_stream, write_stream) for bidirectional communication
        """

        # Create the memory streams for this connection

        read_stream_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream[SessionMessage](0)

        # Store the streams
        self._read_stream_writer = read_stream_writer
        self._read_stream = read_stream
        self._write_stream_reader = write_stream_reader
        self._write_stream = write_stream

        # Start a task group for message routing
        async with anyio.create_task_group() as tg:
            # Create a message router that distributes messages to request streams
            async def message_router():
                try:
                    async for session_message in write_stream_reader:
                        # Determine which request stream(s) should receive this message
                        message = session_message.message
                        target_request_id = None
                        # Check if this is a response
                        if isinstance(message.root, JSONRPCResponse | JSONRPCError):
                            response_id = str(message.root.id)
                            # If this response is for an existing request stream,
                            # send it there
                            if response_id in self._request_streams:
                                target_request_id = response_id

                        else:
                            # Extract related_request_id from meta if it exists
                            if (
                                session_message.metadata is not None
                                and isinstance(
                                    session_message.metadata,
                                    ServerMessageMetadata,
                                )
                                and session_message.metadata.related_request_id is not None
                            ):
                                target_request_id = str(session_message.metadata.related_request_id)

                        request_stream_id = target_request_id if target_request_id is not None else GET_STREAM_KEY

                        # Store the event if we have an event store,
                        # regardless of whether a client is connected
                        # messages will be replayed on the re-connect
                        event_id = None
                        if self._event_store:
                            event_id = await self._event_store.store_event(request_stream_id, message)
                            logger.debug(f"Stored {event_id} from {request_stream_id}")

                        if request_stream_id in self._request_streams:
                            try:
                                # Send both the message and the event ID
                                await self._request_streams[request_stream_id][0].send(EventMessage(message, event_id))
                            except (
                                anyio.BrokenResourceError,
                                anyio.ClosedResourceError,
                            ):
                                # Stream might be closed, remove from registry
                                self._request_streams.pop(request_stream_id, None)
                        else:
                            logging.debug(
                                f"""Request stream {request_stream_id} not found 
                                for message. Still processing message as the client
                                might reconnect and replay."""
                            )
                except Exception as e:
                    logger.exception(f"Error in message router: {e}")

            # Start the message router
            tg.start_soon(message_router)

            try:
                # Yield the streams for the caller to use
                yield read_stream, write_stream
            finally:
                for stream_id in list(self._request_streams.keys()):
                    try:
                        await self._clean_up_memory_streams(stream_id)
                    except Exception as e:
                        logger.debug(f"Error closing request stream: {e}")
                        pass
                self._request_streams.clear()

                # Clean up the read and write streams
                try:
                    await read_stream_writer.aclose()
                    await read_stream.aclose()
                    await write_stream_reader.aclose()
                    await write_stream.aclose()
                except Exception as e:
                    logger.debug(f"Error closing streams: {e}")

## StreamableHTTPSessionManager

**Type**: Class

**Description**: class StreamableHTTPSessionManager:
    """
    Manages StreamableHTTP sessions with optional resumability via event store.

    This class abstracts away the complexity of session management, event storage,
    and request handling for StreamableHTTP transports. It handles:

    1. Session tracking for clients
    2. Resumability via an optional event store
    3. Connection management and lifecycle
    4. Request handling and transport setup

    Important: Only one StreamableHTTPSessionManager instance should be created
    per application. The instance cannot be reused after its run() context has
    completed. If you need to restart the manager, create a new instance.

    Args:
        app: The MCP server instance
        event_store: Optional event store for resumability support.
                     If provided, enables resumable connections where clients
                     can reconnect and receive missed events.
                     If None, sessions are still tracked but not resumable.
        json_response: Whether to use JSON responses instead of SSE streams
        stateless: If True, creates a completely fresh transport for each request
                   with no session tracking or state persistence between requests.

    """

    def __init__(
        self,
        app: MCPServer[Any, Any],
        event_store: EventStore | None = None,
        json_response: bool = False,
        stateless: bool = False,
        security_settings: TransportSecuritySettings | None = None,
    ):
        self.app = app
        self.event_store = event_store
        self.json_response = json_response
        self.stateless = stateless
        self.security_settings = security_settings

        # Session tracking (only used if not stateless)
        self._session_creation_lock = anyio.Lock()
        self._server_instances: dict[str, StreamableHTTPServerTransport] = {}

        # The task group will be set during lifespan
        self._task_group = None
        # Thread-safe tracking of run() calls
        self._run_lock = threading.Lock()
        self._has_started = False

    @contextlib.asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        """
        Run the session manager with proper lifecycle management.

        This creates and manages the task group for all session operations.

        Important: This method can only be called once per instance. The same
        StreamableHTTPSessionManager instance cannot be reused after this
        context manager exits. Create a new instance if you need to restart.

        Use this in the lifespan context manager of your Starlette app:

        @contextlib.asynccontextmanager
        async def lifespan(app: Starlette) -> AsyncIterator[None]:
            async with session_manager.run():
                yield
        """
        # Thread-safe check to ensure run() is only called once
        with self._run_lock:
            if self._has_started:
                raise RuntimeError(
                    "StreamableHTTPSessionManager .run() can only be called "
                    "once per instance. Create a new instance if you need to run again."
                )
            self._has_started = True

        async with anyio.create_task_group() as tg:
            # Store the task group for later use
            self._task_group = tg
            logger.info("StreamableHTTP session manager started")
            try:
                yield  # Let the application run
            finally:
                logger.info("StreamableHTTP session manager shutting down")
                # Cancel task group to stop all spawned tasks
                tg.cancel_scope.cancel()
                self._task_group = None
                # Clear any remaining server instances
                self._server_instances.clear()

    async def handle_request(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """
        Process ASGI request with proper session handling and transport setup.

        Dispatches to the appropriate handler based on stateless mode.

        Args:
            scope: ASGI scope
            receive: ASGI receive function
            send: ASGI send function
        """
        if self._task_group is None:
            raise RuntimeError("Task group is not initialized. Make sure to use run().")

        # Dispatch to the appropriate handler
        if self.stateless:
            await self._handle_stateless_request(scope, receive, send)
        else:
            await self._handle_stateful_request(scope, receive, send)

    async def _handle_stateless_request(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """
        Process request in stateless mode - creating a new transport for each request.

        Args:
            scope: ASGI scope
            receive: ASGI receive function
            send: ASGI send function
        """
        logger.debug("Stateless mode: Creating new transport for this request")
        # No session ID needed in stateless mode
        http_transport = StreamableHTTPServerTransport(
            mcp_session_id=None,  # No session tracking in stateless mode
            is_json_response_enabled=self.json_response,
            event_store=None,  # No event store in stateless mode
            security_settings=self.security_settings,
        )

        # Start server in a new task
        async def run_stateless_server(*, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED):
            async with http_transport.connect() as streams:
                read_stream, write_stream = streams
                task_status.started()
                await self.app.run(
                    read_stream,
                    write_stream,
                    self.app.create_initialization_options(),
                    stateless=True,
                )

        # Assert task group is not None for type checking
        assert self._task_group is not None
        # Start the server task
        await self._task_group.start(run_stateless_server)

        # Handle the HTTP request and return the response
        await http_transport.handle_request(scope, receive, send)

    async def _handle_stateful_request(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """
        Process request in stateful mode - maintaining session state between requests.

        Args:
            scope: ASGI scope
            receive: ASGI receive function
            send: ASGI send function
        """
        request = Request(scope, receive)
        request_mcp_session_id = request.headers.get(MCP_SESSION_ID_HEADER)

        # Existing session case
        if request_mcp_session_id is not None and request_mcp_session_id in self._server_instances:
            transport = self._server_instances[request_mcp_session_id]
            logger.debug("Session already exists, handling request directly")
            await transport.handle_request(scope, receive, send)
            return

        if request_mcp_session_id is None:
            # New session case
            logger.debug("Creating new transport")
            async with self._session_creation_lock:
                new_session_id = uuid4().hex
                http_transport = StreamableHTTPServerTransport(
                    mcp_session_id=new_session_id,
                    is_json_response_enabled=self.json_response,
                    event_store=self.event_store,  # May be None (no resumability)
                    security_settings=self.security_settings,
                )

                assert http_transport.mcp_session_id is not None
                self._server_instances[http_transport.mcp_session_id] = http_transport
                logger.info(f"Created new transport with session ID: {new_session_id}")

                # Define the server runner
                async def run_server(*, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
                    async with http_transport.connect() as streams:
                        read_stream, write_stream = streams
                        task_status.started()
                        await self.app.run(
                            read_stream,
                            write_stream,
                            self.app.create_initialization_options(),
                            stateless=False,  # Stateful mode
                        )

                # Assert task group is not None for type checking
                assert self._task_group is not None
                # Start the server task
                await self._task_group.start(run_server)

                # Handle the HTTP request and return the response
                await http_transport.handle_request(scope, receive, send)
        else:
            # Invalid session ID
            response = Response(
                "Bad Request: No valid session ID provided",
                status_code=HTTPStatus.BAD_REQUEST,
            )
            await response(scope, receive, send)

## StreamingASGITransport

**Type**: Class

**Description**: class StreamingASGITransport(AsyncBaseTransport):
    """
    A custom AsyncTransport that handles sending requests directly to an ASGI app
    and supports streaming responses like SSE.

    Unlike the standard ASGITransport, this transport runs the ASGI app in a
    separate anyio task, allowing it to handle responses from apps that don't
    terminate immediately (like SSE endpoints).

    Arguments:

    * `app` - The ASGI application.
    * `raise_app_exceptions` - Boolean indicating if exceptions in the application
       should be raised. Default to `True`. Can be set to `False` for use cases
       such as testing the content of a client 500 response.
    * `root_path` - The root path on which the ASGI application should be mounted.
    * `client` - A two-tuple indicating the client IP and port of incoming requests.
    * `response_timeout` - Timeout in seconds to wait for the initial response.
       Default is 10 seconds.

    TODO: https://github.com/encode/httpx/pull/3059 is adding something similar to
    upstream httpx. When that merges, we should delete this & switch back to the
    upstream implementation.
    """

    def __init__(
        self,
        app: ASGIApp,
        task_group: anyio.abc.TaskGroup,
        raise_app_exceptions: bool = True,
        root_path: str = "",
        client: tuple[str, int] = ("127.0.0.1", 123),
    ) -> None:
        self.app = app
        self.raise_app_exceptions = raise_app_exceptions
        self.root_path = root_path
        self.client = client
        self.task_group = task_group

    async def handle_async_request(
        self,
        request: Request,
    ) -> Response:
        assert isinstance(request.stream, AsyncByteStream)

        # ASGI scope.
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": request.method,
            "headers": [(k.lower(), v) for (k, v) in request.headers.raw],
            "scheme": request.url.scheme,
            "path": request.url.path,
            "raw_path": request.url.raw_path.split(b"?")[0],
            "query_string": request.url.query,
            "server": (request.url.host, request.url.port),
            "client": self.client,
            "root_path": self.root_path,
        }

        # Request body
        request_body_chunks = request.stream.__aiter__()
        request_complete = False

        # Response state
        status_code = 499
        response_headers = None
        response_started = False
        response_complete = anyio.Event()
        initial_response_ready = anyio.Event()

        # Synchronization for streaming response
        asgi_send_channel, asgi_receive_channel = anyio.create_memory_object_stream[dict[str, Any]](100)
        content_send_channel, content_receive_channel = anyio.create_memory_object_stream[bytes](100)

        # ASGI callables.
        async def receive() -> dict[str, Any]:
            nonlocal request_complete

            if request_complete:
                await response_complete.wait()
                return {"type": "http.disconnect"}

            try:
                body = await request_body_chunks.__anext__()
            except StopAsyncIteration:
                request_complete = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.request", "body": body, "more_body": True}

        async def send(message: dict[str, Any]) -> None:
            nonlocal status_code, response_headers, response_started

            await asgi_send_channel.send(message)

        # Start the ASGI application in a separate task
        async def run_app() -> None:
            try:
                # Cast the receive and send functions to the ASGI types
                await self.app(cast(Scope, scope), cast(Receive, receive), cast(Send, send))
            except Exception:
                if self.raise_app_exceptions:
                    raise

                if not response_started:
                    await asgi_send_channel.send({"type": "http.response.start", "status": 500, "headers": []})

                await asgi_send_channel.send({"type": "http.response.body", "body": b"", "more_body": False})
            finally:
                await asgi_send_channel.aclose()

        # Process messages from the ASGI app
        async def process_messages() -> None:
            nonlocal status_code, response_headers, response_started

            try:
                async with asgi_receive_channel:
                    async for message in asgi_receive_channel:
                        if message["type"] == "http.response.start":
                            assert not response_started
                            status_code = message["status"]
                            response_headers = message.get("headers", [])
                            response_started = True

                            # As soon as we have headers, we can return a response
                            initial_response_ready.set()

                        elif message["type"] == "http.response.body":
                            body = message.get("body", b"")
                            more_body = message.get("more_body", False)

                            if body and request.method != "HEAD":
                                await content_send_channel.send(body)

                            if not more_body:
                                response_complete.set()
                                await content_send_channel.aclose()
                                break
            finally:
                # Ensure events are set even if there's an error
                initial_response_ready.set()
                response_complete.set()
                await content_send_channel.aclose()

        # Create tasks for running the app and processing messages
        self.task_group.start_soon(run_app)
        self.task_group.start_soon(process_messages)

        # Wait for the initial response or timeout
        await initial_response_ready.wait()

        # Create a streaming response
        return Response(
            status_code,
            headers=response_headers,
            stream=StreamingASGIResponseStream(content_receive_channel),
        )

## StreamingASGIResponseStream

**Type**: Class

**Description**: class StreamingASGIResponseStream(AsyncByteStream):
    """
    A modified ASGIResponseStream that supports streaming responses.

    This class extends the standard ASGIResponseStream to handle cases where
    the response body continues to be generated after the initial response
    is returned.
    """

    def __init__(
        self,
        receive_channel: anyio.streams.memory.MemoryObjectReceiveStream[bytes],
    ) -> None:
        self.receive_channel = receive_channel

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        try:
            async for chunk in self.receive_channel:
                yield chunk
        finally:
            await self.receive_channel.aclose()

## TransportSecuritySettings

**Type**: Class

**Description**: class TransportSecuritySettings(BaseModel):
    """Settings for MCP transport security features.

    These settings help protect against DNS rebinding attacks by validating
    incoming request headers.
    """

    enable_dns_rebinding_protection: bool = Field(
        default=True,
        description="Enable DNS rebinding protection (recommended for production)",
    )

    allowed_hosts: list[str] = Field(
        default=[],
        description="List of allowed Host header values. Only applies when "
        + "enable_dns_rebinding_protection is True.",
    )

    allowed_origins: list[str] = Field(
        default=[],
        description="List of allowed Origin header values. Only applies when "
        + "enable_dns_rebinding_protection is True.",
    )

## TransportSecurityMiddleware

**Type**: Class

**Description**: class TransportSecurityMiddleware:
    """Middleware to enforce DNS rebinding protection for MCP transport endpoints."""

    def __init__(self, settings: TransportSecuritySettings | None = None):
        # If not specified, disable DNS rebinding protection by default
        # for backwards compatibility
        self.settings = settings or TransportSecuritySettings(enable_dns_rebinding_protection=False)

    def _validate_host(self, host: str | None) -> bool:
        """Validate the Host header against allowed values."""
        if not host:
            logger.warning("Missing Host header in request")
            return False

        # Check exact match first
        if host in self.settings.allowed_hosts:
            return True

        # Check wildcard port patterns
        for allowed in self.settings.allowed_hosts:
            if allowed.endswith(":*"):
                # Extract base host from pattern
                base_host = allowed[:-2]
                # Check if the actual host starts with base host and has a port
                if host.startswith(base_host + ":"):
                    return True

        logger.warning(f"Invalid Host header: {host}")
        return False

    def _validate_origin(self, origin: str | None) -> bool:
        """Validate the Origin header against allowed values."""
        # Origin can be absent for same-origin requests
        if not origin:
            return True

        # Check exact match first
        if origin in self.settings.allowed_origins:
            return True

        # Check wildcard port patterns
        for allowed in self.settings.allowed_origins:
            if allowed.endswith(":*"):
                # Extract base origin from pattern
                base_origin = allowed[:-2]
                # Check if the actual origin starts with base origin and has a port
                if origin.startswith(base_origin + ":"):
                    return True

        logger.warning(f"Invalid Origin header: {origin}")
        return False

    def _validate_content_type(self, content_type: str | None) -> bool:
        """Validate the Content-Type header for POST requests."""
        if not content_type:
            logger.warning("Missing Content-Type header in POST request")
            return False

        # Content-Type must start with application/json
        if not content_type.lower().startswith("application/json"):
            logger.warning(f"Invalid Content-Type header: {content_type}")
            return False

        return True

    async def validate_request(self, request: Request, is_post: bool = False) -> Response | None:
        """Validate request headers for DNS rebinding protection.

        Returns None if validation passes, or an error Response if validation fails.
        """
        # Always validate Content-Type for POST requests
        if is_post:
            content_type = request.headers.get("content-type")
            if not self._validate_content_type(content_type):
                return Response("Invalid Content-Type header", status_code=400)

        # Skip remaining validation if DNS rebinding protection is disabled
        if not self.settings.enable_dns_rebinding_protection:
            return None

        # Validate Host header
        host = request.headers.get("host")
        if not self._validate_host(host):
            return Response("Invalid Host header", status_code=421)

        # Validate Origin header
        origin = request.headers.get("origin")
        if not self._validate_origin(origin):
            return Response("Invalid Origin header", status_code=400)

        return None

## receive_loop

**Type**: Function

**Description**: async def receive_loop(session: ServerSession):
    logger.info("Starting receive loop")
    async for message in session.incoming_messages:
        if isinstance(message, Exception):
            logger.error("Error: %s", message)
            continue

        logger.info("Received message from client: %s", message)

## main

**Type**: Function

**Description**: async def main():
    version = importlib.metadata.version("mcp")
    async with stdio_server() as (read_stream, write_stream):
        async with (
            ServerSession(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="mcp",
                    server_version=version,
                    capabilities=ServerCapabilities(),
                ),
            ) as session,
            write_stream,
        ):
            await receive_loop(session)

## stringify_pydantic_error

**Type**: Function

**Description**: def stringify_pydantic_error(validation_error: ValidationError) -> str:
    return "\n".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in validation_error.errors())

## PydanticJSONResponse

**Type**: Class

**Description**: class PydanticJSONResponse(JSONResponse):
    # use pydantic json serialization instead of the stock `json.dumps`,
    # so that we can handle serializing pydantic models like AnyHttpUrl
    def render(self, content: Any) -> bytes:
        return content.model_dump_json(exclude_none=True).encode("utf-8")

## AuthorizationParams

**Type**: Class

**Description**: class AuthorizationParams(BaseModel):
    state: str | None
    scopes: list[str] | None
    code_challenge: str
    redirect_uri: AnyUrl
    redirect_uri_provided_explicitly: bool
    resource: str | None = None  # RFC 8707 resource indicator

## AuthorizationCode

**Type**: Class

**Description**: class AuthorizationCode(BaseModel):
    code: str
    scopes: list[str]
    expires_at: float
    client_id: str
    code_challenge: str
    redirect_uri: AnyUrl
    redirect_uri_provided_explicitly: bool
    resource: str | None = None  # RFC 8707 resource indicator

## RefreshToken

**Type**: Class

**Description**: class RefreshToken(BaseModel):
    token: str
    client_id: str
    scopes: list[str]
    expires_at: int | None = None

## AccessToken

**Type**: Class

**Description**: class AccessToken(BaseModel):
    token: str
    client_id: str
    scopes: list[str]
    expires_at: int | None = None
    resource: str | None = None  # RFC 8707 resource indicator

## TokenVerifier

**Type**: Class

**Description**: class TokenVerifier(Protocol):
    """Protocol for verifying bearer tokens."""

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a bearer token and return access info if valid."""

## OAuthAuthorizationServerProvider

**Type**: Class

**Description**: class OAuthAuthorizationServerProvider(Protocol, Generic[AuthorizationCodeT, RefreshTokenT, AccessTokenT]):
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """
        Retrieves client information by client ID.

        Implementors MAY raise NotImplementedError if dynamic client registration is
        disabled in ClientRegistrationOptions.

        Args:
            client_id: The ID of the client to retrieve.

        Returns:
            The client information, or None if the client does not exist.
        """
        ...

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """
        Saves client information as part of registering it.

        Implementors MAY raise NotImplementedError if dynamic client registration is
        disabled in ClientRegistrationOptions.

        Args:
            client_info: The client metadata to register.

        Raises:
            RegistrationError: If the client metadata is invalid.
        """
        ...

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """
        Called as part of the /authorize endpoint, and returns a URL that the client
        will be redirected to.
        Many MCP implementations will redirect to a third-party provider to perform
        a second OAuth exchange with that provider. In this sort of setup, the client
        has an OAuth connection with the MCP server, and the MCP server has an OAuth
        connection with the 3rd-party provider. At the end of this flow, the client
        should be redirected to the redirect_uri from params.redirect_uri.

        +--------+     +------------+     +-------------------+
        |        |     |            |     |                   |
        | Client | --> | MCP Server | --> | 3rd Party OAuth   |
        |        |     |            |     | Server            |
        +--------+     +------------+     +-------------------+
                            |   ^                  |
        +------------+      |   |                  |
        |            |      |   |    Redirect      |
        |redirect_uri|<-----+   +------------------+
        |            |
        +------------+

        Implementations will need to define another handler on the MCP server return
        flow to perform the second redirect, and generate and store an authorization
        code as part of completing the OAuth authorization step.

        Implementations SHOULD generate an authorization code with at least 160 bits of
        entropy,
        and MUST generate an authorization code with at least 128 bits of entropy.
        See https://datatracker.ietf.org/doc/html/rfc6749#section-10.10.

        Args:
            client: The client requesting authorization.
            params: The parameters of the authorization request.

        Returns:
            A URL to redirect the client to for authorization.

        Raises:
            AuthorizeError: If the authorization request is invalid.
        """
        ...

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCodeT | None:
        """
        Loads an AuthorizationCode by its code.

        Args:
            client: The client that requested the authorization code.
            authorization_code: The authorization code to get the challenge for.

        Returns:
            The AuthorizationCode, or None if not found
        """
        ...

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCodeT
    ) -> OAuthToken:
        """
        Exchanges an authorization code for an access token and refresh token.

        Args:
            client: The client exchanging the authorization code.
            authorization_code: The authorization code to exchange.

        Returns:
            The OAuth token, containing access and refresh tokens.

        Raises:
            TokenError: If the request is invalid
        """
        ...

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshTokenT | None:
        """
        Loads a RefreshToken by its token string.

        Args:
            client: The client that is requesting to load the refresh token.
            refresh_token: The refresh token string to load.

        Returns:
            The RefreshToken object if found, or None if not found.
        """

    ...

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshTokenT,
        scopes: list[str],
    ) -> OAuthToken:
        """
        Exchanges a refresh token for an access token and refresh token.

        Implementations SHOULD rotate both the access token and refresh token.

        Args:
            client: The client exchanging the refresh token.
            refresh_token: The refresh token to exchange.
            scopes: Optional scopes to request with the new access token.

        Returns:
            The OAuth token, containing access and refresh tokens.

        Raises:
            TokenError: If the request is invalid
        """
        ...

    async def load_access_token(self, token: str) -> AccessTokenT | None:
        """
        Loads an access token by its token.

        Args:
            token: The access token to verify.

        Returns:
            The AuthInfo, or None if the token is invalid.
        """
        ...

    async def revoke_token(
        self,
        token: AccessTokenT | RefreshTokenT,
    ) -> None:
        """
        Revokes an access or refresh token.

        If the given token is invalid or already revoked, this method should do nothing.

        Implementations SHOULD revoke both the access token and its corresponding
        refresh token, regardless of which of the access token or refresh token is
        provided.

        Args:
            token: the token to revoke
        """
        ...

## construct_redirect_uri

**Type**: Function

**Description**: def construct_redirect_uri(redirect_uri_base: str, **params: str | None) -> str:
    parsed_uri = urlparse(redirect_uri_base)
    query_params = [(k, v) for k, vs in parse_qs(parsed_uri.query) for v in vs]
    for k, v in params.items():
        if v is not None:
            query_params.append((k, v))

    redirect_uri = urlunparse(parsed_uri._replace(query=urlencode(query_params)))
    return redirect_uri

## ProviderTokenVerifier

**Type**: Class

**Description**: class ProviderTokenVerifier(TokenVerifier):
    """Token verifier that uses an OAuthAuthorizationServerProvider.

    This is provided for backwards compatibility with existing auth_server_provider
    configurations. For new implementations using AS/RS separation, consider using
    the TokenVerifier protocol with a dedicated implementation like IntrospectionTokenVerifier.
    """

    def __init__(self, provider: "OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]"):
        self.provider = provider

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify token using the provider's load_access_token method."""
        return await self.provider.load_access_token(token)

## validate_issuer_url

**Type**: Function

**Description**: def validate_issuer_url(url: AnyHttpUrl):
    """
    Validate that the issuer URL meets OAuth 2.0 requirements.

    Args:
        url: The issuer URL to validate

    Raises:
        ValueError: If the issuer URL is invalid
    """

    # RFC 8414 requires HTTPS, but we allow localhost HTTP for testing
    if url.scheme != "https" and url.host != "localhost" and not url.host.startswith("127.0.0.1"):
        raise ValueError("Issuer URL must be HTTPS")

    # No fragments or query parameters allowed
    if url.fragment:
        raise ValueError("Issuer URL must not have a fragment")
    if url.query:
        raise ValueError("Issuer URL must not have a query string")

## cors_middleware

**Type**: Function

**Description**: def cors_middleware(
    handler: Callable[[Request], Response | Awaitable[Response]],
    allow_methods: list[str],
) -> ASGIApp:
    cors_app = CORSMiddleware(
        app=request_response(handler),
        allow_origins="*",
        allow_methods=allow_methods,
        allow_headers=[MCP_PROTOCOL_VERSION_HEADER],
    )
    return cors_app

## create_auth_routes

**Type**: Function

**Description**: def create_auth_routes(
    provider: OAuthAuthorizationServerProvider[Any, Any, Any],
    issuer_url: AnyHttpUrl,
    service_documentation_url: AnyHttpUrl | None = None,
    client_registration_options: ClientRegistrationOptions | None = None,
    revocation_options: RevocationOptions | None = None,
) -> list[Route]:
    validate_issuer_url(issuer_url)

    client_registration_options = client_registration_options or ClientRegistrationOptions()
    revocation_options = revocation_options or RevocationOptions()
    metadata = build_metadata(
        issuer_url,
        service_documentation_url,
        client_registration_options,
        revocation_options,
    )
    client_authenticator = ClientAuthenticator(provider)

    # Create routes
    # Allow CORS requests for endpoints meant to be hit by the OAuth client
    # (with the client secret). This is intended to support things like MCP Inspector,
    # where the client runs in a web browser.
    routes = [
        Route(
            "/.well-known/oauth-authorization-server",
            endpoint=cors_middleware(
                MetadataHandler(metadata).handle,
                ["GET", "OPTIONS"],
            ),
            methods=["GET", "OPTIONS"],
        ),
        Route(
            AUTHORIZATION_PATH,
            # do not allow CORS for authorization endpoint;
            # clients should just redirect to this
            endpoint=AuthorizationHandler(provider).handle,
            methods=["GET", "POST"],
        ),
        Route(
            TOKEN_PATH,
            endpoint=cors_middleware(
                TokenHandler(provider, client_authenticator).handle,
                ["POST", "OPTIONS"],
            ),
            methods=["POST", "OPTIONS"],
        ),
    ]

    if client_registration_options.enabled:
        registration_handler = RegistrationHandler(
            provider,
            options=client_registration_options,
        )
        routes.append(
            Route(
                REGISTRATION_PATH,
                endpoint=cors_middleware(
                    registration_handler.handle,
                    ["POST", "OPTIONS"],
                ),
                methods=["POST", "OPTIONS"],
            )
        )

    if revocation_options.enabled:
        revocation_handler = RevocationHandler(provider, client_authenticator)
        routes.append(
            Route(
                REVOCATION_PATH,
                endpoint=cors_middleware(
                    revocation_handler.handle,
                    ["POST", "OPTIONS"],
                ),
                methods=["POST", "OPTIONS"],
            )
        )

    return routes

## build_metadata

**Type**: Function

**Description**: def build_metadata(
    issuer_url: AnyHttpUrl,
    service_documentation_url: AnyHttpUrl | None,
    client_registration_options: ClientRegistrationOptions,
    revocation_options: RevocationOptions,
) -> OAuthMetadata:
    authorization_url = AnyHttpUrl(str(issuer_url).rstrip("/") + AUTHORIZATION_PATH)
    token_url = AnyHttpUrl(str(issuer_url).rstrip("/") + TOKEN_PATH)

    # Create metadata
    metadata = OAuthMetadata(
        issuer=issuer_url,
        authorization_endpoint=authorization_url,
        token_endpoint=token_url,
        scopes_supported=client_registration_options.valid_scopes,
        response_types_supported=["code"],
        response_modes_supported=None,
        grant_types_supported=["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported=["client_secret_post"],
        token_endpoint_auth_signing_alg_values_supported=None,
        service_documentation=service_documentation_url,
        ui_locales_supported=None,
        op_policy_uri=None,
        op_tos_uri=None,
        introspection_endpoint=None,
        code_challenge_methods_supported=["S256"],
    )

    # Add registration endpoint if supported
    if client_registration_options.enabled:
        metadata.registration_endpoint = AnyHttpUrl(str(issuer_url).rstrip("/") + REGISTRATION_PATH)

    # Add revocation endpoint if supported
    if revocation_options.enabled:
        metadata.revocation_endpoint = AnyHttpUrl(str(issuer_url).rstrip("/") + REVOCATION_PATH)
        metadata.revocation_endpoint_auth_methods_supported = ["client_secret_post"]

    return metadata

## create_protected_resource_routes

**Type**: Function

**Description**: def create_protected_resource_routes(
    resource_url: AnyHttpUrl,
    authorization_servers: list[AnyHttpUrl],
    scopes_supported: list[str] | None = None,
) -> list[Route]:
    """
    Create routes for OAuth 2.0 Protected Resource Metadata (RFC 9728).

    Args:
        resource_url: The URL of this resource server
        authorization_servers: List of authorization servers that can issue tokens
        scopes_supported: Optional list of scopes supported by this resource

    Returns:
        List of Starlette routes for protected resource metadata
    """
    from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
    from mcp.shared.auth import ProtectedResourceMetadata

    metadata = ProtectedResourceMetadata(
        resource=resource_url,
        authorization_servers=authorization_servers,
        scopes_supported=scopes_supported,
        # bearer_methods_supported defaults to ["header"] in the model
    )

    handler = ProtectedResourceMetadataHandler(metadata)

    return [
        Route(
            "/.well-known/oauth-protected-resource",
            endpoint=cors_middleware(handler.handle, ["GET", "OPTIONS"]),
            methods=["GET", "OPTIONS"],
        )
    ]

## ClientRegistrationOptions

**Type**: Class

**Description**: class ClientRegistrationOptions(BaseModel):
    enabled: bool = False
    client_secret_expiry_seconds: int | None = None
    valid_scopes: list[str] | None = None
    default_scopes: list[str] | None = None

## RevocationOptions

**Type**: Class

**Description**: class RevocationOptions(BaseModel):
    enabled: bool = False

## AuthSettings

**Type**: Class

**Description**: class AuthSettings(BaseModel):
    issuer_url: AnyHttpUrl = Field(
        ...,
        description="OAuth authorization server URL that issues tokens for this resource server.",
    )
    service_documentation_url: AnyHttpUrl | None = None
    client_registration_options: ClientRegistrationOptions | None = None
    revocation_options: RevocationOptions | None = None
    required_scopes: list[str] | None = None

    # Resource Server settings (when operating as RS only)
    resource_server_url: AnyHttpUrl | None = Field(
        ...,
        description="The URL of the MCP server to be used as the resource identifier "
        "and base route to look up OAuth Protected Resource Metadata.",
    )

## AuthorizationRequest

**Type**: Class

**Description**: class AuthorizationRequest(BaseModel):
    # See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
    client_id: str = Field(..., description="The client ID")
    redirect_uri: AnyUrl | None = Field(None, description="URL to redirect to after authorization")

    # see OAuthClientMetadata; we only support `code`
    response_type: Literal["code"] = Field(..., description="Must be 'code' for authorization code flow")
    code_challenge: str = Field(..., description="PKCE code challenge")
    code_challenge_method: Literal["S256"] = Field("S256", description="PKCE code challenge method, must be S256")
    state: str | None = Field(None, description="Optional state parameter")
    scope: str | None = Field(
        None,
        description="Optional scope; if specified, should be " "a space-separated list of scope strings",
    )
    resource: str | None = Field(
        None,
        description="RFC 8707 resource indicator - the MCP server this token will be used with",
    )

## AuthorizationErrorResponse

**Type**: Class

**Description**: class AuthorizationErrorResponse(BaseModel):
    error: AuthorizationErrorCode
    error_description: str | None
    error_uri: AnyUrl | None = None
    # must be set if provided in the request
    state: str | None = None

## best_effort_extract_string

**Type**: Function

**Description**: def best_effort_extract_string(key: str, params: None | FormData | QueryParams) -> str | None:
    if params is None:
        return None
    value = params.get(key)
    if isinstance(value, str):
        return value
    return None

## AnyUrlModel

**Type**: Class

**Description**: class AnyUrlModel(RootModel[AnyUrl]):
    root: AnyUrl

## RegistrationRequest

**Type**: Class

**Description**: class RegistrationRequest(RootModel[OAuthClientMetadata]):
    # this wrapper is a no-op; it's just to separate out the types exposed to the
    # provider from what we use in the HTTP handler
    root: OAuthClientMetadata

## RegistrationErrorResponse

**Type**: Class

**Description**: class RegistrationErrorResponse(BaseModel):
    error: RegistrationErrorCode
    error_description: str | None

## RevocationRequest

**Type**: Class

**Description**: class RevocationRequest(BaseModel):
    """
    # See https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
    """

    token: str
    token_type_hint: Literal["access_token", "refresh_token"] | None = None
    client_id: str
    client_secret: str | None

## RevocationErrorResponse

**Type**: Class

**Description**: class RevocationErrorResponse(BaseModel):
    error: Literal["invalid_request", "unauthorized_client"]
    error_description: str | None = None

## AuthorizationCodeRequest

**Type**: Class

**Description**: class AuthorizationCodeRequest(BaseModel):
    # See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    grant_type: Literal["authorization_code"]
    code: str = Field(..., description="The authorization code")
    redirect_uri: AnyUrl | None = Field(None, description="Must be the same as redirect URI provided in /authorize")
    client_id: str
    # we use the client_secret param, per https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
    client_secret: str | None = None
    # See https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
    code_verifier: str = Field(..., description="PKCE code verifier")
    # RFC 8707 resource indicator
    resource: str | None = Field(None, description="Resource indicator for the token")

## RefreshTokenRequest

**Type**: Class

**Description**: class RefreshTokenRequest(BaseModel):
    # See https://datatracker.ietf.org/doc/html/rfc6749#section-6
    grant_type: Literal["refresh_token"]
    refresh_token: str = Field(..., description="The refresh token")
    scope: str | None = Field(None, description="Optional scope parameter")
    client_id: str
    # we use the client_secret param, per https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
    client_secret: str | None = None
    # RFC 8707 resource indicator
    resource: str | None = Field(None, description="Resource indicator for the token")

## TokenRequest

**Type**: Class

**Description**: class TokenRequest(
    RootModel[
        Annotated[
            AuthorizationCodeRequest | RefreshTokenRequest,
            Field(discriminator="grant_type"),
        ]
    ]
):
    root: Annotated[
        AuthorizationCodeRequest | RefreshTokenRequest,
        Field(discriminator="grant_type"),
    ]

## TokenErrorResponse

**Type**: Class

**Description**: class TokenErrorResponse(BaseModel):
    """
    See https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    """

    error: TokenErrorCode
    error_description: str | None = None
    error_uri: AnyHttpUrl | None = None

## TokenSuccessResponse

**Type**: Class

**Description**: class TokenSuccessResponse(RootModel[OAuthToken]):
    # this is just a wrapper over OAuthToken; the only reason we do this
    # is to have some separation between the HTTP response type, and the
    # type returned by the provider
    root: OAuthToken

## get_access_token

**Type**: Function

**Description**: def get_access_token() -> AccessToken | None:
    """
    Get the access token from the current context.

    Returns:
        The access token if an authenticated user is available, None otherwise.
    """
    auth_user = auth_context_var.get()
    return auth_user.access_token if auth_user else None

## AuthContextMiddleware

**Type**: Class

**Description**: class AuthContextMiddleware:
    """
    Middleware that extracts the authenticated user from the request
    and sets it in a contextvar for easy access throughout the request lifecycle.

    This middleware should be added after the AuthenticationMiddleware in the
    middleware stack to ensure that the user is properly authenticated before
    being stored in the context.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        user = scope.get("user")
        if isinstance(user, AuthenticatedUser):
            # Set the authenticated user in the contextvar
            token = auth_context_var.set(user)
            try:
                await self.app(scope, receive, send)
            finally:
                auth_context_var.reset(token)
        else:
            # No authenticated user, just process the request
            await self.app(scope, receive, send)

## AuthenticatedUser

**Type**: Class

**Description**: class AuthenticatedUser(SimpleUser):
    """User with authentication info."""

    def __init__(self, auth_info: AccessToken):
        super().__init__(auth_info.client_id)
        self.access_token = auth_info
        self.scopes = auth_info.scopes

## BearerAuthBackend

**Type**: Class

**Description**: class BearerAuthBackend(AuthenticationBackend):
    """
    Authentication backend that validates Bearer tokens using a TokenVerifier.
    """

    def __init__(self, token_verifier: TokenVerifier):
        self.token_verifier = token_verifier

    async def authenticate(self, conn: HTTPConnection):
        auth_header = next(
            (conn.headers.get(key) for key in conn.headers if key.lower() == "authorization"),
            None,
        )
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return None

        token = auth_header[7:]  # Remove "Bearer " prefix

        # Validate the token with the verifier
        auth_info = await self.token_verifier.verify_token(token)

        if not auth_info:
            return None

        if auth_info.expires_at and auth_info.expires_at < int(time.time()):
            return None

        return AuthCredentials(auth_info.scopes), AuthenticatedUser(auth_info)

## RequireAuthMiddleware

**Type**: Class

**Description**: class RequireAuthMiddleware:
    """
    Middleware that requires a valid Bearer token in the Authorization header.

    This will validate the token with the auth provider and store the resulting
    auth info in the request state.
    """

    def __init__(
        self,
        app: Any,
        required_scopes: list[str],
        resource_metadata_url: AnyHttpUrl | None = None,
    ):
        """
        Initialize the middleware.

        Args:
            app: ASGI application
            required_scopes: List of scopes that the token must have
            resource_metadata_url: Optional protected resource metadata URL for WWW-Authenticate header
        """
        self.app = app
        self.required_scopes = required_scopes
        self.resource_metadata_url = resource_metadata_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        auth_user = scope.get("user")
        if not isinstance(auth_user, AuthenticatedUser):
            await self._send_auth_error(
                send, status_code=401, error="invalid_token", description="Authentication required"
            )
            return

        auth_credentials = scope.get("auth")

        for required_scope in self.required_scopes:
            # auth_credentials should always be provided; this is just paranoia
            if auth_credentials is None or required_scope not in auth_credentials.scopes:
                await self._send_auth_error(
                    send, status_code=403, error="insufficient_scope", description=f"Required scope: {required_scope}"
                )
                return

        await self.app(scope, receive, send)

    async def _send_auth_error(self, send: Send, status_code: int, error: str, description: str) -> None:
        """Send an authentication error response with WWW-Authenticate header."""
        # Build WWW-Authenticate header value
        www_auth_parts = [f'error="{error}"', f'error_description="{description}"']
        if self.resource_metadata_url:
            www_auth_parts.append(f'resource_metadata="{self.resource_metadata_url}"')

        www_authenticate = f"Bearer {', '.join(www_auth_parts)}"

        # Send response
        body = {"error": error, "error_description": description}
        body_bytes = json.dumps(body).encode()

        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body_bytes)).encode()),
                    (b"www-authenticate", www_authenticate.encode()),
                ],
            }
        )

        await send(
            {
                "type": "http.response.body",
                "body": body_bytes,
            }
        )

## AuthenticationError

**Type**: Class

**Description**: class AuthenticationError(Exception):
    def __init__(self, message: str):
        self.message = message

## ClientAuthenticator

**Type**: Class

**Description**: class ClientAuthenticator:
    """
    ClientAuthenticator is a callable which validates requests from a client
    application, used to verify /token calls.
    If, during registration, the client requested to be issued a secret, the
    authenticator asserts that /token calls must be authenticated with
    that same token.
    NOTE: clients can opt for no authentication during registration, in which case this
    logic is skipped.
    """

    def __init__(self, provider: OAuthAuthorizationServerProvider[Any, Any, Any]):
        """
        Initialize the dependency.

        Args:
            provider: Provider to look up client information
        """
        self.provider = provider

    async def authenticate(self, client_id: str, client_secret: str | None) -> OAuthClientInformationFull:
        # Look up client information
        client = await self.provider.get_client(client_id)
        if not client:
            raise AuthenticationError("Invalid client_id")

        # If client from the store expects a secret, validate that the request provides
        # that secret
        if client.client_secret:
            if not client_secret:
                raise AuthenticationError("Client secret is required")

            if client.client_secret != client_secret:
                raise AuthenticationError("Invalid client_secret")

            if client.client_secret_expires_at and client.client_secret_expires_at < int(time.time()):
                raise AuthenticationError("Client secret has expired")

        return client

## FastMCPError

**Type**: Class

**Description**: class FastMCPError(Exception):
    """Base error for FastMCP."""

## ValidationError

**Type**: Class

**Description**: class ValidationError(FastMCPError):
    """Error in validating parameters or return values."""

## ResourceError

**Type**: Class

**Description**: class ResourceError(FastMCPError):
    """Error in resource operations."""

## ToolError

**Type**: Class

**Description**: class ToolError(FastMCPError):
    """Error in tool operations."""

## InvalidSignature

**Type**: Class

**Description**: class InvalidSignature(Exception):
    """Invalid signature for use with FastMCP."""

## Settings

**Type**: Class

**Description**: class Settings(BaseSettings, Generic[LifespanResultT]):
    """FastMCP server settings.

    All settings can be configured via environment variables with the prefix FASTMCP_.
    For example, FASTMCP_DEBUG=true will set debug=True.
    """

    model_config = SettingsConfigDict(
        env_prefix="FASTMCP_",
        env_file=".env",
        env_nested_delimiter="__",
        nested_model_default_partial_update=True,
        extra="ignore",
    )

    # Server settings
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # HTTP settings
    host: str = "127.0.0.1"
    port: int = 8000
    mount_path: str = "/"  # Mount path (e.g. "/github", defaults to root path)
    sse_path: str = "/sse"
    message_path: str = "/messages/"
    streamable_http_path: str = "/mcp"

    # StreamableHTTP settings
    json_response: bool = False
    stateless_http: bool = False  # If True, uses true stateless mode (new transport per request)

    # resource settings
    warn_on_duplicate_resources: bool = True

    # tool settings
    warn_on_duplicate_tools: bool = True

    # prompt settings
    warn_on_duplicate_prompts: bool = True

    dependencies: list[str] = Field(
        default_factory=list,
        description="List of dependencies to install in the server environment",
    )

    lifespan: Callable[[FastMCP], AbstractAsyncContextManager[LifespanResultT]] | None = Field(
        None, description="Lifespan context manager"
    )

    auth: AuthSettings | None = None

    # Transport security settings (DNS rebinding protection)
    transport_security: TransportSecuritySettings | None = None

## lifespan_wrapper

**Type**: Function

**Description**: def lifespan_wrapper(
    app: FastMCP,
    lifespan: Callable[[FastMCP], AbstractAsyncContextManager[LifespanResultT]],
) -> Callable[[MCPServer[LifespanResultT, Request]], AbstractAsyncContextManager[object]]:
    @asynccontextmanager
    async def wrap(s: MCPServer[LifespanResultT, Request]) -> AsyncIterator[object]:
        async with lifespan(app) as context:
            yield context

    return wrap

## FastMCP

**Type**: Class

**Description**: class FastMCP:
    def __init__(
        self,
        name: str | None = None,
        instructions: str | None = None,
        auth_server_provider: OAuthAuthorizationServerProvider[Any, Any, Any] | None = None,
        token_verifier: TokenVerifier | None = None,
        event_store: EventStore | None = None,
        *,
        tools: list[Tool] | None = None,
        **settings: Any,
    ):
        self.settings = Settings(**settings)

        self._mcp_server = MCPServer(
            name=name or "FastMCP",
            instructions=instructions,
            lifespan=(lifespan_wrapper(self, self.settings.lifespan) if self.settings.lifespan else default_lifespan),
        )
        self._tool_manager = ToolManager(tools=tools, warn_on_duplicate_tools=self.settings.warn_on_duplicate_tools)
        self._resource_manager = ResourceManager(warn_on_duplicate_resources=self.settings.warn_on_duplicate_resources)
        self._prompt_manager = PromptManager(warn_on_duplicate_prompts=self.settings.warn_on_duplicate_prompts)
        # Validate auth configuration
        if self.settings.auth is not None:
            if auth_server_provider and token_verifier:
                raise ValueError("Cannot specify both auth_server_provider and token_verifier")
            if not auth_server_provider and not token_verifier:
                raise ValueError("Must specify either auth_server_provider or token_verifier when auth is enabled")
        else:
            if auth_server_provider or token_verifier:
                raise ValueError("Cannot specify auth_server_provider or token_verifier without auth settings")

        self._auth_server_provider = auth_server_provider
        self._token_verifier = token_verifier

        # Create token verifier from provider if needed (backwards compatibility)
        if auth_server_provider and not token_verifier:
            self._token_verifier = ProviderTokenVerifier(auth_server_provider)
        self._event_store = event_store
        self._custom_starlette_routes: list[Route] = []
        self.dependencies = self.settings.dependencies
        self._session_manager: StreamableHTTPSessionManager | None = None

        # Set up MCP protocol handlers
        self._setup_handlers()

        # Configure logging
        configure_logging(self.settings.log_level)

    @property
    def name(self) -> str:
        return self._mcp_server.name

    @property
    def instructions(self) -> str | None:
        return self._mcp_server.instructions

    @property
    def session_manager(self) -> StreamableHTTPSessionManager:
        """Get the StreamableHTTP session manager.

        This is exposed to enable advanced use cases like mounting multiple
        FastMCP servers in a single FastAPI application.

        Raises:
            RuntimeError: If called before streamable_http_app() has been called.
        """
        if self._session_manager is None:
            raise RuntimeError(
                "Session manager can only be accessed after"
                "calling streamable_http_app()."
                "The session manager is created lazily"
                "to avoid unnecessary initialization."
            )
        return self._session_manager

    def run(
        self,
        transport: Literal["stdio", "sse", "streamable-http"] = "stdio",
        mount_path: str | None = None,
    ) -> None:
        """Run the FastMCP server. Note this is a synchronous function.

        Args:
            transport: Transport protocol to use ("stdio", "sse", or "streamable-http")
            mount_path: Optional mount path for SSE transport
        """
        TRANSPORTS = Literal["stdio", "sse", "streamable-http"]
        if transport not in TRANSPORTS.__args__:  # type: ignore
            raise ValueError(f"Unknown transport: {transport}")

        match transport:
            case "stdio":
                anyio.run(self.run_stdio_async)
            case "sse":
                anyio.run(lambda: self.run_sse_async(mount_path))
            case "streamable-http":
                anyio.run(self.run_streamable_http_async)

    def _setup_handlers(self) -> None:
        """Set up core MCP protocol handlers."""
        self._mcp_server.list_tools()(self.list_tools)
        # Note: we disable the lowlevel server's input validation.
        # FastMCP does ad hoc conversion of incoming data before validating -
        # for now we preserve this for backwards compatibility.
        self._mcp_server.call_tool(validate_input=False)(self.call_tool)
        self._mcp_server.list_resources()(self.list_resources)
        self._mcp_server.read_resource()(self.read_resource)
        self._mcp_server.list_prompts()(self.list_prompts)
        self._mcp_server.get_prompt()(self.get_prompt)
        self._mcp_server.list_resource_templates()(self.list_resource_templates)

    async def list_tools(self) -> list[MCPTool]:
        """List all available tools."""
        tools = self._tool_manager.list_tools()
        return [
            MCPTool(
                name=info.name,
                title=info.title,
                description=info.description,
                inputSchema=info.parameters,
                outputSchema=info.output_schema,
                annotations=info.annotations,
            )
            for info in tools
        ]

    def get_context(self) -> Context[ServerSession, object, Request]:
        """
        Returns a Context object. Note that the context will only be valid
        during a request; outside a request, most methods will error.
        """
        try:
            request_context = self._mcp_server.request_context
        except LookupError:
            request_context = None
        return Context(request_context=request_context, fastmcp=self)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Sequence[ContentBlock] | dict[str, Any]:
        """Call a tool by name with arguments."""
        context = self.get_context()
        return await self._tool_manager.call_tool(name, arguments, context=context, convert_result=True)

    async def list_resources(self) -> list[MCPResource]:
        """List all available resources."""

        resources = self._resource_manager.list_resources()
        return [
            MCPResource(
                uri=resource.uri,
                name=resource.name or "",
                title=resource.title,
                description=resource.description,
                mimeType=resource.mime_type,
            )
            for resource in resources
        ]

    async def list_resource_templates(self) -> list[MCPResourceTemplate]:
        templates = self._resource_manager.list_templates()
        return [
            MCPResourceTemplate(
                uriTemplate=template.uri_template,
                name=template.name,
                title=template.title,
                description=template.description,
            )
            for template in templates
        ]

    async def read_resource(self, uri: AnyUrl | str) -> Iterable[ReadResourceContents]:
        """Read a resource by URI."""

        resource = await self._resource_manager.get_resource(uri)
        if not resource:
            raise ResourceError(f"Unknown resource: {uri}")

        try:
            content = await resource.read()
            return [ReadResourceContents(content=content, mime_type=resource.mime_type)]
        except Exception as e:
            logger.error(f"Error reading resource {uri}: {e}")
            raise ResourceError(str(e))

    def add_tool(
        self,
        fn: AnyFunction,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | None = None,
        structured_output: bool | None = None,
    ) -> None:
        """Add a tool to the server.

        The tool function can optionally request a Context object by adding a parameter
        with the Context type annotation. See the @tool decorator for examples.

        Args:
            fn: The function to register as a tool
            name: Optional name for the tool (defaults to function name)
            title: Optional human-readable title for the tool
            description: Optional description of what the tool does
            annotations: Optional ToolAnnotations providing additional tool information
            structured_output: Controls whether the tool's output is structured or unstructured
                - If None, auto-detects based on the function's return type annotation
                - If True, unconditionally creates a structured tool (return type annotation permitting)
                - If False, unconditionally creates an unstructured tool
        """
        self._tool_manager.add_tool(
            fn,
            name=name,
            title=title,
            description=description,
            annotations=annotations,
            structured_output=structured_output,
        )

    def tool(
        self,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | None = None,
        structured_output: bool | None = None,
    ) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a tool.

        Tools can optionally request a Context object by adding a parameter with the
        Context type annotation. The context provides access to MCP capabilities like
        logging, progress reporting, and resource access.

        Args:
            name: Optional name for the tool (defaults to function name)
            title: Optional human-readable title for the tool
            description: Optional description of what the tool does
            annotations: Optional ToolAnnotations providing additional tool information
            structured_output: Controls whether the tool's output is structured or unstructured
                - If None, auto-detects based on the function's return type annotation
                - If True, unconditionally creates a structured tool (return type annotation permitting)
                - If False, unconditionally creates an unstructured tool

        Example:
            @server.tool()
            def my_tool(x: int) -> str:
                return str(x)

            @server.tool()
            def tool_with_context(x: int, ctx: Context) -> str:
                ctx.info(f"Processing {x}")
                return str(x)

            @server.tool()
            async def async_tool(x: int, context: Context) -> str:
                await context.report_progress(50, 100)
                return str(x)
        """
        # Check if user passed function directly instead of calling decorator
        if callable(name):
            raise TypeError(
                "The @tool decorator was used incorrectly. " "Did you forget to call it? Use @tool() instead of @tool"
            )

        def decorator(fn: AnyFunction) -> AnyFunction:
            self.add_tool(
                fn,
                name=name,
                title=title,
                description=description,
                annotations=annotations,
                structured_output=structured_output,
            )
            return fn

        return decorator

    def completion(self):
        """Decorator to register a completion handler.

        The completion handler receives:
        - ref: PromptReference or ResourceTemplateReference
        - argument: CompletionArgument with name and partial value
        - context: Optional CompletionContext with previously resolved arguments

        Example:
            @mcp.completion()
            async def handle_completion(ref, argument, context):
                if isinstance(ref, ResourceTemplateReference):
                    # Return completions based on ref, argument, and context
                    return Completion(values=["option1", "option2"])
                return None
        """
        return self._mcp_server.completion()

    def add_resource(self, resource: Resource) -> None:
        """Add a resource to the server.

        Args:
            resource: A Resource instance to add
        """
        self._resource_manager.add_resource(resource)

    def resource(
        self,
        uri: str,
        *,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        mime_type: str | None = None,
    ) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a function as a resource.

        The function will be called when the resource is read to generate its content.
        The function can return:
        - str for text content
        - bytes for binary content
        - other types will be converted to JSON

        If the URI contains parameters (e.g. "resource://{param}") or the function
        has parameters, it will be registered as a template resource.

        Args:
            uri: URI for the resource (e.g. "resource://my-resource" or "resource://{param}")
            name: Optional name for the resource
            title: Optional human-readable title for the resource
            description: Optional description of the resource
            mime_type: Optional MIME type for the resource

        Example:
            @server.resource("resource://my-resource")
            def get_data() -> str:
                return "Hello, world!"

            @server.resource("resource://my-resource")
            async get_data() -> str:
                data = await fetch_data()
                return f"Hello, world! {data}"

            @server.resource("resource://{city}/weather")
            def get_weather(city: str) -> str:
                return f"Weather for {city}"

            @server.resource("resource://{city}/weather")
            async def get_weather(city: str) -> str:
                data = await fetch_weather(city)
                return f"Weather for {city}: {data}"
        """
        # Check if user passed function directly instead of calling decorator
        if callable(uri):
            raise TypeError(
                "The @resource decorator was used incorrectly. "
                "Did you forget to call it? Use @resource('uri') instead of @resource"
            )

        def decorator(fn: AnyFunction) -> AnyFunction:
            # Check if this should be a template
            has_uri_params = "{" in uri and "}" in uri
            has_func_params = bool(inspect.signature(fn).parameters)

            if has_uri_params or has_func_params:
                # Validate that URI params match function params
                uri_params = set(re.findall(r"{(\w+)}", uri))
                func_params = set(inspect.signature(fn).parameters.keys())

                if uri_params != func_params:
                    raise ValueError(
                        f"Mismatch between URI parameters {uri_params} " f"and function parameters {func_params}"
                    )

                # Register as template
                self._resource_manager.add_template(
                    fn=fn,
                    uri_template=uri,
                    name=name,
                    title=title,
                    description=description,
                    mime_type=mime_type,
                )
            else:
                # Register as regular resource
                resource = FunctionResource.from_function(
                    fn=fn,
                    uri=uri,
                    name=name,
                    title=title,
                    description=description,
                    mime_type=mime_type,
                )
                self.add_resource(resource)
            return fn

        return decorator

    def add_prompt(self, prompt: Prompt) -> None:
        """Add a prompt to the server.

        Args:
            prompt: A Prompt instance to add
        """
        self._prompt_manager.add_prompt(prompt)

    def prompt(
        self, name: str | None = None, title: str | None = None, description: str | None = None
    ) -> Callable[[AnyFunction], AnyFunction]:
        """Decorator to register a prompt.

        Args:
            name: Optional name for the prompt (defaults to function name)
            title: Optional human-readable title for the prompt
            description: Optional description of what the prompt does

        Example:
            @server.prompt()
            def analyze_table(table_name: str) -> list[Message]:
                schema = read_table_schema(table_name)
                return [
                    {
                        "role": "user",
                        "content": f"Analyze this schema:\n{schema}"
                    }
                ]

            @server.prompt()
            async def analyze_file(path: str) -> list[Message]:
                content = await read_file(path)
                return [
                    {
                        "role": "user",
                        "content": {
                            "type": "resource",
                            "resource": {
                                "uri": f"file://{path}",
                                "text": content
                            }
                        }
                    }
                ]
        """
        # Check if user passed function directly instead of calling decorator
        if callable(name):
            raise TypeError(
                "The @prompt decorator was used incorrectly. "
                "Did you forget to call it? Use @prompt() instead of @prompt"
            )

        def decorator(func: AnyFunction) -> AnyFunction:
            prompt = Prompt.from_function(func, name=name, title=title, description=description)
            self.add_prompt(prompt)
            return func

        return decorator

    def custom_route(
        self,
        path: str,
        methods: list[str],
        name: str | None = None,
        include_in_schema: bool = True,
    ):
        """
        Decorator to register a custom HTTP route on the FastMCP server.

        Allows adding arbitrary HTTP endpoints outside the standard MCP protocol,
        which can be useful for OAuth callbacks, health checks, or admin APIs.
        The handler function must be an async function that accepts a Starlette
        Request and returns a Response.

        Args:
            path: URL path for the route (e.g., "/oauth/callback")
            methods: List of HTTP methods to support (e.g., ["GET", "POST"])
            name: Optional name for the route (to reference this route with
                  Starlette's reverse URL lookup feature)
            include_in_schema: Whether to include in OpenAPI schema, defaults to True

        Example:
            @server.custom_route("/health", methods=["GET"])
            async def health_check(request: Request) -> Response:
                return JSONResponse({"status": "ok"})
        """

        def decorator(
            func: Callable[[Request], Awaitable[Response]],
        ) -> Callable[[Request], Awaitable[Response]]:
            self._custom_starlette_routes.append(
                Route(
                    path,
                    endpoint=func,
                    methods=methods,
                    name=name,
                    include_in_schema=include_in_schema,
                )
            )
            return func

        return decorator

    async def run_stdio_async(self) -> None:
        """Run the server using stdio transport."""
        async with stdio_server() as (read_stream, write_stream):
            await self._mcp_server.run(
                read_stream,
                write_stream,
                self._mcp_server.create_initialization_options(),
            )

    async def run_sse_async(self, mount_path: str | None = None) -> None:
        """Run the server using SSE transport."""
        import uvicorn

        starlette_app = self.sse_app(mount_path)

        config = uvicorn.Config(
            starlette_app,
            host=self.settings.host,
            port=self.settings.port,
            log_level=self.settings.log_level.lower(),
        )
        server = uvicorn.Server(config)
        await server.serve()

    async def run_streamable_http_async(self) -> None:
        """Run the server using StreamableHTTP transport."""
        import uvicorn

        starlette_app = self.streamable_http_app()

        config = uvicorn.Config(
            starlette_app,
            host=self.settings.host,
            port=self.settings.port,
            log_level=self.settings.log_level.lower(),
        )
        server = uvicorn.Server(config)
        await server.serve()

    def _normalize_path(self, mount_path: str, endpoint: str) -> str:
        """
        Combine mount path and endpoint to return a normalized path.

        Args:
            mount_path: The mount path (e.g. "/github" or "/")
            endpoint: The endpoint path (e.g. "/messages/")

        Returns:
            Normalized path (e.g. "/github/messages/")
        """
        # Special case: root path
        if mount_path == "/":
            return endpoint

        # Remove trailing slash from mount path
        if mount_path.endswith("/"):
            mount_path = mount_path[:-1]

        # Ensure endpoint starts with slash
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint

        # Combine paths
        return mount_path + endpoint

    def sse_app(self, mount_path: str | None = None) -> Starlette:
        """Return an instance of the SSE server app."""
        from starlette.middleware import Middleware
        from starlette.routing import Mount, Route

        # Update mount_path in settings if provided
        if mount_path is not None:
            self.settings.mount_path = mount_path

        # Create normalized endpoint considering the mount path
        normalized_message_endpoint = self._normalize_path(self.settings.mount_path, self.settings.message_path)

        # Set up auth context and dependencies

        sse = SseServerTransport(
            normalized_message_endpoint,
            security_settings=self.settings.transport_security,
        )

        async def handle_sse(scope: Scope, receive: Receive, send: Send):
            # Add client ID from auth context into request context if available

            async with sse.connect_sse(
                scope,
                receive,
                send,
            ) as streams:
                await self._mcp_server.run(
                    streams[0],
                    streams[1],
                    self._mcp_server.create_initialization_options(),
                )
            return Response()

        # Create routes
        routes: list[Route | Mount] = []
        middleware: list[Middleware] = []
        required_scopes = []

        # Set up auth if configured
        if self.settings.auth:
            required_scopes = self.settings.auth.required_scopes or []

            # Add auth middleware if token verifier is available
            if self._token_verifier:
                middleware = [
                    # extract auth info from request (but do not require it)
                    Middleware(
                        AuthenticationMiddleware,
                        backend=BearerAuthBackend(self._token_verifier),
                    ),
                    # Add the auth context middleware to store
                    # authenticated user in a contextvar
                    Middleware(AuthContextMiddleware),
                ]

            # Add auth endpoints if auth server provider is configured
            if self._auth_server_provider:
                from mcp.server.auth.routes import create_auth_routes

                routes.extend(
                    create_auth_routes(
                        provider=self._auth_server_provider,
                        issuer_url=self.settings.auth.issuer_url,
                        service_documentation_url=self.settings.auth.service_documentation_url,
                        client_registration_options=self.settings.auth.client_registration_options,
                        revocation_options=self.settings.auth.revocation_options,
                    )
                )

        # When auth is configured, require authentication
        if self._token_verifier:
            # Determine resource metadata URL
            resource_metadata_url = None
            if self.settings.auth and self.settings.auth.resource_server_url:
                from pydantic import AnyHttpUrl

                resource_metadata_url = AnyHttpUrl(
                    str(self.settings.auth.resource_server_url).rstrip("/") + "/.well-known/oauth-protected-resource"
                )

            # Auth is enabled, wrap the endpoints with RequireAuthMiddleware
            routes.append(
                Route(
                    self.settings.sse_path,
                    endpoint=RequireAuthMiddleware(handle_sse, required_scopes, resource_metadata_url),
                    methods=["GET"],
                )
            )
            routes.append(
                Mount(
                    self.settings.message_path,
                    app=RequireAuthMiddleware(sse.handle_post_message, required_scopes, resource_metadata_url),
                )
            )
        else:
            # Auth is disabled, no need for RequireAuthMiddleware
            # Since handle_sse is an ASGI app, we need to create a compatible endpoint
            async def sse_endpoint(request: Request) -> Response:
                # Convert the Starlette request to ASGI parameters
                return await handle_sse(request.scope, request.receive, request._send)  # type: ignore[reportPrivateUsage]

            routes.append(
                Route(
                    self.settings.sse_path,
                    endpoint=sse_endpoint,
                    methods=["GET"],
                )
            )
            routes.append(
                Mount(
                    self.settings.message_path,
                    app=sse.handle_post_message,
                )
            )
        # Add protected resource metadata endpoint if configured as RS
        if self.settings.auth and self.settings.auth.resource_server_url:
            from mcp.server.auth.routes import create_protected_resource_routes

            routes.extend(
                create_protected_resource_routes(
                    resource_url=self.settings.auth.resource_server_url,
                    authorization_servers=[self.settings.auth.issuer_url],
                    scopes_supported=self.settings.auth.required_scopes,
                )
            )

        # mount these routes last, so they have the lowest route matching precedence
        routes.extend(self._custom_starlette_routes)

        # Create Starlette app with routes and middleware
        return Starlette(debug=self.settings.debug, routes=routes, middleware=middleware)

    def streamable_http_app(self) -> Starlette:
        """Return an instance of the StreamableHTTP server app."""
        from starlette.middleware import Middleware
        from starlette.routing import Mount

        # Create session manager on first call (lazy initialization)
        if self._session_manager is None:
            self._session_manager = StreamableHTTPSessionManager(
                app=self._mcp_server,
                event_store=self._event_store,
                json_response=self.settings.json_response,
                stateless=self.settings.stateless_http,  # Use the stateless setting
                security_settings=self.settings.transport_security,
            )

        # Create the ASGI handler
        async def handle_streamable_http(scope: Scope, receive: Receive, send: Send) -> None:
            await self.session_manager.handle_request(scope, receive, send)

        # Create routes
        routes: list[Route | Mount] = []
        middleware: list[Middleware] = []
        required_scopes = []

        # Set up auth if configured
        if self.settings.auth:
            required_scopes = self.settings.auth.required_scopes or []

            # Add auth middleware if token verifier is available
            if self._token_verifier:
                middleware = [
                    Middleware(
                        AuthenticationMiddleware,
                        backend=BearerAuthBackend(self._token_verifier),
                    ),
                    Middleware(AuthContextMiddleware),
                ]

            # Add auth endpoints if auth server provider is configured
            if self._auth_server_provider:
                from mcp.server.auth.routes import create_auth_routes

                routes.extend(
                    create_auth_routes(
                        provider=self._auth_server_provider,
                        issuer_url=self.settings.auth.issuer_url,
                        service_documentation_url=self.settings.auth.service_documentation_url,
                        client_registration_options=self.settings.auth.client_registration_options,
                        revocation_options=self.settings.auth.revocation_options,
                    )
                )

        # Set up routes with or without auth
        if self._token_verifier:
            # Determine resource metadata URL
            resource_metadata_url = None
            if self.settings.auth and self.settings.auth.resource_server_url:
                from pydantic import AnyHttpUrl

                resource_metadata_url = AnyHttpUrl(
                    str(self.settings.auth.resource_server_url).rstrip("/") + "/.well-known/oauth-protected-resource"
                )

            routes.append(
                Mount(
                    self.settings.streamable_http_path,
                    app=RequireAuthMiddleware(handle_streamable_http, required_scopes, resource_metadata_url),
                )
            )
        else:
            # Auth is disabled, no wrapper needed
            routes.append(
                Mount(
                    self.settings.streamable_http_path,
                    app=handle_streamable_http,
                )
            )

        # Add protected resource metadata endpoint if configured as RS
        if self.settings.auth and self.settings.auth.resource_server_url:
            from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
            from mcp.server.auth.routes import cors_middleware
            from mcp.shared.auth import ProtectedResourceMetadata

            protected_resource_metadata = ProtectedResourceMetadata(
                resource=self.settings.auth.resource_server_url,
                authorization_servers=[self.settings.auth.issuer_url],
                scopes_supported=self.settings.auth.required_scopes,
            )
            routes.append(
                Route(
                    "/.well-known/oauth-protected-resource",
                    endpoint=cors_middleware(
                        ProtectedResourceMetadataHandler(protected_resource_metadata).handle,
                        ["GET", "OPTIONS"],
                    ),
                    methods=["GET", "OPTIONS"],
                )
            )

        routes.extend(self._custom_starlette_routes)

        return Starlette(
            debug=self.settings.debug,
            routes=routes,
            middleware=middleware,
            lifespan=lambda app: self.session_manager.run(),
        )

    async def list_prompts(self) -> list[MCPPrompt]:
        """List all available prompts."""
        prompts = self._prompt_manager.list_prompts()
        return [
            MCPPrompt(
                name=prompt.name,
                title=prompt.title,
                description=prompt.description,
                arguments=[
                    MCPPromptArgument(
                        name=arg.name,
                        description=arg.description,
                        required=arg.required,
                    )
                    for arg in (prompt.arguments or [])
                ],
            )
            for prompt in prompts
        ]

    async def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> GetPromptResult:
        """Get a prompt by name with arguments."""
        try:
            messages = await self._prompt_manager.render_prompt(name, arguments)

            return GetPromptResult(messages=pydantic_core.to_jsonable_python(messages))
        except Exception as e:
            logger.error(f"Error getting prompt {name}: {e}")
            raise ValueError(str(e))

## Context

**Type**: Class

**Description**: class Context(BaseModel, Generic[ServerSessionT, LifespanContextT, RequestT]):
    """Context object providing access to MCP capabilities.

    This provides a cleaner interface to MCP's RequestContext functionality.
    It gets injected into tool and resource functions that request it via type hints.

    To use context in a tool function, add a parameter with the Context type annotation:

    ```python
    @server.tool()
    def my_tool(x: int, ctx: Context) -> str:
        # Log messages to the client
        ctx.info(f"Processing {x}")
        ctx.debug("Debug info")
        ctx.warning("Warning message")
        ctx.error("Error message")

        # Report progress
        ctx.report_progress(50, 100)

        # Access resources
        data = ctx.read_resource("resource://data")

        # Get request info
        request_id = ctx.request_id
        client_id = ctx.client_id

        return str(x)
    ```

    The context parameter name can be anything as long as it's annotated with Context.
    The context is optional - tools that don't need it can omit the parameter.
    """

    _request_context: RequestContext[ServerSessionT, LifespanContextT, RequestT] | None
    _fastmcp: FastMCP | None

    def __init__(
        self,
        *,
        request_context: (RequestContext[ServerSessionT, LifespanContextT, RequestT] | None) = None,
        fastmcp: FastMCP | None = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._request_context = request_context
        self._fastmcp = fastmcp

    @property
    def fastmcp(self) -> FastMCP:
        """Access to the FastMCP server."""
        if self._fastmcp is None:
            raise ValueError("Context is not available outside of a request")
        return self._fastmcp

    @property
    def request_context(
        self,
    ) -> RequestContext[ServerSessionT, LifespanContextT, RequestT]:
        """Access to the underlying request context."""
        if self._request_context is None:
            raise ValueError("Context is not available outside of a request")
        return self._request_context

    async def report_progress(self, progress: float, total: float | None = None, message: str | None = None) -> None:
        """Report progress for the current operation.

        Args:
            progress: Current progress value e.g. 24
            total: Optional total value e.g. 100
            message: Optional message e.g. Starting render...
        """
        progress_token = self.request_context.meta.progressToken if self.request_context.meta else None

        if progress_token is None:
            return

        await self.request_context.session.send_progress_notification(
            progress_token=progress_token,
            progress=progress,
            total=total,
            message=message,
        )

    async def read_resource(self, uri: str | AnyUrl) -> Iterable[ReadResourceContents]:
        """Read a resource by URI.

        Args:
            uri: Resource URI to read

        Returns:
            The resource content as either text or bytes
        """
        assert self._fastmcp is not None, "Context is not available outside of a request"
        return await self._fastmcp.read_resource(uri)

    async def elicit(
        self,
        message: str,
        schema: type[ElicitSchemaModelT],
    ) -> ElicitationResult[ElicitSchemaModelT]:
        """Elicit information from the client/user.

        This method can be used to interactively ask for additional information from the
        client within a tool's execution. The client might display the message to the
        user and collect a response according to the provided schema. Or in case a
        client is an agent, it might decide how to handle the elicitation -- either by asking
        the user or automatically generating a response.

        Args:
            schema: A Pydantic model class defining the expected response structure, according to the specification,
                    only primive types are allowed.
            message: Optional message to present to the user. If not provided, will use
                    a default message based on the schema

        Returns:
            An ElicitationResult containing the action taken and the data if accepted

        Note:
            Check the result.action to determine if the user accepted, declined, or cancelled.
            The result.data will only be populated if action is "accept" and validation succeeded.
        """

        return await elicit_with_validation(
            session=self.request_context.session, message=message, schema=schema, related_request_id=self.request_id
        )

    async def log(
        self,
        level: Literal["debug", "info", "warning", "error"],
        message: str,
        *,
        logger_name: str | None = None,
    ) -> None:
        """Send a log message to the client.

        Args:
            level: Log level (debug, info, warning, error)
            message: Log message
            logger_name: Optional logger name
            **extra: Additional structured data to include
        """
        await self.request_context.session.send_log_message(
            level=level,
            data=message,
            logger=logger_name,
            related_request_id=self.request_id,
        )

    @property
    def client_id(self) -> str | None:
        """Get the client ID if available."""
        return getattr(self.request_context.meta, "client_id", None) if self.request_context.meta else None

    @property
    def request_id(self) -> str:
        """Get the unique ID for this request."""
        return str(self.request_context.request_id)

    @property
    def session(self):
        """Access to the underlying session for advanced usage."""
        return self.request_context.session

    # Convenience methods for common log levels
    async def debug(self, message: str, **extra: Any) -> None:
        """Send a debug log message."""
        await self.log("debug", message, **extra)

    async def info(self, message: str, **extra: Any) -> None:
        """Send an info log message."""
        await self.log("info", message, **extra)

    async def warning(self, message: str, **extra: Any) -> None:
        """Send a warning log message."""
        await self.log("warning", message, **extra)

    async def error(self, message: str, **extra: Any) -> None:
        """Send an error log message."""
        await self.log("error", message, **extra)

## Message

**Type**: Class

**Description**: class Message(BaseModel):
    """Base class for all prompt messages."""

    role: Literal["user", "assistant"]
    content: ContentBlock

    def __init__(self, content: str | ContentBlock, **kwargs: Any):
        if isinstance(content, str):
            content = TextContent(type="text", text=content)
        super().__init__(content=content, **kwargs)

## UserMessage

**Type**: Class

**Description**: class UserMessage(Message):
    """A message from the user."""

    role: Literal["user", "assistant"] = "user"

    def __init__(self, content: str | ContentBlock, **kwargs: Any):
        super().__init__(content=content, **kwargs)

## AssistantMessage

**Type**: Class

**Description**: class AssistantMessage(Message):
    """A message from the assistant."""

    role: Literal["user", "assistant"] = "assistant"

    def __init__(self, content: str | ContentBlock, **kwargs: Any):
        super().__init__(content=content, **kwargs)

## PromptArgument

**Type**: Class

**Description**: class PromptArgument(BaseModel):
    """An argument that can be passed to a prompt."""

    name: str = Field(description="Name of the argument")
    description: str | None = Field(None, description="Description of what the argument does")
    required: bool = Field(default=False, description="Whether the argument is required")

## Prompt

**Type**: Class

**Description**: class Prompt(BaseModel):
    """A prompt template that can be rendered with parameters."""

    name: str = Field(description="Name of the prompt")
    title: str | None = Field(None, description="Human-readable title of the prompt")
    description: str | None = Field(None, description="Description of what the prompt does")
    arguments: list[PromptArgument] | None = Field(None, description="Arguments that can be passed to the prompt")
    fn: Callable[..., PromptResult | Awaitable[PromptResult]] = Field(exclude=True)

    @classmethod
    def from_function(
        cls,
        fn: Callable[..., PromptResult | Awaitable[PromptResult]],
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
    ) -> "Prompt":
        """Create a Prompt from a function.

        The function can return:
        - A string (converted to a message)
        - A Message object
        - A dict (converted to a message)
        - A sequence of any of the above
        """
        func_name = name or fn.__name__

        if func_name == "<lambda>":
            raise ValueError("You must provide a name for lambda functions")

        # Get schema from TypeAdapter - will fail if function isn't properly typed
        parameters = TypeAdapter(fn).json_schema()

        # Convert parameters to PromptArguments
        arguments: list[PromptArgument] = []
        if "properties" in parameters:
            for param_name, param in parameters["properties"].items():
                required = param_name in parameters.get("required", [])
                arguments.append(
                    PromptArgument(
                        name=param_name,
                        description=param.get("description"),
                        required=required,
                    )
                )

        # ensure the arguments are properly cast
        fn = validate_call(fn)

        return cls(
            name=func_name,
            title=title,
            description=description or fn.__doc__ or "",
            arguments=arguments,
            fn=fn,
        )

    async def render(self, arguments: dict[str, Any] | None = None) -> list[Message]:
        """Render the prompt with arguments."""
        # Validate required arguments
        if self.arguments:
            required = {arg.name for arg in self.arguments if arg.required}
            provided = set(arguments or {})
            missing = required - provided
            if missing:
                raise ValueError(f"Missing required arguments: {missing}")

        try:
            # Call function and check if result is a coroutine
            result = self.fn(**(arguments or {}))
            if inspect.iscoroutine(result):
                result = await result

            # Validate messages
            if not isinstance(result, list | tuple):
                result = [result]

            # Convert result to messages
            messages: list[Message] = []
            for msg in result:  # type: ignore[reportUnknownVariableType]
                try:
                    if isinstance(msg, Message):
                        messages.append(msg)
                    elif isinstance(msg, dict):
                        messages.append(message_validator.validate_python(msg))
                    elif isinstance(msg, str):
                        content = TextContent(type="text", text=msg)
                        messages.append(UserMessage(content=content))
                    else:
                        content = pydantic_core.to_json(msg, fallback=str, indent=2).decode()
                        messages.append(Message(role="user", content=content))
                except Exception:
                    raise ValueError(f"Could not convert prompt result to message: {msg}")

            return messages
        except Exception as e:
            raise ValueError(f"Error rendering prompt {self.name}: {e}")

## PromptManager

**Type**: Class

**Description**: class PromptManager:
    """Manages FastMCP prompts."""

    def __init__(self, warn_on_duplicate_prompts: bool = True):
        self._prompts: dict[str, Prompt] = {}
        self.warn_on_duplicate_prompts = warn_on_duplicate_prompts

    def get_prompt(self, name: str) -> Prompt | None:
        """Get prompt by name."""
        return self._prompts.get(name)

    def list_prompts(self) -> list[Prompt]:
        """List all registered prompts."""
        return list(self._prompts.values())

    def add_prompt(
        self,
        prompt: Prompt,
    ) -> Prompt:
        """Add a prompt to the manager."""

        # Check for duplicates
        existing = self._prompts.get(prompt.name)
        if existing:
            if self.warn_on_duplicate_prompts:
                logger.warning(f"Prompt already exists: {prompt.name}")
            return existing

        self._prompts[prompt.name] = prompt
        return prompt

    async def render_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> list[Message]:
        """Render a prompt by name with arguments."""
        prompt = self.get_prompt(name)
        if not prompt:
            raise ValueError(f"Unknown prompt: {name}")

        return await prompt.render(arguments)

## PromptManager

**Type**: Class

**Description**: class PromptManager:
    """Manages FastMCP prompts."""

    def __init__(self, warn_on_duplicate_prompts: bool = True):
        self._prompts: dict[str, Prompt] = {}
        self.warn_on_duplicate_prompts = warn_on_duplicate_prompts

    def add_prompt(self, prompt: Prompt) -> Prompt:
        """Add a prompt to the manager."""
        logger.debug(f"Adding prompt: {prompt.name}")
        existing = self._prompts.get(prompt.name)
        if existing:
            if self.warn_on_duplicate_prompts:
                logger.warning(f"Prompt already exists: {prompt.name}")
            return existing
        self._prompts[prompt.name] = prompt
        return prompt

    def get_prompt(self, name: str) -> Prompt | None:
        """Get prompt by name."""
        return self._prompts.get(name)

    def list_prompts(self) -> list[Prompt]:
        """List all registered prompts."""
        return list(self._prompts.values())

## Resource

**Type**: Class

**Description**: class Resource(BaseModel, abc.ABC):
    """Base class for all resources."""

    model_config = ConfigDict(validate_default=True)

    uri: Annotated[AnyUrl, UrlConstraints(host_required=False)] = Field(default=..., description="URI of the resource")
    name: str | None = Field(description="Name of the resource", default=None)
    title: str | None = Field(description="Human-readable title of the resource", default=None)
    description: str | None = Field(description="Description of the resource", default=None)
    mime_type: str = Field(
        default="text/plain",
        description="MIME type of the resource content",
        pattern=r"^[a-zA-Z0-9]+/[a-zA-Z0-9\-+.]+$",
    )

    @field_validator("name", mode="before")
    @classmethod
    def set_default_name(cls, name: str | None, info: ValidationInfo) -> str:
        """Set default name from URI if not provided."""
        if name:
            return name
        if uri := info.data.get("uri"):
            return str(uri)
        raise ValueError("Either name or uri must be provided")

    @abc.abstractmethod
    async def read(self) -> str | bytes:
        """Read the resource content."""
        pass

## ResourceManager

**Type**: Class

**Description**: class ResourceManager:
    """Manages FastMCP resources."""

    def __init__(self, warn_on_duplicate_resources: bool = True):
        self._resources: dict[str, Resource] = {}
        self._templates: dict[str, ResourceTemplate] = {}
        self.warn_on_duplicate_resources = warn_on_duplicate_resources

    def add_resource(self, resource: Resource) -> Resource:
        """Add a resource to the manager.

        Args:
            resource: A Resource instance to add

        Returns:
            The added resource. If a resource with the same URI already exists,
            returns the existing resource.
        """
        logger.debug(
            "Adding resource",
            extra={
                "uri": resource.uri,
                "type": type(resource).__name__,
                "resource_name": resource.name,
            },
        )
        existing = self._resources.get(str(resource.uri))
        if existing:
            if self.warn_on_duplicate_resources:
                logger.warning(f"Resource already exists: {resource.uri}")
            return existing
        self._resources[str(resource.uri)] = resource
        return resource

    def add_template(
        self,
        fn: Callable[..., Any],
        uri_template: str,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        mime_type: str | None = None,
    ) -> ResourceTemplate:
        """Add a template from a function."""
        template = ResourceTemplate.from_function(
            fn,
            uri_template=uri_template,
            name=name,
            title=title,
            description=description,
            mime_type=mime_type,
        )
        self._templates[template.uri_template] = template
        return template

    async def get_resource(self, uri: AnyUrl | str) -> Resource | None:
        """Get resource by URI, checking concrete resources first, then templates."""
        uri_str = str(uri)
        logger.debug("Getting resource", extra={"uri": uri_str})

        # First check concrete resources
        if resource := self._resources.get(uri_str):
            return resource

        # Then check templates
        for template in self._templates.values():
            if params := template.matches(uri_str):
                try:
                    return await template.create_resource(uri_str, params)
                except Exception as e:
                    raise ValueError(f"Error creating resource from template: {e}")

        raise ValueError(f"Unknown resource: {uri}")

    def list_resources(self) -> list[Resource]:
        """List all registered resources."""
        logger.debug("Listing resources", extra={"count": len(self._resources)})
        return list(self._resources.values())

    def list_templates(self) -> list[ResourceTemplate]:
        """List all registered templates."""
        logger.debug("Listing templates", extra={"count": len(self._templates)})
        return list(self._templates.values())

## ResourceTemplate

**Type**: Class

**Description**: class ResourceTemplate(BaseModel):
    """A template for dynamically creating resources."""

    uri_template: str = Field(description="URI template with parameters (e.g. weather://{city}/current)")
    name: str = Field(description="Name of the resource")
    title: str | None = Field(description="Human-readable title of the resource", default=None)
    description: str | None = Field(description="Description of what the resource does")
    mime_type: str = Field(default="text/plain", description="MIME type of the resource content")
    fn: Callable[..., Any] = Field(exclude=True)
    parameters: dict[str, Any] = Field(description="JSON schema for function parameters")

    @classmethod
    def from_function(
        cls,
        fn: Callable[..., Any],
        uri_template: str,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        mime_type: str | None = None,
    ) -> ResourceTemplate:
        """Create a template from a function."""
        func_name = name or fn.__name__
        if func_name == "<lambda>":
            raise ValueError("You must provide a name for lambda functions")

        # Get schema from TypeAdapter - will fail if function isn't properly typed
        parameters = TypeAdapter(fn).json_schema()

        # ensure the arguments are properly cast
        fn = validate_call(fn)

        return cls(
            uri_template=uri_template,
            name=func_name,
            title=title,
            description=description or fn.__doc__ or "",
            mime_type=mime_type or "text/plain",
            fn=fn,
            parameters=parameters,
        )

    def matches(self, uri: str) -> dict[str, Any] | None:
        """Check if URI matches template and extract parameters."""
        # Convert template to regex pattern
        pattern = self.uri_template.replace("{", "(?P<").replace("}", ">[^/]+)")
        match = re.match(f"^{pattern}$", uri)
        if match:
            return match.groupdict()
        return None

    async def create_resource(self, uri: str, params: dict[str, Any]) -> Resource:
        """Create a resource from the template with the given parameters."""
        try:
            # Call function and check if result is a coroutine
            result = self.fn(**params)
            if inspect.iscoroutine(result):
                result = await result

            return FunctionResource(
                uri=uri,  # type: ignore
                name=self.name,
                title=self.title,
                description=self.description,
                mime_type=self.mime_type,
                fn=lambda: result,  # Capture result in closure
            )
        except Exception as e:
            raise ValueError(f"Error creating resource from template: {e}")

## TextResource

**Type**: Class

**Description**: class TextResource(Resource):
    """A resource that reads from a string."""

    text: str = Field(description="Text content of the resource")

    async def read(self) -> str:
        """Read the text content."""
        return self.text

## BinaryResource

**Type**: Class

**Description**: class BinaryResource(Resource):
    """A resource that reads from bytes."""

    data: bytes = Field(description="Binary content of the resource")

    async def read(self) -> bytes:
        """Read the binary content."""
        return self.data

## FunctionResource

**Type**: Class

**Description**: class FunctionResource(Resource):
    """A resource that defers data loading by wrapping a function.

    The function is only called when the resource is read, allowing for lazy loading
    of potentially expensive data. This is particularly useful when listing resources,
    as the function won't be called until the resource is actually accessed.

    The function can return:
    - str for text content (default)
    - bytes for binary content
    - other types will be converted to JSON
    """

    fn: Callable[[], Any] = Field(exclude=True)

    async def read(self) -> str | bytes:
        """Read the resource by calling the wrapped function."""
        try:
            result = await self.fn() if inspect.iscoroutinefunction(self.fn) else self.fn()
            if isinstance(result, Resource):
                return await result.read()
            elif isinstance(result, bytes):
                return result
            elif isinstance(result, str):
                return result
            else:
                return pydantic_core.to_json(result, fallback=str, indent=2).decode()
        except Exception as e:
            raise ValueError(f"Error reading resource {self.uri}: {e}")

    @classmethod
    def from_function(
        cls,
        fn: Callable[..., Any],
        uri: str,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        mime_type: str | None = None,
    ) -> "FunctionResource":
        """Create a FunctionResource from a function."""
        func_name = name or fn.__name__
        if func_name == "<lambda>":
            raise ValueError("You must provide a name for lambda functions")

        # ensure the arguments are properly cast
        fn = validate_call(fn)

        return cls(
            uri=AnyUrl(uri),
            name=func_name,
            title=title,
            description=description or fn.__doc__ or "",
            mime_type=mime_type or "text/plain",
            fn=fn,
        )

## FileResource

**Type**: Class

**Description**: class FileResource(Resource):
    """A resource that reads from a file.

    Set is_binary=True to read file as binary data instead of text.
    """

    path: Path = Field(description="Path to the file")
    is_binary: bool = Field(
        default=False,
        description="Whether to read the file as binary data",
    )
    mime_type: str = Field(
        default="text/plain",
        description="MIME type of the resource content",
    )

    @pydantic.field_validator("path")
    @classmethod
    def validate_absolute_path(cls, path: Path) -> Path:
        """Ensure path is absolute."""
        if not path.is_absolute():
            raise ValueError("Path must be absolute")
        return path

    @pydantic.field_validator("is_binary")
    @classmethod
    def set_binary_from_mime_type(cls, is_binary: bool, info: ValidationInfo) -> bool:
        """Set is_binary based on mime_type if not explicitly set."""
        if is_binary:
            return True
        mime_type = info.data.get("mime_type", "text/plain")
        return not mime_type.startswith("text/")

    async def read(self) -> str | bytes:
        """Read the file content."""
        try:
            if self.is_binary:
                return await anyio.to_thread.run_sync(self.path.read_bytes)
            return await anyio.to_thread.run_sync(self.path.read_text)
        except Exception as e:
            raise ValueError(f"Error reading file {self.path}: {e}")

## HttpResource

**Type**: Class

**Description**: class HttpResource(Resource):
    """A resource that reads from an HTTP endpoint."""

    url: str = Field(description="URL to fetch content from")
    mime_type: str = Field(default="application/json", description="MIME type of the resource content")

    async def read(self) -> str | bytes:
        """Read the HTTP content."""
        async with httpx.AsyncClient() as client:
            response = await client.get(self.url)
            response.raise_for_status()
            return response.text

## DirectoryResource

**Type**: Class

**Description**: class DirectoryResource(Resource):
    """A resource that lists files in a directory."""

    path: Path = Field(description="Path to the directory")
    recursive: bool = Field(default=False, description="Whether to list files recursively")
    pattern: str | None = Field(default=None, description="Optional glob pattern to filter files")
    mime_type: str = Field(default="application/json", description="MIME type of the resource content")

    @pydantic.field_validator("path")
    @classmethod
    def validate_absolute_path(cls, path: Path) -> Path:
        """Ensure path is absolute."""
        if not path.is_absolute():
            raise ValueError("Path must be absolute")
        return path

    def list_files(self) -> list[Path]:
        """List files in the directory."""
        if not self.path.exists():
            raise FileNotFoundError(f"Directory not found: {self.path}")
        if not self.path.is_dir():
            raise NotADirectoryError(f"Not a directory: {self.path}")

        try:
            if self.pattern:
                return list(self.path.glob(self.pattern)) if not self.recursive else list(self.path.rglob(self.pattern))
            return list(self.path.glob("*")) if not self.recursive else list(self.path.rglob("*"))
        except Exception as e:
            raise ValueError(f"Error listing directory {self.path}: {e}")

    async def read(self) -> str:  # Always returns JSON string
        """Read the directory listing."""
        try:
            files = await anyio.to_thread.run_sync(self.list_files)
            file_list = [str(f.relative_to(self.path)) for f in files if f.is_file()]
            return json.dumps({"files": file_list}, indent=2)
        except Exception as e:
            raise ValueError(f"Error reading directory {self.path}: {e}")

## Tool

**Type**: Class

**Description**: class Tool(BaseModel):
    """Internal tool registration info."""

    fn: Callable[..., Any] = Field(exclude=True)
    name: str = Field(description="Name of the tool")
    title: str | None = Field(None, description="Human-readable title of the tool")
    description: str = Field(description="Description of what the tool does")
    parameters: dict[str, Any] = Field(description="JSON schema for tool parameters")
    fn_metadata: FuncMetadata = Field(
        description="Metadata about the function including a pydantic model for tool" " arguments"
    )
    is_async: bool = Field(description="Whether the tool is async")
    context_kwarg: str | None = Field(None, description="Name of the kwarg that should receive context")
    annotations: ToolAnnotations | None = Field(None, description="Optional annotations for the tool")

    @cached_property
    def output_schema(self) -> dict[str, Any] | None:
        return self.fn_metadata.output_schema

    @classmethod
    def from_function(
        cls,
        fn: Callable[..., Any],
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        context_kwarg: str | None = None,
        annotations: ToolAnnotations | None = None,
        structured_output: bool | None = None,
    ) -> Tool:
        """Create a Tool from a function."""
        from mcp.server.fastmcp.server import Context

        func_name = name or fn.__name__

        if func_name == "<lambda>":
            raise ValueError("You must provide a name for lambda functions")

        func_doc = description or fn.__doc__ or ""
        is_async = _is_async_callable(fn)

        if context_kwarg is None:
            sig = inspect.signature(fn)
            for param_name, param in sig.parameters.items():
                if get_origin(param.annotation) is not None:
                    continue
                if issubclass(param.annotation, Context):
                    context_kwarg = param_name
                    break

        func_arg_metadata = func_metadata(
            fn,
            skip_names=[context_kwarg] if context_kwarg is not None else [],
            structured_output=structured_output,
        )
        parameters = func_arg_metadata.arg_model.model_json_schema()

        return cls(
            fn=fn,
            name=func_name,
            title=title,
            description=func_doc,
            parameters=parameters,
            fn_metadata=func_arg_metadata,
            is_async=is_async,
            context_kwarg=context_kwarg,
            annotations=annotations,
        )

    async def run(
        self,
        arguments: dict[str, Any],
        context: Context[ServerSessionT, LifespanContextT, RequestT] | None = None,
        convert_result: bool = False,
    ) -> Any:
        """Run the tool with arguments."""
        try:
            result = await self.fn_metadata.call_fn_with_arg_validation(
                self.fn,
                self.is_async,
                arguments,
                {self.context_kwarg: context} if self.context_kwarg is not None else None,
            )

            if convert_result:
                result = self.fn_metadata.convert_result(result)

            return result
        except Exception as e:
            raise ToolError(f"Error executing tool {self.name}: {e}") from e

## _is_async_callable

**Type**: Function

**Description**: def _is_async_callable(obj: Any) -> bool:
    while isinstance(obj, functools.partial):
        obj = obj.func

    return inspect.iscoroutinefunction(obj) or (
        callable(obj) and inspect.iscoroutinefunction(getattr(obj, "__call__", None))
    )

## ToolManager

**Type**: Class

**Description**: class ToolManager:
    """Manages FastMCP tools."""

    def __init__(
        self,
        warn_on_duplicate_tools: bool = True,
        *,
        tools: list[Tool] | None = None,
    ):
        self._tools: dict[str, Tool] = {}
        if tools is not None:
            for tool in tools:
                if warn_on_duplicate_tools and tool.name in self._tools:
                    logger.warning(f"Tool already exists: {tool.name}")
                self._tools[tool.name] = tool

        self.warn_on_duplicate_tools = warn_on_duplicate_tools

    def get_tool(self, name: str) -> Tool | None:
        """Get tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[Tool]:
        """List all registered tools."""
        return list(self._tools.values())

    def add_tool(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | None = None,
        structured_output: bool | None = None,
    ) -> Tool:
        """Add a tool to the server."""
        tool = Tool.from_function(
            fn,
            name=name,
            title=title,
            description=description,
            annotations=annotations,
            structured_output=structured_output,
        )
        existing = self._tools.get(tool.name)
        if existing:
            if self.warn_on_duplicate_tools:
                logger.warning(f"Tool already exists: {tool.name}")
            return existing
        self._tools[tool.name] = tool
        return tool

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context: Context[ServerSessionT, LifespanContextT, RequestT] | None = None,
        convert_result: bool = False,
    ) -> Any:
        """Call a tool by name with arguments."""
        tool = self.get_tool(name)
        if not tool:
            raise ToolError(f"Unknown tool: {name}")

        return await tool.run(arguments, context=context, convert_result=convert_result)

## StrictJsonSchema

**Type**: Class

**Description**: class StrictJsonSchema(GenerateJsonSchema):
    """A JSON schema generator that raises exceptions instead of emitting warnings.

    This is used to detect non-serializable types during schema generation.
    """

    def emit_warning(self, kind: JsonSchemaWarningKind, detail: str) -> None:
        # Raise an exception instead of emitting a warning
        raise ValueError(f"JSON schema warning: {kind} - {detail}")

## ArgModelBase

**Type**: Class

**Description**: class ArgModelBase(BaseModel):
    """A model representing the arguments to a function."""

    def model_dump_one_level(self) -> dict[str, Any]:
        """Return a dict of the model's fields, one level deep.

        That is, sub-models etc are not dumped - they are kept as pydantic models.
        """
        kwargs: dict[str, Any] = {}
        for field_name in self.__class__.model_fields.keys():
            kwargs[field_name] = getattr(self, field_name)
        return kwargs

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
    )

## FuncMetadata

**Type**: Class

**Description**: class FuncMetadata(BaseModel):
    arg_model: Annotated[type[ArgModelBase], WithJsonSchema(None)]
    output_schema: dict[str, Any] | None = None
    output_model: Annotated[type[BaseModel], WithJsonSchema(None)] | None = None
    wrap_output: bool = False

    async def call_fn_with_arg_validation(
        self,
        fn: Callable[..., Any | Awaitable[Any]],
        fn_is_async: bool,
        arguments_to_validate: dict[str, Any],
        arguments_to_pass_directly: dict[str, Any] | None,
    ) -> Any:
        """Call the given function with arguments validated and injected.

        Arguments are first attempted to be parsed from JSON, then validated against
        the argument model, before being passed to the function.
        """
        arguments_pre_parsed = self.pre_parse_json(arguments_to_validate)
        arguments_parsed_model = self.arg_model.model_validate(arguments_pre_parsed)
        arguments_parsed_dict = arguments_parsed_model.model_dump_one_level()

        arguments_parsed_dict |= arguments_to_pass_directly or {}

        if fn_is_async:
            return await fn(**arguments_parsed_dict)
        else:
            return fn(**arguments_parsed_dict)

    def convert_result(self, result: Any) -> Any:
        """
        Convert the result of a function call to the appropriate format for
         the lowlevel server tool call handler:

        - If output_model is None, return the unstructured content directly.
        - If output_model is not None, convert the result to structured output format
            (dict[str, Any]) and return both unstructured and structured content.

        Note: we return unstructured content here **even though the lowlevel server
        tool call handler provides generic backwards compatibility serialization of
        structured content**. This is for FastMCP backwards compatibility: we need to
        retain FastMCP's ad hoc conversion logic for constructing unstructured output
        from function return values, whereas the lowlevel server simply serializes
        the structured output.
        """
        unstructured_content = _convert_to_content(result)

        if self.output_schema is None:
            return unstructured_content
        else:
            if self.wrap_output:
                result = {"result": result}

            assert self.output_model is not None, "Output model must be set if output schema is defined"
            validated = self.output_model.model_validate(result)
            structured_content = validated.model_dump(mode="json")

            return (unstructured_content, structured_content)

    def pre_parse_json(self, data: dict[str, Any]) -> dict[str, Any]:
        """Pre-parse data from JSON.

        Return a dict with same keys as input but with values parsed from JSON
        if appropriate.

        This is to handle cases like `["a", "b", "c"]` being passed in as JSON inside
        a string rather than an actual list. Claude desktop is prone to this - in fact
        it seems incapable of NOT doing this. For sub-models, it tends to pass
        dicts (JSON objects) as JSON strings, which can be pre-parsed here.
        """
        new_data = data.copy()  # Shallow copy
        for field_name in self.arg_model.model_fields.keys():
            if field_name not in data.keys():
                continue
            if isinstance(data[field_name], str):
                try:
                    pre_parsed = json.loads(data[field_name])
                except json.JSONDecodeError:
                    continue  # Not JSON - skip
                if isinstance(pre_parsed, str | int | float):
                    # This is likely that the raw value is e.g. `"hello"` which we
                    # Should really be parsed as '"hello"' in Python - but if we parse
                    # it as JSON it'll turn into just 'hello'. So we skip it.
                    continue
                new_data[field_name] = pre_parsed
        assert new_data.keys() == data.keys()
        return new_data

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
    )

## func_metadata

**Type**: Function

**Description**: def func_metadata(
    func: Callable[..., Any],
    skip_names: Sequence[str] = (),
    structured_output: bool | None = None,
) -> FuncMetadata:
    """Given a function, return metadata including a pydantic model representing its
    signature.

    The use case for this is
    ```
    meta = func_metadata(func)
    validated_args = meta.arg_model.model_validate(some_raw_data_dict)
    return func(**validated_args.model_dump_one_level())
    ```

    **critically** it also provides pre-parse helper to attempt to parse things from
    JSON.

    Args:
        func: The function to convert to a pydantic model
        skip_names: A list of parameter names to skip. These will not be included in
            the model.
        structured_output: Controls whether the tool's output is structured or unstructured
            - If None, auto-detects based on the function's return type annotation
            - If True, unconditionally creates a structured tool (return type annotation permitting)
            - If False, unconditionally creates an unstructured tool

        If structured, creates a Pydantic model for the function's result based on its annotation.
        Supports various return types:
            - BaseModel subclasses (used directly)
            - Primitive types (str, int, float, bool, bytes, None) - wrapped in a
                model with a 'result' field
            - TypedDict - converted to a Pydantic model with same fields
            - Dataclasses and other annotated classes - converted to Pydantic models
            - Generic types (list, dict, Union, etc.) - wrapped in a model with a 'result' field

    Returns:
        A FuncMetadata object containing:
        - arg_model: A pydantic model representing the function's arguments
        - output_model: A pydantic model for the return type if output is structured
        - output_conversion: Records how function output should be converted before returning.
    """
    sig = _get_typed_signature(func)
    params = sig.parameters
    dynamic_pydantic_model_params: dict[str, Any] = {}
    globalns = getattr(func, "__globals__", {})
    for param in params.values():
        if param.name.startswith("_"):
            raise InvalidSignature(f"Parameter {param.name} of {func.__name__} cannot start with '_'")
        if param.name in skip_names:
            continue
        annotation = param.annotation

        # `x: None` / `x: None = None`
        if annotation is None:
            annotation = Annotated[
                None,
                Field(default=param.default if param.default is not inspect.Parameter.empty else PydanticUndefined),
            ]

        # Untyped field
        if annotation is inspect.Parameter.empty:
            annotation = Annotated[
                Any,
                Field(),
                # 🤷
                WithJsonSchema({"title": param.name, "type": "string"}),
            ]

        field_info = FieldInfo.from_annotated_attribute(
            _get_typed_annotation(annotation, globalns),
            param.default if param.default is not inspect.Parameter.empty else PydanticUndefined,
        )
        dynamic_pydantic_model_params[param.name] = (field_info.annotation, field_info)
        continue

    arguments_model = create_model(
        f"{func.__name__}Arguments",
        **dynamic_pydantic_model_params,
        __base__=ArgModelBase,
    )

    if structured_output is False:
        return FuncMetadata(arg_model=arguments_model)

    # set up structured output support based on return type annotation

    if sig.return_annotation is inspect.Parameter.empty and structured_output is True:
        raise InvalidSignature(f"Function {func.__name__}: return annotation required for structured output")

    output_info = FieldInfo.from_annotation(_get_typed_annotation(sig.return_annotation, globalns))
    annotation = output_info.annotation

    output_model, output_schema, wrap_output = _try_create_model_and_schema(annotation, func.__name__, output_info)

    if output_model is None and structured_output is True:
        # Model creation failed or produced warnings - no structured output
        raise InvalidSignature(
            f"Function {func.__name__}: return type {annotation} is not serializable for structured output"
        )

    return FuncMetadata(
        arg_model=arguments_model,
        output_schema=output_schema,
        output_model=output_model,
        wrap_output=wrap_output,
    )

## _try_create_model_and_schema

**Type**: Function

**Description**: def _try_create_model_and_schema(
    annotation: Any, func_name: str, field_info: FieldInfo
) -> tuple[type[BaseModel] | None, dict[str, Any] | None, bool]:
    """Try to create a model and schema for the given annotation without warnings.

    Returns:
        tuple of (model or None, schema or None, wrap_output)
        Model and schema are None if warnings occur or creation fails.
        wrap_output is True if the result needs to be wrapped in {"result": ...}
    """
    model = None
    wrap_output = False

    # First handle special case: None
    if annotation is None:
        model = _create_wrapped_model(func_name, annotation, field_info)
        wrap_output = True

    # Handle GenericAlias types (list[str], dict[str, int], Union[str, int], etc.)
    elif isinstance(annotation, GenericAlias):
        origin = get_origin(annotation)

        # Special case: dict with string keys can use RootModel
        if origin is dict:
            args = get_args(annotation)
            if len(args) == 2 and args[0] is str:
                model = _create_dict_model(func_name, annotation)
            else:
                # dict with non-str keys needs wrapping
                model = _create_wrapped_model(func_name, annotation, field_info)
                wrap_output = True
        else:
            # All other generic types need wrapping (list, tuple, Union, Optional, etc.)
            model = _create_wrapped_model(func_name, annotation, field_info)
            wrap_output = True

    # Handle regular type objects
    elif isinstance(annotation, type):
        type_annotation: type[Any] = cast(type[Any], annotation)

        # Case 1: BaseModel subclasses (can be used directly)
        if issubclass(annotation, BaseModel):
            model = annotation

        # Case 2: TypedDict (special dict subclass with __annotations__)
        elif hasattr(type_annotation, "__annotations__") and issubclass(annotation, dict):
            model = _create_model_from_typeddict(type_annotation)

        # Case 3: Primitive types that need wrapping
        elif annotation in (str, int, float, bool, bytes, type(None)):
            model = _create_wrapped_model(func_name, annotation, field_info)
            wrap_output = True

        # Case 4: Other class types (dataclasses, regular classes with annotations)
        else:
            type_hints = get_type_hints(type_annotation)
            if type_hints:
                # Classes with type hints can be converted to Pydantic models
                model = _create_model_from_class(type_annotation)
            # Classes without type hints are not serializable - model remains None

    # Handle any other types not covered above
    else:
        # This includes typing constructs that aren't GenericAlias in Python 3.10
        # (e.g., Union, Optional in some Python versions)
        model = _create_wrapped_model(func_name, annotation, field_info)
        wrap_output = True

    if model:
        # If we successfully created a model, try to get its schema
        # Use StrictJsonSchema to raise exceptions instead of warnings
        try:
            schema = model.model_json_schema(schema_generator=StrictJsonSchema)
        except (TypeError, ValueError, pydantic_core.SchemaError, pydantic_core.ValidationError) as e:
            # These are expected errors when a type can't be converted to a Pydantic schema
            # TypeError: When Pydantic can't handle the type
            # ValueError: When there are issues with the type definition (including our custom warnings)
            # SchemaError: When Pydantic can't build a schema
            # ValidationError: When validation fails
            logger.info(f"Cannot create schema for type {annotation} in {func_name}: {type(e).__name__}: {e}")
            return None, None, False

        return model, schema, wrap_output

    return None, None, False

## _create_model_from_class

**Type**: Function

**Description**: def _create_model_from_class(cls: type[Any]) -> type[BaseModel]:
    """Create a Pydantic model from an ordinary class.

    The created model will:
    - Have the same name as the class
    - Have fields with the same names and types as the class's fields
    - Include all fields whose type does not include None in the set of required fields

    Precondition: cls must have type hints (i.e., get_type_hints(cls) is non-empty)
    """
    type_hints = get_type_hints(cls)

    model_fields: dict[str, Any] = {}
    for field_name, field_type in type_hints.items():
        if field_name.startswith("_"):
            continue

        default = getattr(cls, field_name, PydanticUndefined)
        field_info = FieldInfo.from_annotated_attribute(field_type, default)
        model_fields[field_name] = (field_info.annotation, field_info)

    # Create a base class with the config
    class BaseWithConfig(BaseModel):
        model_config = ConfigDict(from_attributes=True)

    return create_model(cls.__name__, **model_fields, __base__=BaseWithConfig)

## _create_model_from_typeddict

**Type**: Function

**Description**: def _create_model_from_typeddict(td_type: type[Any]) -> type[BaseModel]:
    """Create a Pydantic model from a TypedDict.

    The created model will have the same name and fields as the TypedDict.
    """
    type_hints = get_type_hints(td_type)
    required_keys = getattr(td_type, "__required_keys__", set(type_hints.keys()))

    model_fields: dict[str, Any] = {}
    for field_name, field_type in type_hints.items():
        field_info = FieldInfo.from_annotation(field_type)

        if field_name not in required_keys:
            # For optional TypedDict fields, set default=None
            # This makes them not required in the Pydantic model
            # The model should use exclude_unset=True when dumping to get TypedDict semantics
            field_info.default = None

        model_fields[field_name] = (field_info.annotation, field_info)

    return create_model(td_type.__name__, **model_fields, __base__=BaseModel)

## _create_wrapped_model

**Type**: Function

**Description**: def _create_wrapped_model(func_name: str, annotation: Any, field_info: FieldInfo) -> type[BaseModel]:
    """Create a model that wraps a type in a 'result' field.

    This is used for primitive types, generic types like list/dict, etc.
    """
    model_name = f"{func_name}Output"

    # Pydantic needs type(None) instead of None for the type annotation
    if annotation is None:
        annotation = type(None)

    return create_model(model_name, result=(annotation, field_info), __base__=BaseModel)

## _create_dict_model

**Type**: Function

**Description**: def _create_dict_model(func_name: str, dict_annotation: Any) -> type[BaseModel]:
    """Create a RootModel for dict[str, T] types."""

    class DictModel(RootModel[dict_annotation]):
        pass

    # Give it a meaningful name
    DictModel.__name__ = f"{func_name}DictOutput"
    DictModel.__qualname__ = f"{func_name}DictOutput"

    return DictModel

## _get_typed_annotation

**Type**: Function

**Description**: def _get_typed_annotation(annotation: Any, globalns: dict[str, Any]) -> Any:
    def try_eval_type(value: Any, globalns: dict[str, Any], localns: dict[str, Any]) -> tuple[Any, bool]:
        try:
            return eval_type_backport(value, globalns, localns), True
        except NameError:
            return value, False

    if isinstance(annotation, str):
        annotation = ForwardRef(annotation)
        annotation, status = try_eval_type(annotation, globalns, globalns)

        # This check and raise could perhaps be skipped, and we (FastMCP) just call
        # model_rebuild right before using it 🤷
        if status is False:
            raise InvalidSignature(f"Unable to evaluate type annotation {annotation}")

    return annotation

## _get_typed_signature

**Type**: Function

**Description**: def _get_typed_signature(call: Callable[..., Any]) -> inspect.Signature:
    """Get function signature while evaluating forward references"""
    signature = inspect.signature(call)
    globalns = getattr(call, "__globals__", {})
    typed_params = [
        inspect.Parameter(
            name=param.name,
            kind=param.kind,
            default=param.default,
            annotation=_get_typed_annotation(param.annotation, globalns),
        )
        for param in signature.parameters.values()
    ]
    typed_return = _get_typed_annotation(signature.return_annotation, globalns)
    typed_signature = inspect.Signature(typed_params, return_annotation=typed_return)
    return typed_signature

## _convert_to_content

**Type**: Function

**Description**: def _convert_to_content(
    result: Any,
) -> Sequence[ContentBlock]:
    """
    Convert a result to a sequence of content objects.

    Note: This conversion logic comes from previous versions of FastMCP and is being
    retained for purposes of backwards compatibility. It produces different unstructured
    output than the lowlevel server tool call handler, which just serializes structured
    content verbatim.
    """
    if result is None:
        return []

    if isinstance(result, ContentBlock):
        return [result]

    if isinstance(result, Image):
        return [result.to_image_content()]

    if isinstance(result, list | tuple):
        return list(
            chain.from_iterable(
                _convert_to_content(item)
                for item in result  # type: ignore
            )
        )

    if not isinstance(result, str):
        result = pydantic_core.to_json(result, fallback=str, indent=2).decode()

    return [TextContent(type="text", text=result)]

## get_logger

**Type**: Function

**Description**: def get_logger(name: str) -> logging.Logger:
    """Get a logger nested under MCPnamespace.

    Args:
        name: the name of the logger, which will be prefixed with 'FastMCP.'

    Returns:
        a configured logger instance
    """
    return logging.getLogger(name)

## configure_logging

**Type**: Function

**Description**: def configure_logging(
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO",
) -> None:
    """Configure logging for MCP.

    Args:
        level: the log level to use
    """
    handlers: list[logging.Handler] = []
    try:
        from rich.console import Console
        from rich.logging import RichHandler

        handlers.append(RichHandler(console=Console(stderr=True), rich_tracebacks=True))
    except ImportError:
        pass

    if not handlers:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=handlers,
    )

## Image

**Type**: Class

**Description**: class Image:
    """Helper class for returning images from tools."""

    def __init__(
        self,
        path: str | Path | None = None,
        data: bytes | None = None,
        format: str | None = None,
    ):
        if path is None and data is None:
            raise ValueError("Either path or data must be provided")
        if path is not None and data is not None:
            raise ValueError("Only one of path or data can be provided")

        self.path = Path(path) if path else None
        self.data = data
        self._format = format
        self._mime_type = self._get_mime_type()

    def _get_mime_type(self) -> str:
        """Get MIME type from format or guess from file extension."""
        if self._format:
            return f"image/{self._format.lower()}"

        if self.path:
            suffix = self.path.suffix.lower()
            return {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".gif": "image/gif",
                ".webp": "image/webp",
            }.get(suffix, "application/octet-stream")
        return "image/png"  # default for raw binary data

    def to_image_content(self) -> ImageContent:
        """Convert to MCP ImageContent."""
        if self.path:
            with open(self.path, "rb") as f:
                data = base64.b64encode(f.read()).decode()
        elif self.data is not None:
            data = base64.b64encode(self.data).decode()
        else:
            raise ValueError("No image data available")

        return ImageContent(type="image", data=data, mimeType=self._mime_type)

## NotificationOptions

**Type**: Class

**Description**: class NotificationOptions:
    def __init__(
        self,
        prompts_changed: bool = False,
        resources_changed: bool = False,
        tools_changed: bool = False,
    ):
        self.prompts_changed = prompts_changed
        self.resources_changed = resources_changed
        self.tools_changed = tools_changed

## Server

**Type**: Class

**Description**: class Server(Generic[LifespanResultT, RequestT]):
    def __init__(
        self,
        name: str,
        version: str | None = None,
        instructions: str | None = None,
        lifespan: Callable[
            [Server[LifespanResultT, RequestT]],
            AbstractAsyncContextManager[LifespanResultT],
        ] = lifespan,
    ):
        self.name = name
        self.version = version
        self.instructions = instructions
        self.lifespan = lifespan
        self.request_handlers: dict[type, Callable[..., Awaitable[types.ServerResult]]] = {
            types.PingRequest: _ping_handler,
        }
        self.notification_handlers: dict[type, Callable[..., Awaitable[None]]] = {}
        self.notification_options = NotificationOptions()
        self._tool_cache: dict[str, types.Tool] = {}
        logger.debug("Initializing server %r", name)

    def create_initialization_options(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        """Create initialization options from this server instance."""

        def pkg_version(package: str) -> str:
            try:
                from importlib.metadata import version

                return version(package)
            except Exception:
                pass

            return "unknown"

        return InitializationOptions(
            server_name=self.name,
            server_version=self.version if self.version else pkg_version("mcp"),
            capabilities=self.get_capabilities(
                notification_options or NotificationOptions(),
                experimental_capabilities or {},
            ),
            instructions=self.instructions,
        )

    def get_capabilities(
        self,
        notification_options: NotificationOptions,
        experimental_capabilities: dict[str, dict[str, Any]],
    ) -> types.ServerCapabilities:
        """Convert existing handlers to a ServerCapabilities object."""
        prompts_capability = None
        resources_capability = None
        tools_capability = None
        logging_capability = None

        # Set prompt capabilities if handler exists
        if types.ListPromptsRequest in self.request_handlers:
            prompts_capability = types.PromptsCapability(listChanged=notification_options.prompts_changed)

        # Set resource capabilities if handler exists
        if types.ListResourcesRequest in self.request_handlers:
            resources_capability = types.ResourcesCapability(
                subscribe=False, listChanged=notification_options.resources_changed
            )

        # Set tool capabilities if handler exists
        if types.ListToolsRequest in self.request_handlers:
            tools_capability = types.ToolsCapability(listChanged=notification_options.tools_changed)

        # Set logging capabilities if handler exists
        if types.SetLevelRequest in self.request_handlers:
            logging_capability = types.LoggingCapability()

        return types.ServerCapabilities(
            prompts=prompts_capability,
            resources=resources_capability,
            tools=tools_capability,
            logging=logging_capability,
            experimental=experimental_capabilities,
        )

    @property
    def request_context(
        self,
    ) -> RequestContext[ServerSession, LifespanResultT, RequestT]:
        """If called outside of a request context, this will raise a LookupError."""
        return request_ctx.get()

    def list_prompts(self):
        def decorator(func: Callable[[], Awaitable[list[types.Prompt]]]):
            logger.debug("Registering handler for PromptListRequest")

            async def handler(_: Any):
                prompts = await func()
                return types.ServerResult(types.ListPromptsResult(prompts=prompts))

            self.request_handlers[types.ListPromptsRequest] = handler
            return func

        return decorator

    def get_prompt(self):
        def decorator(
            func: Callable[[str, dict[str, str] | None], Awaitable[types.GetPromptResult]],
        ):
            logger.debug("Registering handler for GetPromptRequest")

            async def handler(req: types.GetPromptRequest):
                prompt_get = await func(req.params.name, req.params.arguments)
                return types.ServerResult(prompt_get)

            self.request_handlers[types.GetPromptRequest] = handler
            return func

        return decorator

    def list_resources(self):
        def decorator(func: Callable[[], Awaitable[list[types.Resource]]]):
            logger.debug("Registering handler for ListResourcesRequest")

            async def handler(_: Any):
                resources = await func()
                return types.ServerResult(types.ListResourcesResult(resources=resources))

            self.request_handlers[types.ListResourcesRequest] = handler
            return func

        return decorator

    def list_resource_templates(self):
        def decorator(func: Callable[[], Awaitable[list[types.ResourceTemplate]]]):
            logger.debug("Registering handler for ListResourceTemplatesRequest")

            async def handler(_: Any):
                templates = await func()
                return types.ServerResult(types.ListResourceTemplatesResult(resourceTemplates=templates))

            self.request_handlers[types.ListResourceTemplatesRequest] = handler
            return func

        return decorator

    def read_resource(self):
        def decorator(
            func: Callable[[AnyUrl], Awaitable[str | bytes | Iterable[ReadResourceContents]]],
        ):
            logger.debug("Registering handler for ReadResourceRequest")

            async def handler(req: types.ReadResourceRequest):
                result = await func(req.params.uri)

                def create_content(data: str | bytes, mime_type: str | None):
                    match data:
                        case str() as data:
                            return types.TextResourceContents(
                                uri=req.params.uri,
                                text=data,
                                mimeType=mime_type or "text/plain",
                            )
                        case bytes() as data:
                            import base64

                            return types.BlobResourceContents(
                                uri=req.params.uri,
                                blob=base64.b64encode(data).decode(),
                                mimeType=mime_type or "application/octet-stream",
                            )

                match result:
                    case str() | bytes() as data:
                        warnings.warn(
                            "Returning str or bytes from read_resource is deprecated. "
                            "Use Iterable[ReadResourceContents] instead.",
                            DeprecationWarning,
                            stacklevel=2,
                        )
                        content = create_content(data, None)
                    case Iterable() as contents:
                        contents_list = [
                            create_content(content_item.content, content_item.mime_type) for content_item in contents
                        ]
                        return types.ServerResult(
                            types.ReadResourceResult(
                                contents=contents_list,
                            )
                        )
                    case _:
                        raise ValueError(f"Unexpected return type from read_resource: {type(result)}")

                return types.ServerResult(
                    types.ReadResourceResult(
                        contents=[content],
                    )
                )

            self.request_handlers[types.ReadResourceRequest] = handler
            return func

        return decorator

    def set_logging_level(self):
        def decorator(func: Callable[[types.LoggingLevel], Awaitable[None]]):
            logger.debug("Registering handler for SetLevelRequest")

            async def handler(req: types.SetLevelRequest):
                await func(req.params.level)
                return types.ServerResult(types.EmptyResult())

            self.request_handlers[types.SetLevelRequest] = handler
            return func

        return decorator

    def subscribe_resource(self):
        def decorator(func: Callable[[AnyUrl], Awaitable[None]]):
            logger.debug("Registering handler for SubscribeRequest")

            async def handler(req: types.SubscribeRequest):
                await func(req.params.uri)
                return types.ServerResult(types.EmptyResult())

            self.request_handlers[types.SubscribeRequest] = handler
            return func

        return decorator

    def unsubscribe_resource(self):
        def decorator(func: Callable[[AnyUrl], Awaitable[None]]):
            logger.debug("Registering handler for UnsubscribeRequest")

            async def handler(req: types.UnsubscribeRequest):
                await func(req.params.uri)
                return types.ServerResult(types.EmptyResult())

            self.request_handlers[types.UnsubscribeRequest] = handler
            return func

        return decorator

    def list_tools(self):
        def decorator(func: Callable[[], Awaitable[list[types.Tool]]]):
            logger.debug("Registering handler for ListToolsRequest")

            async def handler(_: Any):
                tools = await func()
                # Refresh the tool cache
                self._tool_cache.clear()
                for tool in tools:
                    self._tool_cache[tool.name] = tool
                return types.ServerResult(types.ListToolsResult(tools=tools))

            self.request_handlers[types.ListToolsRequest] = handler
            return func

        return decorator

    def _make_error_result(self, error_message: str) -> types.ServerResult:
        """Create a ServerResult with an error CallToolResult."""
        return types.ServerResult(
            types.CallToolResult(
                content=[types.TextContent(type="text", text=error_message)],
                isError=True,
            )
        )

    async def _get_cached_tool_definition(self, tool_name: str) -> types.Tool | None:
        """Get tool definition from cache, refreshing if necessary.

        Returns the Tool object if found, None otherwise.
        """
        if tool_name not in self._tool_cache:
            if types.ListToolsRequest in self.request_handlers:
                logger.debug("Tool cache miss for %s, refreshing cache", tool_name)
                await self.request_handlers[types.ListToolsRequest](None)

        tool = self._tool_cache.get(tool_name)
        if tool is None:
            logger.warning("Tool '%s' not listed, no validation will be performed", tool_name)

        return tool

    def call_tool(self, *, validate_input: bool = True):
        """Register a tool call handler.

        Args:
            validate_input: If True, validates input against inputSchema. Default is True.

        The handler validates input against inputSchema (if validate_input=True), calls the tool function,
        and builds a CallToolResult with the results:
        - Unstructured content (iterable of ContentBlock): returned in content
        - Structured content (dict): returned in structuredContent, serialized JSON text returned in content
        - Both: returned in content and structuredContent

        If outputSchema is defined, validates structuredContent or errors if missing.
        """

        def decorator(
            func: Callable[
                ...,
                Awaitable[UnstructuredContent | StructuredContent | CombinationContent],
            ],
        ):
            logger.debug("Registering handler for CallToolRequest")

            async def handler(req: types.CallToolRequest):
                try:
                    tool_name = req.params.name
                    arguments = req.params.arguments or {}
                    tool = await self._get_cached_tool_definition(tool_name)

                    # input validation
                    if validate_input and tool:
                        try:
                            jsonschema.validate(instance=arguments, schema=tool.inputSchema)
                        except jsonschema.ValidationError as e:
                            return self._make_error_result(f"Input validation error: {e.message}")

                    # tool call
                    results = await func(tool_name, arguments)

                    # output normalization
                    unstructured_content: UnstructuredContent
                    maybe_structured_content: StructuredContent | None
                    if isinstance(results, tuple) and len(results) == 2:
                        # tool returned both structured and unstructured content
                        unstructured_content, maybe_structured_content = cast(CombinationContent, results)
                    elif isinstance(results, dict):
                        # tool returned structured content only
                        maybe_structured_content = cast(StructuredContent, results)
                        unstructured_content = [types.TextContent(type="text", text=json.dumps(results, indent=2))]
                    elif hasattr(results, "__iter__"):
                        # tool returned unstructured content only
                        unstructured_content = cast(UnstructuredContent, results)
                        maybe_structured_content = None
                    else:
                        return self._make_error_result(f"Unexpected return type from tool: {type(results).__name__}")

                    # output validation
                    if tool and tool.outputSchema is not None:
                        if maybe_structured_content is None:
                            return self._make_error_result(
                                "Output validation error: outputSchema defined but no structured output returned"
                            )
                        else:
                            try:
                                jsonschema.validate(instance=maybe_structured_content, schema=tool.outputSchema)
                            except jsonschema.ValidationError as e:
                                return self._make_error_result(f"Output validation error: {e.message}")

                    # result
                    return types.ServerResult(
                        types.CallToolResult(
                            content=list(unstructured_content),
                            structuredContent=maybe_structured_content,
                            isError=False,
                        )
                    )
                except Exception as e:
                    return self._make_error_result(str(e))

            self.request_handlers[types.CallToolRequest] = handler
            return func

        return decorator

    def progress_notification(self):
        def decorator(
            func: Callable[[str | int, float, float | None, str | None], Awaitable[None]],
        ):
            logger.debug("Registering handler for ProgressNotification")

            async def handler(req: types.ProgressNotification):
                await func(
                    req.params.progressToken,
                    req.params.progress,
                    req.params.total,
                    req.params.message,
                )

            self.notification_handlers[types.ProgressNotification] = handler
            return func

        return decorator

    def completion(self):
        """Provides completions for prompts and resource templates"""

        def decorator(
            func: Callable[
                [
                    types.PromptReference | types.ResourceTemplateReference,
                    types.CompletionArgument,
                    types.CompletionContext | None,
                ],
                Awaitable[types.Completion | None],
            ],
        ):
            logger.debug("Registering handler for CompleteRequest")

            async def handler(req: types.CompleteRequest):
                completion = await func(req.params.ref, req.params.argument, req.params.context)
                return types.ServerResult(
                    types.CompleteResult(
                        completion=completion
                        if completion is not None
                        else types.Completion(values=[], total=None, hasMore=None),
                    )
                )

            self.request_handlers[types.CompleteRequest] = handler
            return func

        return decorator

    async def run(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        initialization_options: InitializationOptions,
        # When False, exceptions are returned as messages to the client.
        # When True, exceptions are raised, which will cause the server to shut down
        # but also make tracing exceptions much easier during testing and when using
        # in-process servers.
        raise_exceptions: bool = False,
        # When True, the server is stateless and
        # clients can perform initialization with any node. The client must still follow
        # the initialization lifecycle, but can do so with any available node
        # rather than requiring initialization for each connection.
        stateless: bool = False,
    ):
        async with AsyncExitStack() as stack:
            lifespan_context = await stack.enter_async_context(self.lifespan(self))
            session = await stack.enter_async_context(
                ServerSession(
                    read_stream,
                    write_stream,
                    initialization_options,
                    stateless=stateless,
                )
            )

            async with anyio.create_task_group() as tg:
                async for message in session.incoming_messages:
                    logger.debug("Received message: %s", message)

                    tg.start_soon(
                        self._handle_message,
                        message,
                        session,
                        lifespan_context,
                        raise_exceptions,
                    )

    async def _handle_message(
        self,
        message: RequestResponder[types.ClientRequest, types.ServerResult] | types.ClientNotification | Exception,
        session: ServerSession,
        lifespan_context: LifespanResultT,
        raise_exceptions: bool = False,
    ):
        with warnings.catch_warnings(record=True) as w:
            # TODO(Marcelo): We should be checking if message is Exception here.
            match message:  # type: ignore[reportMatchNotExhaustive]
                case RequestResponder(request=types.ClientRequest(root=req)) as responder:
                    with responder:
                        await self._handle_request(message, req, session, lifespan_context, raise_exceptions)
                case types.ClientNotification(root=notify):
                    await self._handle_notification(notify)

            for warning in w:
                logger.info("Warning: %s: %s", warning.category.__name__, warning.message)

    async def _handle_request(
        self,
        message: RequestResponder[types.ClientRequest, types.ServerResult],
        req: Any,
        session: ServerSession,
        lifespan_context: LifespanResultT,
        raise_exceptions: bool,
    ):
        logger.info("Processing request of type %s", type(req).__name__)
        if handler := self.request_handlers.get(type(req)):  # type: ignore
            logger.debug("Dispatching request of type %s", type(req).__name__)

            token = None
            try:
                # Extract request context from message metadata
                request_data = None
                if message.message_metadata is not None and isinstance(message.message_metadata, ServerMessageMetadata):
                    request_data = message.message_metadata.request_context

                # Set our global state that can be retrieved via
                # app.get_request_context()
                token = request_ctx.set(
                    RequestContext(
                        message.request_id,
                        message.request_meta,
                        session,
                        lifespan_context,
                        request=request_data,
                    )
                )
                response = await handler(req)
            except McpError as err:
                response = err.error
            except Exception as err:
                if raise_exceptions:
                    raise err
                response = types.ErrorData(code=0, message=str(err), data=None)
            finally:
                # Reset the global state after we are done
                if token is not None:
                    request_ctx.reset(token)

            await message.respond(response)
        else:
            await message.respond(
                types.ErrorData(
                    code=types.METHOD_NOT_FOUND,
                    message="Method not found",
                )
            )

        logger.debug("Response sent")

    async def _handle_notification(self, notify: Any):
        if handler := self.notification_handlers.get(type(notify)):  # type: ignore
            logger.debug("Dispatching notification of type %s", type(notify).__name__)

            try:
                await handler(notify)
            except Exception:
                logger.exception("Uncaught exception in notification handler")

## _ping_handler

**Type**: Function

**Description**: async def _ping_handler(request: types.PingRequest) -> types.ServerResult:
    return types.ServerResult(types.EmptyResult())

## OAuthToken

**Type**: Class

**Description**: class OAuthToken(BaseModel):
    """
    See https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
    """

    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int | None = None
    scope: str | None = None
    refresh_token: str | None = None

    @field_validator("token_type", mode="before")
    @classmethod
    def normalize_token_type(cls, v: str | None) -> str | None:
        if isinstance(v, str):
            # Bearer is title-cased in the spec, so we normalize it
            # https://datatracker.ietf.org/doc/html/rfc6750#section-4
            return v.title()
        return v

## InvalidScopeError

**Type**: Class

**Description**: class InvalidScopeError(Exception):
    def __init__(self, message: str):
        self.message = message

## InvalidRedirectUriError

**Type**: Class

**Description**: class InvalidRedirectUriError(Exception):
    def __init__(self, message: str):
        self.message = message

## OAuthClientMetadata

**Type**: Class

**Description**: class OAuthClientMetadata(BaseModel):
    """
    RFC 7591 OAuth 2.0 Dynamic Client Registration metadata.
    See https://datatracker.ietf.org/doc/html/rfc7591#section-2
    for the full specification.
    """

    redirect_uris: list[AnyUrl] = Field(..., min_length=1)
    # token_endpoint_auth_method: this implementation only supports none &
    # client_secret_post;
    # ie: we do not support client_secret_basic
    token_endpoint_auth_method: Literal["none", "client_secret_post"] = "client_secret_post"
    # grant_types: this implementation only supports authorization_code & refresh_token
    grant_types: list[Literal["authorization_code", "refresh_token"]] = [
        "authorization_code",
        "refresh_token",
    ]
    # this implementation only supports code; ie: it does not support implicit grants
    response_types: list[Literal["code"]] = ["code"]
    scope: str | None = None

    # these fields are currently unused, but we support & store them for potential
    # future use
    client_name: str | None = None
    client_uri: AnyHttpUrl | None = None
    logo_uri: AnyHttpUrl | None = None
    contacts: list[str] | None = None
    tos_uri: AnyHttpUrl | None = None
    policy_uri: AnyHttpUrl | None = None
    jwks_uri: AnyHttpUrl | None = None
    jwks: Any | None = None
    software_id: str | None = None
    software_version: str | None = None

    def validate_scope(self, requested_scope: str | None) -> list[str] | None:
        if requested_scope is None:
            return None
        requested_scopes = requested_scope.split(" ")
        allowed_scopes = [] if self.scope is None else self.scope.split(" ")
        for scope in requested_scopes:
            if scope not in allowed_scopes:
                raise InvalidScopeError(f"Client was not registered with scope {scope}")
        return requested_scopes

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        if redirect_uri is not None:
            # Validate redirect_uri against client's registered redirect URIs
            if redirect_uri not in self.redirect_uris:
                raise InvalidRedirectUriError(f"Redirect URI '{redirect_uri}' not registered for client")
            return redirect_uri
        elif len(self.redirect_uris) == 1:
            return self.redirect_uris[0]
        else:
            raise InvalidRedirectUriError("redirect_uri must be specified when client " "has multiple registered URIs")

## OAuthClientInformationFull

**Type**: Class

**Description**: class OAuthClientInformationFull(OAuthClientMetadata):
    """
    RFC 7591 OAuth 2.0 Dynamic Client Registration full response
    (client information plus metadata).
    """

    client_id: str
    client_secret: str | None = None
    client_id_issued_at: int | None = None
    client_secret_expires_at: int | None = None

## OAuthMetadata

**Type**: Class

**Description**: class OAuthMetadata(BaseModel):
    """
    RFC 8414 OAuth 2.0 Authorization Server Metadata.
    See https://datatracker.ietf.org/doc/html/rfc8414#section-2
    """

    issuer: AnyHttpUrl
    authorization_endpoint: AnyHttpUrl
    token_endpoint: AnyHttpUrl
    registration_endpoint: AnyHttpUrl | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[str] = ["code"]
    response_modes_supported: list[Literal["query", "fragment"]] | None = None
    grant_types_supported: list[str] | None = None
    token_endpoint_auth_methods_supported: list[str] | None = None
    token_endpoint_auth_signing_alg_values_supported: None = None
    service_documentation: AnyHttpUrl | None = None
    ui_locales_supported: list[str] | None = None
    op_policy_uri: AnyHttpUrl | None = None
    op_tos_uri: AnyHttpUrl | None = None
    revocation_endpoint: AnyHttpUrl | None = None
    revocation_endpoint_auth_methods_supported: list[str] | None = None
    revocation_endpoint_auth_signing_alg_values_supported: None = None
    introspection_endpoint: AnyHttpUrl | None = None
    introspection_endpoint_auth_methods_supported: list[str] | None = None
    introspection_endpoint_auth_signing_alg_values_supported: None = None
    code_challenge_methods_supported: list[str] | None = None

## ProtectedResourceMetadata

**Type**: Class

**Description**: class ProtectedResourceMetadata(BaseModel):
    """
    RFC 9728 OAuth 2.0 Protected Resource Metadata.
    See https://datatracker.ietf.org/doc/html/rfc9728#section-2
    """

    resource: AnyHttpUrl
    authorization_servers: list[AnyHttpUrl] = Field(..., min_length=1)
    scopes_supported: list[str] | None = None
    bearer_methods_supported: list[str] | None = Field(default=["header"])  # MCP only supports header method
    resource_documentation: AnyHttpUrl | None = None

## resource_url_from_server_url

**Type**: Function

**Description**: def resource_url_from_server_url(url: str | HttpUrl | AnyUrl) -> str:
    """Convert server URL to canonical resource URL per RFC 8707.

    RFC 8707 section 2 states that resource URIs "MUST NOT include a fragment component".
    Returns absolute URI with lowercase scheme/host for canonical form.

    Args:
        url: Server URL to convert

    Returns:
        Canonical resource URL string
    """
    # Convert to string if needed
    url_str = str(url)

    # Parse the URL and remove fragment, create canonical form
    parsed = urlsplit(url_str)
    canonical = urlunsplit(parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower(), fragment=""))

    return canonical

## check_resource_allowed

**Type**: Function

**Description**: def check_resource_allowed(requested_resource: str, configured_resource: str) -> bool:
    """Check if a requested resource URL matches a configured resource URL.

    A requested resource matches if it has the same scheme, domain, port,
    and its path starts with the configured resource's path. This allows
    hierarchical matching where a token for a parent resource can be used
    for child resources.

    Args:
        requested_resource: The resource URL being requested
        configured_resource: The resource URL that has been configured

    Returns:
        True if the requested resource matches the configured resource
    """
    # Parse both URLs
    requested = urlparse(requested_resource)
    configured = urlparse(configured_resource)

    # Compare scheme, host, and port (origin)
    if requested.scheme.lower() != configured.scheme.lower() or requested.netloc.lower() != configured.netloc.lower():
        return False

    # Handle cases like requested=/foo and configured=/foo/
    requested_path = requested.path
    configured_path = configured.path

    # If requested path is shorter, it cannot be a child
    if len(requested_path) < len(configured_path):
        return False

    # Check if the requested path starts with the configured path
    # Ensure both paths end with / for proper comparison
    # This ensures that paths like "/api123" don't incorrectly match "/api"
    if not requested_path.endswith("/"):
        requested_path += "/"
    if not configured_path.endswith("/"):
        configured_path += "/"

    return requested_path.startswith(configured_path)

## McpError

**Type**: Class

**Description**: class McpError(Exception):
    """
    Exception type raised when an error arrives over an MCP connection.
    """

    error: ErrorData

    def __init__(self, error: ErrorData):
        """Initialize McpError."""
        super().__init__(error.message)
        self.error = error

## get_display_name

**Type**: Function

**Description**: def get_display_name(obj: Tool | Resource | Prompt | ResourceTemplate | Implementation) -> str:
    """
    Get the display name for an MCP object with proper precedence.

    This is a client-side utility function designed to help MCP clients display
    human-readable names in their user interfaces. When servers provide a 'title'
    field, it should be preferred over the programmatic 'name' field for display.

    For tools: title > annotations.title > name
    For other objects: title > name

    Example:
        # In a client displaying available tools
        tools = await session.list_tools()
        for tool in tools.tools:
            display_name = get_display_name(tool)
            print(f"Available tool: {display_name}")

    Args:
        obj: An MCP object with name and optional title fields

    Returns:
        The display name to use for UI presentation
    """
    if isinstance(obj, Tool):
        # Tools have special precedence: title > annotations.title > name
        if hasattr(obj, "title") and obj.title is not None:
            return obj.title
        if obj.annotations and hasattr(obj.annotations, "title") and obj.annotations.title is not None:
            return obj.annotations.title
        return obj.name
    else:
        # All other objects: title > name
        if hasattr(obj, "title") and obj.title is not None:
            return obj.title
        return obj.name

## Progress

**Type**: Class

**Description**: class Progress(BaseModel):
    progress: float
    total: float | None

## ProgressFnT

**Type**: Class

**Description**: class ProgressFnT(Protocol):
    """Protocol for progress notification callbacks."""

    async def __call__(self, progress: float, total: float | None, message: str | None) -> None: ...

## RequestResponder

**Type**: Class

**Description**: class RequestResponder(Generic[ReceiveRequestT, SendResultT]):
    """Handles responding to MCP requests and manages request lifecycle.

    This class MUST be used as a context manager to ensure proper cleanup and
    cancellation handling:

    Example:
        with request_responder as resp:
            await resp.respond(result)

    The context manager ensures:
    1. Proper cancellation scope setup and cleanup
    2. Request completion tracking
    3. Cleanup of in-flight requests
    """

    def __init__(
        self,
        request_id: RequestId,
        request_meta: RequestParams.Meta | None,
        request: ReceiveRequestT,
        session: """BaseSession[
            SendRequestT,
            SendNotificationT,
            SendResultT,
            ReceiveRequestT,
            ReceiveNotificationT
        ]""",
        on_complete: Callable[["RequestResponder[ReceiveRequestT, SendResultT]"], Any],
        message_metadata: MessageMetadata = None,
    ) -> None:
        self.request_id = request_id
        self.request_meta = request_meta
        self.request = request
        self.message_metadata = message_metadata
        self._session = session
        self._completed = False
        self._cancel_scope = anyio.CancelScope()
        self._on_complete = on_complete
        self._entered = False  # Track if we're in a context manager

    def __enter__(self) -> "RequestResponder[ReceiveRequestT, SendResultT]":
        """Enter the context manager, enabling request cancellation tracking."""
        self._entered = True
        self._cancel_scope = anyio.CancelScope()
        self._cancel_scope.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the context manager, performing cleanup and notifying completion."""
        try:
            if self._completed:
                self._on_complete(self)
        finally:
            self._entered = False
            if not self._cancel_scope:
                raise RuntimeError("No active cancel scope")
            self._cancel_scope.__exit__(exc_type, exc_val, exc_tb)

    async def respond(self, response: SendResultT | ErrorData) -> None:
        """Send a response for this request.

        Must be called within a context manager block.
        Raises:
            RuntimeError: If not used within a context manager
            AssertionError: If request was already responded to
        """
        if not self._entered:
            raise RuntimeError("RequestResponder must be used as a context manager")
        assert not self._completed, "Request already responded to"

        if not self.cancelled:
            self._completed = True

            await self._session._send_response(  # type: ignore[reportPrivateUsage]
                request_id=self.request_id, response=response
            )

    async def cancel(self) -> None:
        """Cancel this request and mark it as completed."""
        if not self._entered:
            raise RuntimeError("RequestResponder must be used as a context manager")
        if not self._cancel_scope:
            raise RuntimeError("No active cancel scope")

        self._cancel_scope.cancel()
        self._completed = True  # Mark as completed so it's removed from in_flight
        # Send an error response to indicate cancellation
        await self._session._send_response(  # type: ignore[reportPrivateUsage]
            request_id=self.request_id,
            response=ErrorData(code=0, message="Request cancelled", data=None),
        )

    @property
    def in_flight(self) -> bool:
        return not self._completed and not self.cancelled

    @property
    def cancelled(self) -> bool:
        return self._cancel_scope.cancel_called

## BaseSession

**Type**: Class

**Description**: class BaseSession(
    Generic[
        SendRequestT,
        SendNotificationT,
        SendResultT,
        ReceiveRequestT,
        ReceiveNotificationT,
    ],
):
    """
    Implements an MCP "session" on top of read/write streams, including features
    like request/response linking, notifications, and progress.

    This class is an async context manager that automatically starts processing
    messages when entered.
    """

    _response_streams: dict[RequestId, MemoryObjectSendStream[JSONRPCResponse | JSONRPCError]]
    _request_id: int
    _in_flight: dict[RequestId, RequestResponder[ReceiveRequestT, SendResultT]]
    _progress_callbacks: dict[RequestId, ProgressFnT]

    def __init__(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        receive_request_type: type[ReceiveRequestT],
        receive_notification_type: type[ReceiveNotificationT],
        # If none, reading will never time out
        read_timeout_seconds: timedelta | None = None,
    ) -> None:
        self._read_stream = read_stream
        self._write_stream = write_stream
        self._response_streams = {}
        self._request_id = 0
        self._receive_request_type = receive_request_type
        self._receive_notification_type = receive_notification_type
        self._session_read_timeout_seconds = read_timeout_seconds
        self._in_flight = {}
        self._progress_callbacks = {}
        self._exit_stack = AsyncExitStack()

    async def __aenter__(self) -> Self:
        self._task_group = anyio.create_task_group()
        await self._task_group.__aenter__()
        self._task_group.start_soon(self._receive_loop)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        await self._exit_stack.aclose()
        # Using BaseSession as a context manager should not block on exit (this
        # would be very surprising behavior), so make sure to cancel the tasks
        # in the task group.
        self._task_group.cancel_scope.cancel()
        return await self._task_group.__aexit__(exc_type, exc_val, exc_tb)

    async def send_request(
        self,
        request: SendRequestT,
        result_type: type[ReceiveResultT],
        request_read_timeout_seconds: timedelta | None = None,
        metadata: MessageMetadata = None,
        progress_callback: ProgressFnT | None = None,
    ) -> ReceiveResultT:
        """
        Sends a request and wait for a response. Raises an McpError if the
        response contains an error. If a request read timeout is provided, it
        will take precedence over the session read timeout.

        Do not use this method to emit notifications! Use send_notification()
        instead.
        """
        request_id = self._request_id
        self._request_id = request_id + 1

        response_stream, response_stream_reader = anyio.create_memory_object_stream[JSONRPCResponse | JSONRPCError](1)
        self._response_streams[request_id] = response_stream

        # Set up progress token if progress callback is provided
        request_data = request.model_dump(by_alias=True, mode="json", exclude_none=True)
        if progress_callback is not None:
            # Use request_id as progress token
            if "params" not in request_data:
                request_data["params"] = {}
            if "_meta" not in request_data["params"]:
                request_data["params"]["_meta"] = {}
            request_data["params"]["_meta"]["progressToken"] = request_id
            # Store the callback for this request
            self._progress_callbacks[request_id] = progress_callback

        try:
            jsonrpc_request = JSONRPCRequest(
                jsonrpc="2.0",
                id=request_id,
                **request_data,
            )

            await self._write_stream.send(SessionMessage(message=JSONRPCMessage(jsonrpc_request), metadata=metadata))

            # request read timeout takes precedence over session read timeout
            timeout = None
            if request_read_timeout_seconds is not None:
                timeout = request_read_timeout_seconds.total_seconds()
            elif self._session_read_timeout_seconds is not None:
                timeout = self._session_read_timeout_seconds.total_seconds()

            try:
                with anyio.fail_after(timeout):
                    response_or_error = await response_stream_reader.receive()
            except TimeoutError:
                raise McpError(
                    ErrorData(
                        code=httpx.codes.REQUEST_TIMEOUT,
                        message=(
                            f"Timed out while waiting for response to "
                            f"{request.__class__.__name__}. Waited "
                            f"{timeout} seconds."
                        ),
                    )
                )

            if isinstance(response_or_error, JSONRPCError):
                raise McpError(response_or_error.error)
            else:
                return result_type.model_validate(response_or_error.result)

        finally:
            self._response_streams.pop(request_id, None)
            self._progress_callbacks.pop(request_id, None)
            await response_stream.aclose()
            await response_stream_reader.aclose()

    async def send_notification(
        self,
        notification: SendNotificationT,
        related_request_id: RequestId | None = None,
    ) -> None:
        """
        Emits a notification, which is a one-way message that does not expect
        a response.
        """
        # Some transport implementations may need to set the related_request_id
        # to attribute to the notifications to the request that triggered them.
        jsonrpc_notification = JSONRPCNotification(
            jsonrpc="2.0",
            **notification.model_dump(by_alias=True, mode="json", exclude_none=True),
        )
        session_message = SessionMessage(
            message=JSONRPCMessage(jsonrpc_notification),
            metadata=ServerMessageMetadata(related_request_id=related_request_id) if related_request_id else None,
        )
        await self._write_stream.send(session_message)

    async def _send_response(self, request_id: RequestId, response: SendResultT | ErrorData) -> None:
        if isinstance(response, ErrorData):
            jsonrpc_error = JSONRPCError(jsonrpc="2.0", id=request_id, error=response)
            session_message = SessionMessage(message=JSONRPCMessage(jsonrpc_error))
            await self._write_stream.send(session_message)
        else:
            jsonrpc_response = JSONRPCResponse(
                jsonrpc="2.0",
                id=request_id,
                result=response.model_dump(by_alias=True, mode="json", exclude_none=True),
            )
            session_message = SessionMessage(message=JSONRPCMessage(jsonrpc_response))
            await self._write_stream.send(session_message)

    async def _receive_loop(self) -> None:
        async with (
            self._read_stream,
            self._write_stream,
        ):
            try:
                async for message in self._read_stream:
                    if isinstance(message, Exception):
                        await self._handle_incoming(message)
                    elif isinstance(message.message.root, JSONRPCRequest):
                        try:
                            validated_request = self._receive_request_type.model_validate(
                                message.message.root.model_dump(by_alias=True, mode="json", exclude_none=True)
                            )
                            responder = RequestResponder(
                                request_id=message.message.root.id,
                                request_meta=validated_request.root.params.meta
                                if validated_request.root.params
                                else None,
                                request=validated_request,
                                session=self,
                                on_complete=lambda r: self._in_flight.pop(r.request_id, None),
                                message_metadata=message.metadata,
                            )
                            self._in_flight[responder.request_id] = responder
                            await self._received_request(responder)

                            if not responder._completed:  # type: ignore[reportPrivateUsage]
                                await self._handle_incoming(responder)
                        except Exception as e:
                            # For request validation errors, send a proper JSON-RPC error
                            # response instead of crashing the server
                            logging.warning(f"Failed to validate request: {e}")
                            logging.debug(f"Message that failed validation: {message.message.root}")
                            error_response = JSONRPCError(
                                jsonrpc="2.0",
                                id=message.message.root.id,
                                error=ErrorData(
                                    code=INVALID_PARAMS,
                                    message="Invalid request parameters",
                                    data="",
                                ),
                            )
                            session_message = SessionMessage(message=JSONRPCMessage(error_response))
                            await self._write_stream.send(session_message)

                    elif isinstance(message.message.root, JSONRPCNotification):
                        try:
                            notification = self._receive_notification_type.model_validate(
                                message.message.root.model_dump(by_alias=True, mode="json", exclude_none=True)
                            )
                            # Handle cancellation notifications
                            if isinstance(notification.root, CancelledNotification):
                                cancelled_id = notification.root.params.requestId
                                if cancelled_id in self._in_flight:
                                    await self._in_flight[cancelled_id].cancel()
                            else:
                                # Handle progress notifications callback
                                if isinstance(notification.root, ProgressNotification):
                                    progress_token = notification.root.params.progressToken
                                    # If there is a progress callback for this token,
                                    # call it with the progress information
                                    if progress_token in self._progress_callbacks:
                                        callback = self._progress_callbacks[progress_token]
                                        await callback(
                                            notification.root.params.progress,
                                            notification.root.params.total,
                                            notification.root.params.message,
                                        )
                                await self._received_notification(notification)
                                await self._handle_incoming(notification)
                        except Exception as e:
                            # For other validation errors, log and continue
                            logging.warning(
                                f"Failed to validate notification: {e}. " f"Message was: {message.message.root}"
                            )
                    else:  # Response or error
                        stream = self._response_streams.pop(message.message.root.id, None)
                        if stream:
                            await stream.send(message.message.root)
                        else:
                            await self._handle_incoming(
                                RuntimeError("Received response with an unknown " f"request ID: {message}")
                            )

            except anyio.ClosedResourceError:
                # This is expected when the client disconnects abruptly.
                # Without this handler, the exception would propagate up and
                # crash the server's task group.
                logging.debug("Read stream closed by client")
            except Exception as e:
                # Other exceptions are not expected and should be logged. We purposefully
                # catch all exceptions here to avoid crashing the server.
                logging.exception(f"Unhandled exception in receive loop: {e}")
            finally:
                # after the read stream is closed, we need to send errors
                # to any pending requests
                for id, stream in self._response_streams.items():
                    error = ErrorData(code=CONNECTION_CLOSED, message="Connection closed")
                    try:
                        await stream.send(JSONRPCError(jsonrpc="2.0", id=id, error=error))
                        await stream.aclose()
                    except Exception:
                        # Stream might already be closed
                        pass
                self._response_streams.clear()

    async def _received_request(self, responder: RequestResponder[ReceiveRequestT, SendResultT]) -> None:
        """
        Can be overridden by subclasses to handle a request without needing to
        listen on the message stream.

        If the request is responded to within this method, it will not be
        forwarded on to the message stream.
        """

    async def _received_notification(self, notification: ReceiveNotificationT) -> None:
        """
        Can be overridden by subclasses to handle a notification without needing
        to listen on the message stream.
        """

    async def send_progress_notification(
        self,
        progress_token: str | int,
        progress: float,
        total: float | None = None,
        message: str | None = None,
    ) -> None:
        """
        Sends a progress notification for a request that is currently being
        processed.
        """

    async def _handle_incoming(
        self,
        req: RequestResponder[ReceiveRequestT, SendResultT] | ReceiveNotificationT | Exception,
    ) -> None:
        """A generic handler for incoming messages. Overwritten by subclasses."""
        pass

## McpHttpClientFactory

**Type**: Class

**Description**: class McpHttpClientFactory(Protocol):
    def __call__(
        self,
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient: ...

## create_mcp_http_client

**Type**: Function

**Description**: def create_mcp_http_client(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    """Create a standardized httpx AsyncClient with MCP defaults.

    This function provides common defaults used throughout the MCP codebase:
    - follow_redirects=True (always enabled)
    - Default timeout of 30 seconds if not specified

    Args:
        headers: Optional headers to include with all requests.
        timeout: Request timeout as httpx.Timeout object.
            Defaults to 30 seconds if not specified.
        auth: Optional authentication handler.

    Returns:
        Configured httpx.AsyncClient instance with MCP defaults.

    Note:
        The returned AsyncClient must be used as a context manager to ensure
        proper cleanup of connections.

    Examples:
        # Basic usage with MCP defaults
        async with create_mcp_http_client() as client:
            response = await client.get("https://api.example.com")

        # With custom headers
        headers = {"Authorization": "Bearer token"}
        async with create_mcp_http_client(headers) as client:
            response = await client.get("/endpoint")

        # With both custom headers and timeout
        timeout = httpx.Timeout(60.0, read=300.0)
        async with create_mcp_http_client(headers, timeout) as client:
            response = await client.get("/long-request")

        # With authentication
        from httpx import BasicAuth
        auth = BasicAuth(username="user", password="pass")
        async with create_mcp_http_client(headers, timeout, auth) as client:
            response = await client.get("/protected-endpoint")
    """
    # Set MCP defaults
    kwargs: dict[str, Any] = {
        "follow_redirects": True,
    }

    # Handle timeout
    if timeout is None:
        kwargs["timeout"] = httpx.Timeout(30.0)
    else:
        kwargs["timeout"] = timeout

    # Handle headers
    if headers is not None:
        kwargs["headers"] = headers

    # Handle authentication
    if auth is not None:
        kwargs["auth"] = auth

    return httpx.AsyncClient(**kwargs)

## SpyMemoryObjectSendStream

**Type**: Class

**Description**: class SpyMemoryObjectSendStream:
    def __init__(self, original_stream):
        self.original_stream = original_stream
        self.sent_messages: list[SessionMessage] = []

    async def send(self, message):
        self.sent_messages.append(message)
        await self.original_stream.send(message)

    async def aclose(self):
        await self.original_stream.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.aclose()

## StreamSpyCollection

**Type**: Class

**Description**: class StreamSpyCollection:
    def __init__(
        self,
        client_spy: SpyMemoryObjectSendStream,
        server_spy: SpyMemoryObjectSendStream,
    ):
        self.client = client_spy
        self.server = server_spy

    def clear(self) -> None:
        """Clear all captured messages."""
        self.client.sent_messages.clear()
        self.server.sent_messages.clear()

    def get_client_requests(self, method: str | None = None) -> list[JSONRPCRequest]:
        """Get client-sent requests, optionally filtered by method."""
        return [
            req.message.root
            for req in self.client.sent_messages
            if isinstance(req.message.root, JSONRPCRequest) and (method is None or req.message.root.method == method)
        ]

    def get_server_requests(self, method: str | None = None) -> list[JSONRPCRequest]:
        """Get server-sent requests, optionally filtered by method."""
        return [
            req.message.root
            for req in self.server.sent_messages
            if isinstance(req.message.root, JSONRPCRequest) and (method is None or req.message.root.method == method)
        ]

    def get_client_notifications(self, method: str | None = None) -> list[JSONRPCNotification]:
        """Get client-sent notifications, optionally filtered by method."""
        return [
            notif.message.root
            for notif in self.client.sent_messages
            if isinstance(notif.message.root, JSONRPCNotification)
            and (method is None or notif.message.root.method == method)
        ]

    def get_server_notifications(self, method: str | None = None) -> list[JSONRPCNotification]:
        """Get server-sent notifications, optionally filtered by method."""
        return [
            notif.message.root
            for notif in self.server.sent_messages
            if isinstance(notif.message.root, JSONRPCNotification)
            and (method is None or notif.message.root.method == method)
        ]

## MockTokenStorage

**Type**: Class

**Description**: class MockTokenStorage:
    """Mock token storage for testing."""

    def __init__(self):
        self._tokens: OAuthToken | None = None
        self._client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info

## TestPKCEParameters

**Type**: Class

**Description**: class TestPKCEParameters:
    """Test PKCE parameter generation."""

    def test_pkce_generation(self):
        """Test PKCE parameter generation creates valid values."""
        pkce = PKCEParameters.generate()

        # Verify lengths
        assert len(pkce.code_verifier) == 128
        assert 43 <= len(pkce.code_challenge) <= 128

        # Verify characters used in verifier
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        assert all(c in allowed_chars for c in pkce.code_verifier)

        # Verify base64url encoding in challenge (no padding)
        assert "=" not in pkce.code_challenge

    def test_pkce_uniqueness(self):
        """Test PKCE generates unique values each time."""
        pkce1 = PKCEParameters.generate()
        pkce2 = PKCEParameters.generate()

        assert pkce1.code_verifier != pkce2.code_verifier
        assert pkce1.code_challenge != pkce2.code_challenge

## TestOAuthContext

**Type**: Class

**Description**: class TestOAuthContext:
    """Test OAuth context functionality."""

    @pytest.mark.anyio
    async def test_oauth_provider_initialization(self, oauth_provider, client_metadata, mock_storage):
        """Test OAuthClientProvider basic setup."""
        assert oauth_provider.context.server_url == "https://api.example.com/v1/mcp"
        assert oauth_provider.context.client_metadata == client_metadata
        assert oauth_provider.context.storage == mock_storage
        assert oauth_provider.context.timeout == 300.0
        assert oauth_provider.context is not None

    def test_context_url_parsing(self, oauth_provider):
        """Test get_authorization_base_url() extracts base URLs correctly."""
        context = oauth_provider.context

        # Test with path
        assert context.get_authorization_base_url("https://api.example.com/v1/mcp") == "https://api.example.com"

        # Test with no path
        assert context.get_authorization_base_url("https://api.example.com") == "https://api.example.com"

        # Test with port
        assert (
            context.get_authorization_base_url("https://api.example.com:8080/path/to/mcp")
            == "https://api.example.com:8080"
        )

        # Test with query params
        assert (
            context.get_authorization_base_url("https://api.example.com/path?param=value") == "https://api.example.com"
        )

    @pytest.mark.anyio
    async def test_token_validity_checking(self, oauth_provider, mock_storage, valid_tokens):
        """Test is_token_valid() and can_refresh_token() logic."""
        context = oauth_provider.context

        # No tokens - should be invalid
        assert not context.is_token_valid()
        assert not context.can_refresh_token()

        # Set valid tokens and client info
        context.current_tokens = valid_tokens
        context.token_expiry_time = time.time() + 1800  # 30 minutes from now
        context.client_info = OAuthClientInformationFull(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uris=[AnyUrl("http://localhost:3030/callback")],
        )

        # Should be valid
        assert context.is_token_valid()
        assert context.can_refresh_token()  # Has refresh token and client info

        # Expire the token
        context.token_expiry_time = time.time() - 100  # Expired 100 seconds ago
        assert not context.is_token_valid()
        assert context.can_refresh_token()  # Can still refresh

        # Remove refresh token
        context.current_tokens.refresh_token = None
        assert not context.can_refresh_token()

        # Remove client info
        context.current_tokens.refresh_token = "test_refresh_token"
        context.client_info = None
        assert not context.can_refresh_token()

    def test_clear_tokens(self, oauth_provider, valid_tokens):
        """Test clear_tokens() removes token data."""
        context = oauth_provider.context
        context.current_tokens = valid_tokens
        context.token_expiry_time = time.time() + 1800

        # Clear tokens
        context.clear_tokens()

        # Verify cleared
        assert context.current_tokens is None
        assert context.token_expiry_time is None

## TestOAuthFlow

**Type**: Class

**Description**: class TestOAuthFlow:
    """Test OAuth flow methods."""

    @pytest.mark.anyio
    async def test_discover_protected_resource_request(self, oauth_provider):
        """Test protected resource discovery request building."""
        request = await oauth_provider._discover_protected_resource()

        assert request.method == "GET"
        assert str(request.url) == "https://api.example.com/.well-known/oauth-protected-resource"
        assert "mcp-protocol-version" in request.headers

    @pytest.mark.anyio
    async def test_discover_oauth_metadata_request(self, oauth_provider):
        """Test OAuth metadata discovery request building."""
        request = await oauth_provider._discover_oauth_metadata()

        assert request.method == "GET"
        assert str(request.url) == "https://api.example.com/.well-known/oauth-authorization-server/v1/mcp"
        assert "mcp-protocol-version" in request.headers

    @pytest.mark.anyio
    async def test_discover_oauth_metadata_request_no_path(self, client_metadata, mock_storage):
        """Test OAuth metadata discovery request building when server has no path."""

        async def redirect_handler(url: str) -> None:
            pass

        async def callback_handler() -> tuple[str, str | None]:
            return "test_auth_code", "test_state"

        provider = OAuthClientProvider(
            server_url="https://api.example.com",
            client_metadata=client_metadata,
            storage=mock_storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
        )

        request = await provider._discover_oauth_metadata()

        assert request.method == "GET"
        assert str(request.url) == "https://api.example.com/.well-known/oauth-authorization-server"
        assert "mcp-protocol-version" in request.headers

    @pytest.mark.anyio
    async def test_discover_oauth_metadata_request_trailing_slash(self, client_metadata, mock_storage):
        """Test OAuth metadata discovery request building when server path has trailing slash."""

        async def redirect_handler(url: str) -> None:
            pass

        async def callback_handler() -> tuple[str, str | None]:
            return "test_auth_code", "test_state"

        provider = OAuthClientProvider(
            server_url="https://api.example.com/v1/mcp/",
            client_metadata=client_metadata,
            storage=mock_storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
        )

        request = await provider._discover_oauth_metadata()

        assert request.method == "GET"
        assert str(request.url) == "https://api.example.com/.well-known/oauth-authorization-server/v1/mcp"
        assert "mcp-protocol-version" in request.headers

## TestOAuthFallback

**Type**: Class

**Description**: class TestOAuthFallback:
    """Test OAuth discovery fallback behavior for legacy (act as AS not RS) servers."""

    @pytest.mark.anyio
    async def test_fallback_discovery_request(self, client_metadata, mock_storage):
        """Test fallback discovery request building."""

        async def redirect_handler(url: str) -> None:
            pass

        async def callback_handler() -> tuple[str, str | None]:
            return "test_auth_code", "test_state"

        provider = OAuthClientProvider(
            server_url="https://api.example.com/v1/mcp",
            client_metadata=client_metadata,
            storage=mock_storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
        )

        # Set up discovery state manually as if path-aware discovery was attempted
        provider.context.discovery_base_url = "https://api.example.com"
        provider.context.discovery_pathname = "/v1/mcp"

        # Test fallback request building
        request = await provider._discover_oauth_metadata_fallback()

        assert request.method == "GET"
        assert str(request.url) == "https://api.example.com/.well-known/oauth-authorization-server"
        assert "mcp-protocol-version" in request.headers

    @pytest.mark.anyio
    async def test_should_attempt_fallback(self, oauth_provider):
        """Test fallback decision logic."""
        # Should attempt fallback on 404 with non-root path
        assert oauth_provider._should_attempt_fallback(404, "/v1/mcp")

        # Should NOT attempt fallback on 404 with root path
        assert not oauth_provider._should_attempt_fallback(404, "/")

        # Should NOT attempt fallback on other status codes
        assert not oauth_provider._should_attempt_fallback(200, "/v1/mcp")
        assert not oauth_provider._should_attempt_fallback(500, "/v1/mcp")

    @pytest.mark.anyio
    async def test_handle_metadata_response_success(self, oauth_provider):
        """Test successful metadata response handling."""
        # Create minimal valid OAuth metadata
        content = b"""{
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize", 
            "token_endpoint": "https://auth.example.com/token"
        }"""
        response = httpx.Response(200, content=content)

        # Should return True (success) and set metadata
        result = await oauth_provider._handle_oauth_metadata_response(response, is_fallback=False)
        assert result is True
        assert oauth_provider.context.oauth_metadata is not None
        assert str(oauth_provider.context.oauth_metadata.issuer) == "https://auth.example.com/"

    @pytest.mark.anyio
    async def test_handle_metadata_response_404_needs_fallback(self, oauth_provider):
        """Test 404 response handling that should trigger fallback."""
        # Set up discovery state for non-root path
        oauth_provider.context.discovery_base_url = "https://api.example.com"
        oauth_provider.context.discovery_pathname = "/v1/mcp"

        # Mock 404 response
        response = httpx.Response(404)

        # Should return False (needs fallback)
        result = await oauth_provider._handle_oauth_metadata_response(response, is_fallback=False)
        assert result is False

    @pytest.mark.anyio
    async def test_handle_metadata_response_404_no_fallback_needed(self, oauth_provider):
        """Test 404 response handling when no fallback is needed."""
        # Set up discovery state for root path
        oauth_provider.context.discovery_base_url = "https://api.example.com"
        oauth_provider.context.discovery_pathname = "/"

        # Mock 404 response
        response = httpx.Response(404)

        # Should return True (no fallback needed)
        result = await oauth_provider._handle_oauth_metadata_response(response, is_fallback=False)
        assert result is True

    @pytest.mark.anyio
    async def test_handle_metadata_response_404_fallback_attempt(self, oauth_provider):
        """Test 404 response handling during fallback attempt."""
        # Mock 404 response during fallback
        response = httpx.Response(404)

        # Should return True (fallback attempt complete, no further action needed)
        result = await oauth_provider._handle_oauth_metadata_response(response, is_fallback=True)
        assert result is True

    @pytest.mark.anyio
    async def test_register_client_request(self, oauth_provider):
        """Test client registration request building."""
        request = await oauth_provider._register_client()

        assert request is not None
        assert request.method == "POST"
        assert str(request.url) == "https://api.example.com/register"
        assert request.headers["Content-Type"] == "application/json"

    @pytest.mark.anyio
    async def test_register_client_skip_if_registered(self, oauth_provider, mock_storage):
        """Test client registration is skipped if already registered."""
        # Set existing client info
        client_info = OAuthClientInformationFull(
            client_id="existing_client",
            redirect_uris=[AnyUrl("http://localhost:3030/callback")],
        )
        oauth_provider.context.client_info = client_info

        # Should return None (skip registration)
        request = await oauth_provider._register_client()
        assert request is None

    @pytest.mark.anyio
    async def test_token_exchange_request(self, oauth_provider):
        """Test token exchange request building."""
        # Set up required context
        oauth_provider.context.client_info = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=[AnyUrl("http://localhost:3030/callback")],
        )

        request = await oauth_provider._exchange_token("test_auth_code", "test_verifier")

        assert request.method == "POST"
        assert str(request.url) == "https://api.example.com/token"
        assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"

        # Check form data
        content = request.content.decode()
        assert "grant_type=authorization_code" in content
        assert "code=test_auth_code" in content
        assert "code_verifier=test_verifier" in content
        assert "client_id=test_client" in content
        assert "client_secret=test_secret" in content

    @pytest.mark.anyio
    async def test_refresh_token_request(self, oauth_provider, valid_tokens):
        """Test refresh token request building."""
        # Set up required context
        oauth_provider.context.current_tokens = valid_tokens
        oauth_provider.context.client_info = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=[AnyUrl("http://localhost:3030/callback")],
        )

        request = await oauth_provider._refresh_token()

        assert request.method == "POST"
        assert str(request.url) == "https://api.example.com/token"
        assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"

        # Check form data
        content = request.content.decode()
        assert "grant_type=refresh_token" in content
        assert "refresh_token=test_refresh_token" in content
        assert "client_id=test_client" in content
        assert "client_secret=test_secret" in content

## TestProtectedResourceMetadata

**Type**: Class

**Description**: class TestProtectedResourceMetadata:
    """Test protected resource handling."""

    @pytest.mark.anyio
    async def test_resource_param_included_with_recent_protocol_version(self, oauth_provider: OAuthClientProvider):
        """Test resource parameter is included for protocol version >= 2025-06-18."""
        # Set protocol version to 2025-06-18
        oauth_provider.context.protocol_version = "2025-06-18"
        oauth_provider.context.client_info = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=[AnyUrl("http://localhost:3030/callback")],
        )

        # Test in token exchange
        request = await oauth_provider._exchange_token("test_code", "test_verifier")
        content = request.content.decode()
        assert "resource=" in content
        # Check URL-encoded resource parameter
        from urllib.parse import quote

        expected_resource = quote(oauth_provider.context.get_resource_url(), safe="")
        assert f"resource={expected_resource}" in content

        # Test in refresh token
        oauth_provider.context.current_tokens = OAuthToken(
            access_token="test_access",
            token_type="Bearer",
            refresh_token="test_refresh",
        )
        refresh_request = await oauth_provider._refresh_token()
        refresh_content = refresh_request.content.decode()
        assert "resource=" in refresh_content

    @pytest.mark.anyio
    async def test_resource_param_excluded_with_old_protocol_version(self, oauth_provider: OAuthClientProvider):
        """Test resource parameter is excluded for protocol version < 2025-06-18."""
        # Set protocol version to older version
        oauth_provider.context.protocol_version = "2025-03-26"
        oauth_provider.context.client_info = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=[AnyUrl("http://localhost:3030/callback")],
        )

        # Test in token exchange
        request = await oauth_provider._exchange_token("test_code", "test_verifier")
        content = request.content.decode()
        assert "resource=" not in content

        # Test in refresh token
        oauth_provider.context.current_tokens = OAuthToken(
            access_token="test_access",
            token_type="Bearer",
            refresh_token="test_refresh",
        )
        refresh_request = await oauth_provider._refresh_token()
        refresh_content = refresh_request.content.decode()
        assert "resource=" not in refresh_content

    @pytest.mark.anyio
    async def test_resource_param_included_with_protected_resource_metadata(self, oauth_provider: OAuthClientProvider):
        """Test resource parameter is always included when protected resource metadata exists."""
        # Set old protocol version but with protected resource metadata
        oauth_provider.context.protocol_version = "2025-03-26"
        oauth_provider.context.protected_resource_metadata = ProtectedResourceMetadata(
            resource=AnyHttpUrl("https://api.example.com/v1/mcp"),
            authorization_servers=[AnyHttpUrl("https://api.example.com")],
        )
        oauth_provider.context.client_info = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=[AnyUrl("http://localhost:3030/callback")],
        )

        # Test in token exchange
        request = await oauth_provider._exchange_token("test_code", "test_verifier")
        content = request.content.decode()
        assert "resource=" in content

## TestAuthFlow

**Type**: Class

**Description**: class TestAuthFlow:
    """Test the auth flow in httpx."""

    @pytest.mark.anyio
    async def test_auth_flow_with_valid_tokens(self, oauth_provider, mock_storage, valid_tokens):
        """Test auth flow when tokens are already valid."""
        # Pre-store valid tokens
        await mock_storage.set_tokens(valid_tokens)
        oauth_provider.context.current_tokens = valid_tokens
        oauth_provider.context.token_expiry_time = time.time() + 1800
        oauth_provider._initialized = True

        # Create a test request
        test_request = httpx.Request("GET", "https://api.example.com/test")

        # Mock the auth flow
        auth_flow = oauth_provider.async_auth_flow(test_request)

        # Should get the request with auth header added
        request = await auth_flow.__anext__()
        assert request.headers["Authorization"] == "Bearer test_access_token"

        # Send a successful response
        response = httpx.Response(200)
        try:
            await auth_flow.asend(response)
        except StopAsyncIteration:
            pass  # Expected

## test_command_execution

**Type**: Function

**Description**: def test_command_execution(mock_config_path: Path):
    """Test that the generated command can actually be executed."""
    # Setup
    server_name = "test_server"
    file_spec = "test_server.py:app"

    # Update config
    success = update_claude_config(file_spec=file_spec, server_name=server_name)
    assert success

    # Read the generated config
    config_file = mock_config_path / "claude_desktop_config.json"
    config = json.loads(config_file.read_text())

    # Get the command and args
    server_config = config["mcpServers"][server_name]
    command = server_config["command"]
    args = server_config["args"]

    test_args = [command] + args + ["--help"]

    result = subprocess.run(test_args, capture_output=True, text=True, timeout=5, check=False)

    assert result.returncode == 0
    assert "usage" in result.stdout.lower()

## test_absolute_uv_path

**Type**: Function

**Description**: def test_absolute_uv_path(mock_config_path: Path):
    """Test that the absolute path to uv is used when available."""
    # Mock the shutil.which function to return a fake path
    mock_uv_path = "/usr/local/bin/uv"

    with patch("mcp.cli.claude.get_uv_path", return_value=mock_uv_path):
        # Setup
        server_name = "test_server"
        file_spec = "test_server.py:app"

        # Update config
        success = update_claude_config(file_spec=file_spec, server_name=server_name)
        assert success

        # Read the generated config
        config_file = mock_config_path / "claude_desktop_config.json"
        config = json.loads(config_file.read_text())

        # Verify the command is the absolute path
        server_config = config["mcpServers"][server_name]
        command = server_config["command"]

        assert command == mock_uv_path

## test_list_tools_cursor_parameter

**Type**: Function

**Description**: async def test_list_tools_cursor_parameter(stream_spy):
    """Test that the cursor parameter is accepted for list_tools
    and that it is correctly passed to the server.

    See: https://modelcontextprotocol.io/specification/2025-03-26/server/utilities/pagination#request-format
    """
    server = FastMCP("test")

    # Create a couple of test tools
    @server.tool(name="test_tool_1")
    async def test_tool_1() -> str:
        """First test tool"""
        return "Result 1"

    @server.tool(name="test_tool_2")
    async def test_tool_2() -> str:
        """Second test tool"""
        return "Result 2"

    async with create_session(server._mcp_server) as client_session:
        spies = stream_spy()

        # Test without cursor parameter (omitted)
        _ = await client_session.list_tools()
        list_tools_requests = spies.get_client_requests(method="tools/list")
        assert len(list_tools_requests) == 1
        assert list_tools_requests[0].params is None

        spies.clear()

        # Test with cursor=None
        _ = await client_session.list_tools(cursor=None)
        list_tools_requests = spies.get_client_requests(method="tools/list")
        assert len(list_tools_requests) == 1
        assert list_tools_requests[0].params is None

        spies.clear()

        # Test with cursor as string
        _ = await client_session.list_tools(cursor="some_cursor_value")
        list_tools_requests = spies.get_client_requests(method="tools/list")
        assert len(list_tools_requests) == 1
        assert list_tools_requests[0].params is not None
        assert list_tools_requests[0].params["cursor"] == "some_cursor_value"

        spies.clear()

        # Test with empty string cursor
        _ = await client_session.list_tools(cursor="")
        list_tools_requests = spies.get_client_requests(method="tools/list")
        assert len(list_tools_requests) == 1
        assert list_tools_requests[0].params is not None
        assert list_tools_requests[0].params["cursor"] == ""

## test_list_resources_cursor_parameter

**Type**: Function

**Description**: async def test_list_resources_cursor_parameter(stream_spy):
    """Test that the cursor parameter is accepted for list_resources
    and that it is correctly passed to the server.

    See: https://modelcontextprotocol.io/specification/2025-03-26/server/utilities/pagination#request-format
    """
    server = FastMCP("test")

    # Create a test resource
    @server.resource("resource://test/data")
    async def test_resource() -> str:
        """Test resource"""
        return "Test data"

    async with create_session(server._mcp_server) as client_session:
        spies = stream_spy()

        # Test without cursor parameter (omitted)
        _ = await client_session.list_resources()
        list_resources_requests = spies.get_client_requests(method="resources/list")
        assert len(list_resources_requests) == 1
        assert list_resources_requests[0].params is None

        spies.clear()

        # Test with cursor=None
        _ = await client_session.list_resources(cursor=None)
        list_resources_requests = spies.get_client_requests(method="resources/list")
        assert len(list_resources_requests) == 1
        assert list_resources_requests[0].params is None

        spies.clear()

        # Test with cursor as string
        _ = await client_session.list_resources(cursor="some_cursor")
        list_resources_requests = spies.get_client_requests(method="resources/list")
        assert len(list_resources_requests) == 1
        assert list_resources_requests[0].params is not None
        assert list_resources_requests[0].params["cursor"] == "some_cursor"

        spies.clear()

        # Test with empty string cursor
        _ = await client_session.list_resources(cursor="")
        list_resources_requests = spies.get_client_requests(method="resources/list")
        assert len(list_resources_requests) == 1
        assert list_resources_requests[0].params is not None
        assert list_resources_requests[0].params["cursor"] == ""

## test_list_prompts_cursor_parameter

**Type**: Function

**Description**: async def test_list_prompts_cursor_parameter(stream_spy):
    """Test that the cursor parameter is accepted for list_prompts
    and that it is correctly passed to the server.
    See: https://modelcontextprotocol.io/specification/2025-03-26/server/utilities/pagination#request-format
    """
    server = FastMCP("test")

    # Create a test prompt
    @server.prompt()
    async def test_prompt(name: str) -> str:
        """Test prompt"""
        return f"Hello, {name}!"

    async with create_session(server._mcp_server) as client_session:
        spies = stream_spy()

        # Test without cursor parameter (omitted)
        _ = await client_session.list_prompts()
        list_prompts_requests = spies.get_client_requests(method="prompts/list")
        assert len(list_prompts_requests) == 1
        assert list_prompts_requests[0].params is None

        spies.clear()

        # Test with cursor=None
        _ = await client_session.list_prompts(cursor=None)
        list_prompts_requests = spies.get_client_requests(method="prompts/list")
        assert len(list_prompts_requests) == 1
        assert list_prompts_requests[0].params is None

        spies.clear()

        # Test with cursor as string
        _ = await client_session.list_prompts(cursor="some_cursor")
        list_prompts_requests = spies.get_client_requests(method="prompts/list")
        assert len(list_prompts_requests) == 1
        assert list_prompts_requests[0].params is not None
        assert list_prompts_requests[0].params["cursor"] == "some_cursor"

        spies.clear()

        # Test with empty string cursor
        _ = await client_session.list_prompts(cursor="")
        list_prompts_requests = spies.get_client_requests(method="prompts/list")
        assert len(list_prompts_requests) == 1
        assert list_prompts_requests[0].params is not None
        assert list_prompts_requests[0].params["cursor"] == ""

## test_list_resource_templates_cursor_parameter

**Type**: Function

**Description**: async def test_list_resource_templates_cursor_parameter(stream_spy):
    """Test that the cursor parameter is accepted for list_resource_templates
    and that it is correctly passed to the server.

    See: https://modelcontextprotocol.io/specification/2025-03-26/server/utilities/pagination#request-format
    """
    server = FastMCP("test")

    # Create a test resource template
    @server.resource("resource://test/{name}")
    async def test_template(name: str) -> str:
        """Test resource template"""
        return f"Data for {name}"

    async with create_session(server._mcp_server) as client_session:
        spies = stream_spy()

        # Test without cursor parameter (omitted)
        _ = await client_session.list_resource_templates()
        list_templates_requests = spies.get_client_requests(method="resources/templates/list")
        assert len(list_templates_requests) == 1
        assert list_templates_requests[0].params is None

        spies.clear()

        # Test with cursor=None
        _ = await client_session.list_resource_templates(cursor=None)
        list_templates_requests = spies.get_client_requests(method="resources/templates/list")
        assert len(list_templates_requests) == 1
        assert list_templates_requests[0].params is None

        spies.clear()

        # Test with cursor as string
        _ = await client_session.list_resource_templates(cursor="some_cursor")
        list_templates_requests = spies.get_client_requests(method="resources/templates/list")
        assert len(list_templates_requests) == 1
        assert list_templates_requests[0].params is not None
        assert list_templates_requests[0].params["cursor"] == "some_cursor"

        spies.clear()

        # Test with empty string cursor
        _ = await client_session.list_resource_templates(cursor="")
        list_templates_requests = spies.get_client_requests(method="resources/templates/list")
        assert len(list_templates_requests) == 1
        assert list_templates_requests[0].params is not None
        assert list_templates_requests[0].params["cursor"] == ""

## LoggingCollector

**Type**: Class

**Description**: class LoggingCollector:
    def __init__(self):
        self.log_messages: list[LoggingMessageNotificationParams] = []

    async def __call__(self, params: LoggingMessageNotificationParams) -> None:
        self.log_messages.append(params)

## TestClientOutputSchemaValidation

**Type**: Class

**Description**: class TestClientOutputSchemaValidation:
    """Test client-side validation of structured output from tools"""

    @pytest.mark.anyio
    async def test_tool_structured_output_client_side_validation_basemodel(self):
        """Test that client validates structured content against schema for BaseModel outputs"""
        # Create a malicious low-level server that returns invalid structured content
        server = Server("test-server")

        # Define the expected schema for our tool
        output_schema = {
            "type": "object",
            "properties": {"name": {"type": "string", "title": "Name"}, "age": {"type": "integer", "title": "Age"}},
            "required": ["name", "age"],
            "title": "UserOutput",
        }

        @server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="get_user",
                    description="Get user data",
                    inputSchema={"type": "object"},
                    outputSchema=output_schema,
                )
            ]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            # Return invalid structured content - age is string instead of integer
            # The low-level server will wrap this in CallToolResult
            return {"name": "John", "age": "invalid"}  # Invalid: age should be int

        # Test that client validates the structured content
        with bypass_server_output_validation():
            async with client_session(server) as client:
                # The client validates structured content and should raise an error
                with pytest.raises(RuntimeError) as exc_info:
                    await client.call_tool("get_user", {})
                # Verify it's a validation error
                assert "Invalid structured content returned by tool get_user" in str(exc_info.value)

    @pytest.mark.anyio
    async def test_tool_structured_output_client_side_validation_primitive(self):
        """Test that client validates structured content for primitive outputs"""
        server = Server("test-server")

        # Primitive types are wrapped in {"result": value}
        output_schema = {
            "type": "object",
            "properties": {"result": {"type": "integer", "title": "Result"}},
            "required": ["result"],
            "title": "calculate_Output",
        }

        @server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="calculate",
                    description="Calculate something",
                    inputSchema={"type": "object"},
                    outputSchema=output_schema,
                )
            ]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            # Return invalid structured content - result is string instead of integer
            return {"result": "not_a_number"}  # Invalid: should be int

        with bypass_server_output_validation():
            async with client_session(server) as client:
                # The client validates structured content and should raise an error
                with pytest.raises(RuntimeError) as exc_info:
                    await client.call_tool("calculate", {})
                assert "Invalid structured content returned by tool calculate" in str(exc_info.value)

    @pytest.mark.anyio
    async def test_tool_structured_output_client_side_validation_dict_typed(self):
        """Test that client validates dict[str, T] structured content"""
        server = Server("test-server")

        # dict[str, int] schema
        output_schema = {"type": "object", "additionalProperties": {"type": "integer"}, "title": "get_scores_Output"}

        @server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="get_scores",
                    description="Get scores",
                    inputSchema={"type": "object"},
                    outputSchema=output_schema,
                )
            ]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            # Return invalid structured content - values should be integers
            return {"alice": "100", "bob": "85"}  # Invalid: values should be int

        with bypass_server_output_validation():
            async with client_session(server) as client:
                # The client validates structured content and should raise an error
                with pytest.raises(RuntimeError) as exc_info:
                    await client.call_tool("get_scores", {})
                assert "Invalid structured content returned by tool get_scores" in str(exc_info.value)

    @pytest.mark.anyio
    async def test_tool_structured_output_client_side_validation_missing_required(self):
        """Test that client validates missing required fields"""
        server = Server("test-server")

        output_schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}, "age": {"type": "integer"}, "email": {"type": "string"}},
            "required": ["name", "age", "email"],  # All fields required
            "title": "PersonOutput",
        }

        @server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="get_person",
                    description="Get person data",
                    inputSchema={"type": "object"},
                    outputSchema=output_schema,
                )
            ]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            # Return structured content missing required field 'email'
            return {"name": "John", "age": 30}  # Missing required 'email'

        with bypass_server_output_validation():
            async with client_session(server) as client:
                # The client validates structured content and should raise an error
                with pytest.raises(RuntimeError) as exc_info:
                    await client.call_tool("get_person", {})
                assert "Invalid structured content returned by tool get_person" in str(exc_info.value)

    @pytest.mark.anyio
    async def test_tool_not_listed_warning(self, caplog):
        """Test that client logs warning when tool is not in list_tools but has outputSchema"""
        server = Server("test-server")

        @server.list_tools()
        async def list_tools():
            # Return empty list - tool is not listed
            return []

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            # Server still responds to the tool call with structured content
            return {"result": 42}

        # Set logging level to capture warnings
        caplog.set_level(logging.WARNING)

        with bypass_server_output_validation():
            async with client_session(server) as client:
                # Call a tool that wasn't listed
                result = await client.call_tool("mystery_tool", {})
                assert result.structuredContent == {"result": 42}
                assert result.isError is False

                # Check that warning was logged
                assert "Tool mystery_tool not listed" in caplog.text

## test_list_tools_returns_all_tools

**Type**: Function

**Description**: async def test_list_tools_returns_all_tools():
    mcp = FastMCP("TestTools")

    # Create 100 tools with unique names
    num_tools = 100
    for i in range(num_tools):

        @mcp.tool(name=f"tool_{i}")
        def dummy_tool_func():
            f"""Tool number {i}"""
            return i

        globals()[f"dummy_tool_{i}"] = dummy_tool_func  # Keep reference to avoid garbage collection

    # Get all tools
    tools = await mcp.list_tools()

    # Verify we get all tools
    assert len(tools) == num_tools, f"Expected {num_tools} tools, but got {len(tools)}"

    # Verify each tool is unique and has the correct name
    tool_names = [tool.name for tool in tools]
    expected_names = [f"tool_{i}" for i in range(num_tools)]
    assert sorted(tool_names) == sorted(expected_names), "Tool names don't match expected names"

## test_fastmcp_resource_mime_type

**Type**: Function

**Description**: async def test_fastmcp_resource_mime_type():
    """Test that mime_type parameter is respected for resources."""
    mcp = FastMCP("test")

    # Create a small test image as bytes
    image_bytes = b"fake_image_data"
    base64_string = base64.b64encode(image_bytes).decode("utf-8")

    @mcp.resource("test://image", mime_type="image/png")
    def get_image_as_string() -> str:
        """Return a test image as base64 string."""
        return base64_string

    @mcp.resource("test://image_bytes", mime_type="image/png")
    def get_image_as_bytes() -> bytes:
        """Return a test image as bytes."""
        return image_bytes

    # Test that resources are listed with correct mime type
    async with client_session(mcp._mcp_server) as client:
        # List resources and verify mime types
        resources = await client.list_resources()
        assert resources.resources is not None

        mapping = {str(r.uri): r for r in resources.resources}

        # Find our resources
        string_resource = mapping["test://image"]
        bytes_resource = mapping["test://image_bytes"]

        # Verify mime types
        assert string_resource.mimeType == "image/png", "String resource mime type not respected"
        assert bytes_resource.mimeType == "image/png", "Bytes resource mime type not respected"

        # Also verify the content can be read correctly
        string_result = await client.read_resource(AnyUrl("test://image"))
        assert len(string_result.contents) == 1
        assert getattr(string_result.contents[0], "text") == base64_string, "Base64 string mismatch"
        assert string_result.contents[0].mimeType == "image/png", "String content mime type not preserved"

        bytes_result = await client.read_resource(AnyUrl("test://image_bytes"))
        assert len(bytes_result.contents) == 1
        assert base64.b64decode(getattr(bytes_result.contents[0], "blob")) == image_bytes, "Bytes mismatch"
        assert bytes_result.contents[0].mimeType == "image/png", "Bytes content mime type not preserved"

## test_lowlevel_resource_mime_type

**Type**: Function

**Description**: async def test_lowlevel_resource_mime_type():
    """Test that mime_type parameter is respected for resources."""
    server = Server("test")

    # Create a small test image as bytes
    image_bytes = b"fake_image_data"
    base64_string = base64.b64encode(image_bytes).decode("utf-8")

    # Create test resources with specific mime types
    test_resources = [
        types.Resource(uri=AnyUrl("test://image"), name="test image", mimeType="image/png"),
        types.Resource(
            uri=AnyUrl("test://image_bytes"),
            name="test image bytes",
            mimeType="image/png",
        ),
    ]

    @server.list_resources()
    async def handle_list_resources():
        return test_resources

    @server.read_resource()
    async def handle_read_resource(uri: AnyUrl):
        if str(uri) == "test://image":
            return [ReadResourceContents(content=base64_string, mime_type="image/png")]
        elif str(uri) == "test://image_bytes":
            return [ReadResourceContents(content=bytes(image_bytes), mime_type="image/png")]
        raise Exception(f"Resource not found: {uri}")

    # Test that resources are listed with correct mime type
    async with client_session(server) as client:
        # List resources and verify mime types
        resources = await client.list_resources()
        assert resources.resources is not None

        mapping = {str(r.uri): r for r in resources.resources}

        # Find our resources
        string_resource = mapping["test://image"]
        bytes_resource = mapping["test://image_bytes"]

        # Verify mime types
        assert string_resource.mimeType == "image/png", "String resource mime type not respected"
        assert bytes_resource.mimeType == "image/png", "Bytes resource mime type not respected"

        # Also verify the content can be read correctly
        string_result = await client.read_resource(AnyUrl("test://image"))
        assert len(string_result.contents) == 1
        assert getattr(string_result.contents[0], "text") == base64_string, "Base64 string mismatch"
        assert string_result.contents[0].mimeType == "image/png", "String content mime type not preserved"

        bytes_result = await client.read_resource(AnyUrl("test://image_bytes"))
        assert len(bytes_result.contents) == 1
        assert base64.b64decode(getattr(bytes_result.contents[0], "blob")) == image_bytes, "Bytes mismatch"
        assert bytes_result.contents[0].mimeType == "image/png", "Bytes content mime type not preserved"

## test_progress_token_zero_first_call

**Type**: Function

**Description**: async def test_progress_token_zero_first_call():
    """Test that progress notifications work when progress_token is 0 on first call."""

    # Create mock session with progress notification tracking
    mock_session = AsyncMock()
    mock_session.send_progress_notification = AsyncMock()

    # Create request context with progress token 0
    mock_meta = MagicMock()
    mock_meta.progressToken = 0  # This is the key test case - token is 0

    request_context = RequestContext(
        request_id="test-request",
        session=mock_session,
        meta=mock_meta,
        lifespan_context=None,
    )

    # Create context with our mocks
    ctx = Context(request_context=request_context, fastmcp=MagicMock())

    # Test progress reporting
    await ctx.report_progress(0, 10)  # First call with 0
    await ctx.report_progress(5, 10)  # Middle progress
    await ctx.report_progress(10, 10)  # Complete

    # Verify progress notifications
    assert mock_session.send_progress_notification.call_count == 3, "All progress notifications should be sent"
    mock_session.send_progress_notification.assert_any_call(progress_token=0, progress=0.0, total=10.0, message=None)
    mock_session.send_progress_notification.assert_any_call(progress_token=0, progress=5.0, total=10.0, message=None)
    mock_session.send_progress_notification.assert_any_call(progress_token=0, progress=10.0, total=10.0, message=None)

## main

**Type**: Function

**Description**: def main():
    anyio.run(test_messages_are_executed_concurrently)

## Database

**Type**: Class

**Description**: class Database:  # Replace with your actual DB type
    @classmethod
    async def connect(cls):
        return cls()

    async def disconnect(self):
        pass

    def query(self):
        return "Hello, World!"

## run_tool_test

**Type**: Function

**Description**: async def run_tool_test(
    tools: list[Tool],
    call_tool_handler: Callable[[str, dict[str, Any]], Awaitable[list[TextContent]]],
    test_callback: Callable[[ClientSession], Awaitable[CallToolResult]],
) -> CallToolResult:
    """Helper to run a tool test with minimal boilerplate.

    Args:
        tools: List of tools to register
        call_tool_handler: Handler function for tool calls
        test_callback: Async function that performs the test using the client session

    Returns:
        The result of the tool call
    """
    server = Server("test")

    @server.list_tools()
    async def list_tools():
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        return await call_tool_handler(name, arguments)

    server_to_client_send, server_to_client_receive = anyio.create_memory_object_stream[SessionMessage](10)
    client_to_server_send, client_to_server_receive = anyio.create_memory_object_stream[SessionMessage](10)

    # Message handler for client
    async def message_handler(
        message: RequestResponder[ServerRequest, ClientResult] | ServerNotification | Exception,
    ) -> None:
        if isinstance(message, Exception):
            raise message

    # Server task
    async def run_server():
        async with ServerSession(
            client_to_server_receive,
            server_to_client_send,
            InitializationOptions(
                server_name="test-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        ) as server_session:
            async with anyio.create_task_group() as tg:

                async def handle_messages():
                    async for message in server_session.incoming_messages:
                        await server._handle_message(message, server_session, {}, False)

                tg.start_soon(handle_messages)
                await anyio.sleep_forever()

    # Run the test
    async with anyio.create_task_group() as tg:
        tg.start_soon(run_server)

        async with ClientSession(
            server_to_client_receive,
            client_to_server_send,
            message_handler=message_handler,
        ) as client_session:
            # Initialize the session
            await client_session.initialize()

            # Run the test callback
            result = await test_callback(client_session)

            # Cancel the server task
            tg.cancel_scope.cancel()

    return result

## create_add_tool

**Type**: Function

**Description**: def create_add_tool() -> Tool:
    """Create a standard 'add' tool for testing."""
    return Tool(
        name="add",
        description="Add two numbers",
        inputSchema={
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
            },
            "required": ["a", "b"],
            "additionalProperties": False,
        },
    )

## run_tool_test

**Type**: Function

**Description**: async def run_tool_test(
    tools: list[Tool],
    call_tool_handler: Callable[[str, dict[str, Any]], Awaitable[Any]],
    test_callback: Callable[[ClientSession], Awaitable[CallToolResult]],
) -> CallToolResult:
    """Helper to run a tool test with minimal boilerplate.

    Args:
        tools: List of tools to register
        call_tool_handler: Handler function for tool calls
        test_callback: Async function that performs the test using the client session

    Returns:
        The result of the tool call
    """
    server = Server("test")

    @server.list_tools()
    async def list_tools():
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]):
        return await call_tool_handler(name, arguments)

    server_to_client_send, server_to_client_receive = anyio.create_memory_object_stream[SessionMessage](10)
    client_to_server_send, client_to_server_receive = anyio.create_memory_object_stream[SessionMessage](10)

    # Message handler for client
    async def message_handler(
        message: RequestResponder[ServerRequest, ClientResult] | ServerNotification | Exception,
    ) -> None:
        if isinstance(message, Exception):
            raise message

    # Server task
    async def run_server():
        async with ServerSession(
            client_to_server_receive,
            server_to_client_send,
            InitializationOptions(
                server_name="test-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        ) as server_session:
            async with anyio.create_task_group() as tg:

                async def handle_messages():
                    async for message in server_session.incoming_messages:
                        await server._handle_message(message, server_session, {}, False)

                tg.start_soon(handle_messages)
                await anyio.sleep_forever()

    # Run the test
    async with anyio.create_task_group() as tg:
        tg.start_soon(run_server)

        async with ClientSession(
            server_to_client_receive,
            client_to_server_send,
            message_handler=message_handler,
        ) as client_session:
            # Initialize the session
            await client_session.initialize()

            # Run the test callback
            result = await test_callback(client_session)

            # Cancel the server task
            tg.cancel_scope.cancel()

    return result

## SecurityTestServer

**Type**: Class

**Description**: class SecurityTestServer(Server):
    def __init__(self):
        super().__init__(SERVER_NAME)

    async def on_list_tools(self) -> list[Tool]:
        return []

## run_server_with_settings

**Type**: Function

**Description**: def run_server_with_settings(port: int, security_settings: TransportSecuritySettings | None = None):
    """Run the SSE server with specified security settings."""
    app = SecurityTestServer()
    sse_transport = SseServerTransport("/messages/", security_settings)

    async def handle_sse(request: Request):
        try:
            async with sse_transport.connect_sse(request.scope, request.receive, request._send) as streams:
                if streams:
                    await app.run(streams[0], streams[1], app.create_initialization_options())
        except ValueError as e:
            # Validation error was already handled inside connect_sse
            logger.debug(f"SSE connection failed validation: {e}")
        return Response()

    routes = [
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse_transport.handle_post_message),
    ]

    starlette_app = Starlette(routes=routes)
    uvicorn.run(starlette_app, host="127.0.0.1", port=port, log_level="error")

## start_server_process

**Type**: Function

**Description**: def start_server_process(port: int, security_settings: TransportSecuritySettings | None = None):
    """Start server in a separate process."""
    process = multiprocessing.Process(target=run_server_with_settings, args=(port, security_settings))
    process.start()
    # Give server time to start
    time.sleep(1)
    return process

## SecurityTestServer

**Type**: Class

**Description**: class SecurityTestServer(Server):
    def __init__(self):
        super().__init__(SERVER_NAME)

    async def on_list_tools(self) -> list[Tool]:
        return []

## run_server_with_settings

**Type**: Function

**Description**: def run_server_with_settings(port: int, security_settings: TransportSecuritySettings | None = None):
    """Run the StreamableHTTP server with specified security settings."""
    app = SecurityTestServer()

    # Create session manager with security settings
    session_manager = StreamableHTTPSessionManager(
        app=app,
        json_response=False,
        stateless=False,
        security_settings=security_settings,
    )

    # Create the ASGI handler
    async def handle_streamable_http(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    # Create Starlette app with lifespan
    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncGenerator[None, None]:
        async with session_manager.run():
            yield

    routes = [
        Mount("/", app=handle_streamable_http),
    ]

    starlette_app = Starlette(routes=routes, lifespan=lifespan)
    uvicorn.run(starlette_app, host="127.0.0.1", port=port, log_level="error")

## start_server_process

**Type**: Function

**Description**: def start_server_process(port: int, security_settings: TransportSecuritySettings | None = None):
    """Start server in a separate process."""
    process = multiprocessing.Process(target=run_server_with_settings, args=(port, security_settings))
    process.start()
    # Give server time to start
    time.sleep(1)
    return process

## TestRegistrationErrorHandling

**Type**: Class

**Description**: class TestRegistrationErrorHandling:
    @pytest.mark.anyio
    async def test_registration_error_handling(self, client, oauth_provider):
        # Mock the register_client method to raise a registration error
        with unittest.mock.patch.object(
            oauth_provider,
            "register_client",
            side_effect=RegistrationError(
                error="invalid_redirect_uri",
                error_description="The redirect URI is invalid",
            ),
        ):
            # Prepare a client registration request
            client_data = {
                "redirect_uris": ["https://client.example.com/callback"],
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "client_name": "Test Client",
            }

            # Send the registration request
            response = await client.post(
                "/register",
                json=client_data,
            )

            # Verify the response
            assert response.status_code == 400, response.content
            data = response.json()
            assert data["error"] == "invalid_redirect_uri"
            assert data["error_description"] == "The redirect URI is invalid"

## TestAuthorizeErrorHandling

**Type**: Class

**Description**: class TestAuthorizeErrorHandling:
    @pytest.mark.anyio
    async def test_authorize_error_handling(self, client, oauth_provider, registered_client, pkce_challenge):
        # Mock the authorize method to raise an authorize error
        with unittest.mock.patch.object(
            oauth_provider,
            "authorize",
            side_effect=AuthorizeError(error="access_denied", error_description="The user denied the request"),
        ):
            # Register the client
            client_id = registered_client["client_id"]
            redirect_uri = registered_client["redirect_uris"][0]

            # Prepare an authorization request
            params = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_state",
            }

            # Send the authorization request
            response = await client.get("/authorize", params=params)

            # Verify the response is a redirect with error parameters
            assert response.status_code == 302
            redirect_url = response.headers["location"]
            parsed_url = urlparse(redirect_url)
            query_params = parse_qs(parsed_url.query)

            assert query_params["error"][0] == "access_denied"
            assert "error_description" in query_params
            assert query_params["state"][0] == "test_state"

## TestTokenErrorHandling

**Type**: Class

**Description**: class TestTokenErrorHandling:
    @pytest.mark.anyio
    async def test_token_error_handling_auth_code(self, client, oauth_provider, registered_client, pkce_challenge):
        # Register the client and get an auth code
        client_id = registered_client["client_id"]
        client_secret = registered_client["client_secret"]
        redirect_uri = registered_client["redirect_uris"][0]

        # First get an authorization code
        auth_response = await client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )

        redirect_url = auth_response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)
        code = query_params["code"][0]

        # Mock the exchange_authorization_code method to raise a token error
        with unittest.mock.patch.object(
            oauth_provider,
            "exchange_authorization_code",
            side_effect=TokenError(
                error="invalid_grant",
                error_description="The authorization code is invalid",
            ),
        ):
            # Try to exchange the code for tokens
            token_response = await client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code_verifier": pkce_challenge["code_verifier"],
                },
            )

            # Verify the response
            assert token_response.status_code == 400
            data = token_response.json()
            assert data["error"] == "invalid_grant"
            assert data["error_description"] == "The authorization code is invalid"

    @pytest.mark.anyio
    async def test_token_error_handling_refresh_token(self, client, oauth_provider, registered_client, pkce_challenge):
        # Register the client and get tokens
        client_id = registered_client["client_id"]
        client_secret = registered_client["client_secret"]
        redirect_uri = registered_client["redirect_uris"][0]

        # First get an authorization code
        auth_response = await client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )
        assert auth_response.status_code == 302, auth_response.content

        redirect_url = auth_response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)
        code = query_params["code"][0]

        # Exchange the code for tokens
        token_response = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
                "code_verifier": pkce_challenge["code_verifier"],
            },
        )

        tokens = token_response.json()
        refresh_token = tokens["refresh_token"]

        # Mock the exchange_refresh_token method to raise a token error
        with unittest.mock.patch.object(
            oauth_provider,
            "exchange_refresh_token",
            side_effect=TokenError(
                error="invalid_scope",
                error_description="The requested scope is invalid",
            ),
        ):
            # Try to use the refresh token
            refresh_response = await client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
            )

            # Verify the response
            assert refresh_response.status_code == 400
            data = refresh_response.json()
            assert data["error"] == "invalid_scope"
            assert data["error_description"] == "The requested scope is invalid"

## MockApp

**Type**: Class

**Description**: class MockApp:
    """Mock ASGI app for testing."""

    def __init__(self):
        self.called = False
        self.scope: Scope | None = None
        self.receive: Receive | None = None
        self.send: Send | None = None
        self.access_token_during_call: AccessToken | None = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.called = True
        self.scope = scope
        self.receive = receive
        self.send = send
        # Check the context during the call
        self.access_token_during_call = get_access_token()

## MockOAuthProvider

**Type**: Class

**Description**: class MockOAuthProvider:
    """Mock OAuth provider for testing.

    This is a simplified version that only implements the methods needed for testing
    the BearerAuthMiddleware components.
    """

    def __init__(self):
        self.tokens = {}  # token -> AccessToken

    def add_token(self, token: str, access_token: AccessToken) -> None:
        """Add a token to the provider."""
        self.tokens[token] = access_token

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load an access token."""
        return self.tokens.get(token)

## add_token_to_provider

**Type**: Function

**Description**: def add_token_to_provider(
    provider: OAuthAuthorizationServerProvider[Any, Any, Any],
    token: str,
    access_token: AccessToken,
) -> None:
    """Helper function to add a token to a provider.

    This is used to work around type checking issues with our mock provider.
    """
    # We know this is actually a MockOAuthProvider
    mock_provider = cast(MockOAuthProvider, provider)
    mock_provider.add_token(token, access_token)

## MockApp

**Type**: Class

**Description**: class MockApp:
    """Mock ASGI app for testing."""

    def __init__(self):
        self.called = False
        self.scope: Scope | None = None
        self.receive: Receive | None = None
        self.send: Send | None = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.called = True
        self.scope = scope
        self.receive = receive
        self.send = send

## AnswerSchema

**Type**: Class

**Description**: class AnswerSchema(BaseModel):
    answer: str = Field(description="The user's answer to the question")

## create_ask_user_tool

**Type**: Function

**Description**: def create_ask_user_tool(mcp: FastMCP):
    """Create a standard ask_user tool that handles all elicitation responses."""

    @mcp.tool(description="A tool that uses elicitation")
    async def ask_user(prompt: str, ctx: Context) -> str:
        result = await ctx.elicit(
            message=f"Tool wants to ask: {prompt}",
            schema=AnswerSchema,
        )

        if result.action == "accept" and result.data:
            return f"User answered: {result.data.answer}"
        elif result.action == "decline":
            return "User declined to answer"
        else:
            return "User cancelled"

    return ask_user

## call_tool_and_assert

**Type**: Function

**Description**: async def call_tool_and_assert(
    mcp: FastMCP,
    elicitation_callback,
    tool_name: str,
    args: dict,
    expected_text: str | None = None,
    text_contains: list[str] | None = None,
):
    """Helper to create session, call tool, and assert result."""
    async with create_connected_server_and_client_session(
        mcp._mcp_server, elicitation_callback=elicitation_callback
    ) as client_session:
        await client_session.initialize()

        result = await client_session.call_tool(tool_name, args)
        assert len(result.content) == 1
        assert isinstance(result.content[0], TextContent)

        if expected_text is not None:
            assert result.content[0].text == expected_text
        elif text_contains is not None:
            for substring in text_contains:
                assert substring in result.content[0].text

        return result

## SomeInputModelA

**Type**: Class

**Description**: class SomeInputModelA(BaseModel):
    pass

## SomeInputModelB

**Type**: Class

**Description**: class SomeInputModelB(BaseModel):
    class InnerModel(BaseModel):
        x: int

    how_many_shrimp: Annotated[int, Field(description="How many shrimp in the tank???")]
    ok: InnerModel
    y: None

## complex_arguments_fn

**Type**: Function

**Description**: def complex_arguments_fn(
    an_int: int,
    must_be_none: None,
    must_be_none_dumb_annotation: Annotated[None, "blah"],
    list_of_ints: list[int],
    # list[str] | str is an interesting case because if it comes in as JSON like
    # "[\"a\", \"b\"]" then it will be naively parsed as a string.
    list_str_or_str: list[str] | str,
    an_int_annotated_with_field: Annotated[int, Field(description="An int with a field")],
    an_int_annotated_with_field_and_others: Annotated[
        int,
        str,  # Should be ignored, really
        Field(description="An int with a field"),
        annotated_types.Gt(1),
    ],
    an_int_annotated_with_junk: Annotated[
        int,
        "123",
        456,
    ],
    field_with_default_via_field_annotation_before_nondefault_arg: Annotated[int, Field(1)],
    unannotated,
    my_model_a: SomeInputModelA,
    my_model_a_forward_ref: "SomeInputModelA",
    my_model_b: SomeInputModelB,
    an_int_annotated_with_field_default: Annotated[
        int,
        Field(1, description="An int with a field"),
    ],
    unannotated_with_default=5,
    my_model_a_with_default: SomeInputModelA = SomeInputModelA(),  # noqa: B008
    an_int_with_default: int = 1,
    must_be_none_with_default: None = None,
    an_int_with_equals_field: int = Field(1, ge=0),
    int_annotated_with_default: Annotated[int, Field(description="hey")] = 5,
) -> str:
    _ = (
        an_int,
        must_be_none,
        must_be_none_dumb_annotation,
        list_of_ints,
        list_str_or_str,
        an_int_annotated_with_field,
        an_int_annotated_with_field_and_others,
        an_int_annotated_with_junk,
        field_with_default_via_field_annotation_before_nondefault_arg,
        unannotated,
        an_int_annotated_with_field_default,
        unannotated_with_default,
        my_model_a,
        my_model_a_forward_ref,
        my_model_b,
        my_model_a_with_default,
        an_int_with_default,
        must_be_none_with_default,
        an_int_with_equals_field,
        int_annotated_with_default,
    )
    return "ok!"

## test_str_vs_list_str

**Type**: Function

**Description**: def test_str_vs_list_str():
    """Test handling of string vs list[str] type annotations.

    This is tricky as '"hello"' can be parsed as a JSON string or a Python string.
    We want to make sure it's kept as a python string.
    """

    def func_with_str_types(str_or_list: str | list[str]):
        return str_or_list

    meta = func_metadata(func_with_str_types)

    # Test string input for union type
    result = meta.pre_parse_json({"str_or_list": "hello"})
    assert result["str_or_list"] == "hello"

    # Test string input that contains valid JSON for union type
    # We want to see here that the JSON-vali string is NOT parsed as JSON, but rather
    # kept as a raw string
    result = meta.pre_parse_json({"str_or_list": '"hello"'})
    assert result["str_or_list"] == '"hello"'

    # Test list input for union type
    result = meta.pre_parse_json({"str_or_list": '["hello", "world"]'})
    assert result["str_or_list"] == ["hello", "world"]

## test_skip_names

**Type**: Function

**Description**: def test_skip_names():
    """Test that skipped parameters are not included in the model"""

    def func_with_many_params(keep_this: int, skip_this: str, also_keep: float, also_skip: bool):
        return keep_this, skip_this, also_keep, also_skip

    # Skip some parameters
    meta = func_metadata(func_with_many_params, skip_names=["skip_this", "also_skip"])

    # Check model fields
    assert "keep_this" in meta.arg_model.model_fields
    assert "also_keep" in meta.arg_model.model_fields
    assert "skip_this" not in meta.arg_model.model_fields
    assert "also_skip" not in meta.arg_model.model_fields

    # Validate that we can call with only non-skipped parameters
    model: BaseModel = meta.arg_model.model_validate({"keep_this": 1, "also_keep": 2.5})  # type: ignore
    assert model.keep_this == 1  # type: ignore
    assert model.also_keep == 2.5  # type: ignore

## test_structured_output_dict_str_types

**Type**: Function

**Description**: def test_structured_output_dict_str_types():
    """Test that dict[str, T] types are handled without wrapping."""

    # Test dict[str, Any]
    def func_dict_any() -> dict[str, Any]:
        return {"a": 1, "b": "hello", "c": [1, 2, 3]}

    meta = func_metadata(func_dict_any)
    assert meta.output_schema == {
        "type": "object",
        "title": "func_dict_anyDictOutput",
    }

    # Test dict[str, str]
    def func_dict_str() -> dict[str, str]:
        return {"name": "John", "city": "NYC"}

    meta = func_metadata(func_dict_str)
    assert meta.output_schema == {
        "type": "object",
        "additionalProperties": {"type": "string"},
        "title": "func_dict_strDictOutput",
    }

    # Test dict[str, list[int]]
    def func_dict_list() -> dict[str, list[int]]:
        return {"nums": [1, 2, 3], "more": [4, 5, 6]}

    meta = func_metadata(func_dict_list)
    assert meta.output_schema == {
        "type": "object",
        "additionalProperties": {"type": "array", "items": {"type": "integer"}},
        "title": "func_dict_listDictOutput",
    }

    # Test dict[int, str] - should be wrapped since key is not str
    def func_dict_int_key() -> dict[int, str]:
        return {1: "a", 2: "b"}

    meta = func_metadata(func_dict_int_key)
    assert meta.output_schema is not None
    assert "result" in meta.output_schema["properties"]

## test_complex_function_json_schema

**Type**: Function

**Description**: def test_complex_function_json_schema():
    """Test JSON schema generation for complex function arguments.

    Note: Different versions of pydantic output slightly different
    JSON Schema formats for model fields with defaults. The format changed in 2.9.0:

    1. Before 2.9.0:
       {
         "allOf": [{"$ref": "#/$defs/Model"}],
         "default": {}
       }

    2. Since 2.9.0:
       {
         "$ref": "#/$defs/Model",
         "default": {}
       }

    Both formats are valid and functionally equivalent. This test accepts either format
    to ensure compatibility across our supported pydantic versions.

    This change in format does not affect runtime behavior since:
    1. Both schemas validate the same way
    2. The actual model classes and validation logic are unchanged
    3. func_metadata uses model_validate/model_dump, not the schema directly
    """
    meta = func_metadata(complex_arguments_fn)
    actual_schema = meta.arg_model.model_json_schema()

    # Create a copy of the actual schema to normalize
    normalized_schema = actual_schema.copy()

    # Normalize the my_model_a_with_default field to handle both pydantic formats
    if "allOf" in actual_schema["properties"]["my_model_a_with_default"]:
        normalized_schema["properties"]["my_model_a_with_default"] = {
            "$ref": "#/$defs/SomeInputModelA",
            "default": {},
        }

    assert normalized_schema == {
        "$defs": {
            "InnerModel": {
                "properties": {"x": {"title": "X", "type": "integer"}},
                "required": ["x"],
                "title": "InnerModel",
                "type": "object",
            },
            "SomeInputModelA": {
                "properties": {},
                "title": "SomeInputModelA",
                "type": "object",
            },
            "SomeInputModelB": {
                "properties": {
                    "how_many_shrimp": {
                        "description": "How many shrimp in the tank???",
                        "title": "How Many Shrimp",
                        "type": "integer",
                    },
                    "ok": {"$ref": "#/$defs/InnerModel"},
                    "y": {"title": "Y", "type": "null"},
                },
                "required": ["how_many_shrimp", "ok", "y"],
                "title": "SomeInputModelB",
                "type": "object",
            },
        },
        "properties": {
            "an_int": {"title": "An Int", "type": "integer"},
            "must_be_none": {"title": "Must Be None", "type": "null"},
            "must_be_none_dumb_annotation": {
                "title": "Must Be None Dumb Annotation",
                "type": "null",
            },
            "list_of_ints": {
                "items": {"type": "integer"},
                "title": "List Of Ints",
                "type": "array",
            },
            "list_str_or_str": {
                "anyOf": [
                    {"items": {"type": "string"}, "type": "array"},
                    {"type": "string"},
                ],
                "title": "List Str Or Str",
            },
            "an_int_annotated_with_field": {
                "description": "An int with a field",
                "title": "An Int Annotated With Field",
                "type": "integer",
            },
            "an_int_annotated_with_field_and_others": {
                "description": "An int with a field",
                "exclusiveMinimum": 1,
                "title": "An Int Annotated With Field And Others",
                "type": "integer",
            },
            "an_int_annotated_with_junk": {
                "title": "An Int Annotated With Junk",
                "type": "integer",
            },
            "field_with_default_via_field_annotation_before_nondefault_arg": {
                "default": 1,
                "title": "Field With Default Via Field Annotation Before Nondefault Arg",
                "type": "integer",
            },
            "unannotated": {"title": "unannotated", "type": "string"},
            "my_model_a": {"$ref": "#/$defs/SomeInputModelA"},
            "my_model_a_forward_ref": {"$ref": "#/$defs/SomeInputModelA"},
            "my_model_b": {"$ref": "#/$defs/SomeInputModelB"},
            "an_int_annotated_with_field_default": {
                "default": 1,
                "description": "An int with a field",
                "title": "An Int Annotated With Field Default",
                "type": "integer",
            },
            "unannotated_with_default": {
                "default": 5,
                "title": "unannotated_with_default",
                "type": "string",
            },
            "my_model_a_with_default": {
                "$ref": "#/$defs/SomeInputModelA",
                "default": {},
            },
            "an_int_with_default": {
                "default": 1,
                "title": "An Int With Default",
                "type": "integer",
            },
            "must_be_none_with_default": {
                "default": None,
                "title": "Must Be None With Default",
                "type": "null",
            },
            "an_int_with_equals_field": {
                "default": 1,
                "minimum": 0,
                "title": "An Int With Equals Field",
                "type": "integer",
            },
            "int_annotated_with_default": {
                "default": 5,
                "description": "hey",
                "title": "Int Annotated With Default",
                "type": "integer",
            },
        },
        "required": [
            "an_int",
            "must_be_none",
            "must_be_none_dumb_annotation",
            "list_of_ints",
            "list_str_or_str",
            "an_int_annotated_with_field",
            "an_int_annotated_with_field_and_others",
            "an_int_annotated_with_junk",
            "unannotated",
            "my_model_a",
            "my_model_a_forward_ref",
            "my_model_b",
        ],
        "title": "complex_arguments_fnArguments",
        "type": "object",
    }

## test_str_vs_int

**Type**: Function

**Description**: def test_str_vs_int():
    """
    Test that string values are kept as strings even when they contain numbers,
    while numbers are parsed correctly.
    """

    def func_with_str_and_int(a: str, b: int):
        return a

    meta = func_metadata(func_with_str_and_int)
    result = meta.pre_parse_json({"a": "123", "b": 123})
    assert result["a"] == "123"
    assert result["b"] == 123

## test_structured_output_requires_return_annotation

**Type**: Function

**Description**: def test_structured_output_requires_return_annotation():
    """Test that structured_output=True requires a return annotation"""
    from mcp.server.fastmcp.exceptions import InvalidSignature

    def func_no_annotation():
        return "hello"

    def func_none_annotation() -> None:
        return None

    with pytest.raises(InvalidSignature) as exc_info:
        func_metadata(func_no_annotation, structured_output=True)
    assert "return annotation required" in str(exc_info.value)

    # None annotation should work
    meta = func_metadata(func_none_annotation)
    assert meta.output_schema == {
        "type": "object",
        "properties": {"result": {"title": "Result", "type": "null"}},
        "required": ["result"],
        "title": "func_none_annotationOutput",
    }

## test_structured_output_basemodel

**Type**: Function

**Description**: def test_structured_output_basemodel():
    """Test structured output with BaseModel return types"""

    class PersonModel(BaseModel):
        name: str
        age: int
        email: str | None = None

    def func_returning_person() -> PersonModel:
        return PersonModel(name="Alice", age=30)

    meta = func_metadata(func_returning_person)
    assert meta.output_schema == {
        "type": "object",
        "properties": {
            "name": {"title": "Name", "type": "string"},
            "age": {"title": "Age", "type": "integer"},
            "email": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None, "title": "Email"},
        },
        "required": ["name", "age"],
        "title": "PersonModel",
    }

## test_structured_output_primitives

**Type**: Function

**Description**: def test_structured_output_primitives():
    """Test structured output with primitive return types"""

    def func_str() -> str:
        return "hello"

    def func_int() -> int:
        return 42

    def func_float() -> float:
        return 3.14

    def func_bool() -> bool:
        return True

    def func_bytes() -> bytes:
        return b"data"

    # Test string
    meta = func_metadata(func_str)
    assert meta.output_schema == {
        "type": "object",
        "properties": {"result": {"title": "Result", "type": "string"}},
        "required": ["result"],
        "title": "func_strOutput",
    }

    # Test int
    meta = func_metadata(func_int)
    assert meta.output_schema == {
        "type": "object",
        "properties": {"result": {"title": "Result", "type": "integer"}},
        "required": ["result"],
        "title": "func_intOutput",
    }

    # Test float
    meta = func_metadata(func_float)
    assert meta.output_schema == {
        "type": "object",
        "properties": {"result": {"title": "Result", "type": "number"}},
        "required": ["result"],
        "title": "func_floatOutput",
    }

    # Test bool
    meta = func_metadata(func_bool)
    assert meta.output_schema == {
        "type": "object",
        "properties": {"result": {"title": "Result", "type": "boolean"}},
        "required": ["result"],
        "title": "func_boolOutput",
    }

    # Test bytes
    meta = func_metadata(func_bytes)
    assert meta.output_schema == {
        "type": "object",
        "properties": {"result": {"title": "Result", "type": "string", "format": "binary"}},
        "required": ["result"],
        "title": "func_bytesOutput",
    }

## test_structured_output_generic_types

**Type**: Function

**Description**: def test_structured_output_generic_types():
    """Test structured output with generic types (list, dict, Union, etc.)"""

    def func_list_str() -> list[str]:
        return ["a", "b", "c"]

    def func_dict_str_int() -> dict[str, int]:
        return {"a": 1, "b": 2}

    def func_union() -> str | int:
        return "hello"

    def func_optional() -> str | None:
        return None

    # Test list
    meta = func_metadata(func_list_str)
    assert meta.output_schema == {
        "type": "object",
        "properties": {"result": {"title": "Result", "type": "array", "items": {"type": "string"}}},
        "required": ["result"],
        "title": "func_list_strOutput",
    }

    # Test dict[str, int] - should NOT be wrapped
    meta = func_metadata(func_dict_str_int)
    assert meta.output_schema == {
        "type": "object",
        "additionalProperties": {"type": "integer"},
        "title": "func_dict_str_intDictOutput",
    }

    # Test Union
    meta = func_metadata(func_union)
    assert meta.output_schema == {
        "type": "object",
        "properties": {"result": {"title": "Result", "anyOf": [{"type": "string"}, {"type": "integer"}]}},
        "required": ["result"],
        "title": "func_unionOutput",
    }

    # Test Optional
    meta = func_metadata(func_optional)
    assert meta.output_schema == {
        "type": "object",
        "properties": {"result": {"title": "Result", "anyOf": [{"type": "string"}, {"type": "null"}]}},
        "required": ["result"],
        "title": "func_optionalOutput",
    }

## test_structured_output_dataclass

**Type**: Function

**Description**: def test_structured_output_dataclass():
    """Test structured output with dataclass return types"""

    @dataclass
    class PersonDataClass:
        name: str
        age: int
        email: str | None = None
        tags: list[str] | None = None

    def func_returning_dataclass() -> PersonDataClass:
        return PersonDataClass(name="Bob", age=25)

    meta = func_metadata(func_returning_dataclass)
    assert meta.output_schema == {
        "type": "object",
        "properties": {
            "name": {"title": "Name", "type": "string"},
            "age": {"title": "Age", "type": "integer"},
            "email": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None, "title": "Email"},
            "tags": {
                "anyOf": [{"items": {"type": "string"}, "type": "array"}, {"type": "null"}],
                "default": None,
                "title": "Tags",
            },
        },
        "required": ["name", "age"],
        "title": "PersonDataClass",
    }

## test_structured_output_typeddict

**Type**: Function

**Description**: def test_structured_output_typeddict():
    """Test structured output with TypedDict return types"""

    class PersonTypedDictOptional(TypedDict, total=False):
        name: str
        age: int

    def func_returning_typeddict_optional() -> PersonTypedDictOptional:
        return {"name": "Dave"}  # Only returning one field to test partial dict

    meta = func_metadata(func_returning_typeddict_optional)
    assert meta.output_schema == {
        "type": "object",
        "properties": {
            "name": {"title": "Name", "type": "string", "default": None},
            "age": {"title": "Age", "type": "integer", "default": None},
        },
        "title": "PersonTypedDictOptional",
    }

    # Test with total=True (all required)
    class PersonTypedDictRequired(TypedDict):
        name: str
        age: int
        email: str | None

    def func_returning_typeddict_required() -> PersonTypedDictRequired:
        return {"name": "Eve", "age": 40, "email": None}  # Testing None value

    meta = func_metadata(func_returning_typeddict_required)
    assert meta.output_schema == {
        "type": "object",
        "properties": {
            "name": {"title": "Name", "type": "string"},
            "age": {"title": "Age", "type": "integer"},
            "email": {"anyOf": [{"type": "string"}, {"type": "null"}], "title": "Email"},
        },
        "required": ["name", "age", "email"],
        "title": "PersonTypedDictRequired",
    }

## test_structured_output_ordinary_class

**Type**: Function

**Description**: def test_structured_output_ordinary_class():
    """Test structured output with ordinary annotated classes"""

    class PersonClass:
        name: str
        age: int
        email: str | None

        def __init__(self, name: str, age: int, email: str | None = None):
            self.name = name
            self.age = age
            self.email = email

    def func_returning_class() -> PersonClass:
        return PersonClass("Helen", 55)

    meta = func_metadata(func_returning_class)
    assert meta.output_schema == {
        "type": "object",
        "properties": {
            "name": {"title": "Name", "type": "string"},
            "age": {"title": "Age", "type": "integer"},
            "email": {"anyOf": [{"type": "string"}, {"type": "null"}], "title": "Email"},
        },
        "required": ["name", "age", "email"],
        "title": "PersonClass",
    }

## test_unstructured_output_unannotated_class

**Type**: Function

**Description**: def test_unstructured_output_unannotated_class():
    # Test with class that has no annotations
    class UnannotatedClass:
        def __init__(self, x, y):
            self.x = x
            self.y = y

    def func_returning_unannotated() -> UnannotatedClass:
        return UnannotatedClass(1, 2)

    meta = func_metadata(func_returning_unannotated)
    assert meta.output_schema is None

## test_structured_output_with_field_descriptions

**Type**: Function

**Description**: def test_structured_output_with_field_descriptions():
    """Test that Field descriptions are preserved in structured output"""

    class ModelWithDescriptions(BaseModel):
        name: Annotated[str, Field(description="The person's full name")]
        age: Annotated[int, Field(description="Age in years", ge=0, le=150)]

    def func_with_descriptions() -> ModelWithDescriptions:
        return ModelWithDescriptions(name="Ian", age=60)

    meta = func_metadata(func_with_descriptions)
    assert meta.output_schema == {
        "type": "object",
        "properties": {
            "name": {"title": "Name", "type": "string", "description": "The person's full name"},
            "age": {"title": "Age", "type": "integer", "description": "Age in years", "minimum": 0, "maximum": 150},
        },
        "required": ["name", "age"],
        "title": "ModelWithDescriptions",
    }

## test_structured_output_nested_models

**Type**: Function

**Description**: def test_structured_output_nested_models():
    """Test structured output with nested models"""

    class Address(BaseModel):
        street: str
        city: str
        zipcode: str

    class PersonWithAddress(BaseModel):
        name: str
        address: Address

    def func_nested() -> PersonWithAddress:
        return PersonWithAddress(name="Jack", address=Address(street="123 Main St", city="Anytown", zipcode="12345"))

    meta = func_metadata(func_nested)
    assert meta.output_schema == {
        "type": "object",
        "$defs": {
            "Address": {
                "type": "object",
                "properties": {
                    "street": {"title": "Street", "type": "string"},
                    "city": {"title": "City", "type": "string"},
                    "zipcode": {"title": "Zipcode", "type": "string"},
                },
                "required": ["street", "city", "zipcode"],
                "title": "Address",
            }
        },
        "properties": {
            "name": {"title": "Name", "type": "string"},
            "address": {"$ref": "#/$defs/Address"},
        },
        "required": ["name", "address"],
        "title": "PersonWithAddress",
    }

## test_structured_output_unserializable_type_error

**Type**: Function

**Description**: def test_structured_output_unserializable_type_error():
    """Test error when structured_output=True is used with unserializable types"""
    from typing import NamedTuple

    from mcp.server.fastmcp.exceptions import InvalidSignature

    # Test with a class that has non-serializable default values
    class ConfigWithCallable:
        name: str
        # Callable defaults are not JSON serializable and will trigger Pydantic warnings
        callback: Any = lambda x: x * 2

    def func_returning_config_with_callable() -> ConfigWithCallable:
        return ConfigWithCallable()

    # Should work without structured_output=True (returns None for output_schema)
    meta = func_metadata(func_returning_config_with_callable)
    assert meta.output_schema is None

    # Should raise error with structured_output=True
    with pytest.raises(InvalidSignature) as exc_info:
        func_metadata(func_returning_config_with_callable, structured_output=True)
    assert "is not serializable for structured output" in str(exc_info.value)
    assert "ConfigWithCallable" in str(exc_info.value)

    # Also test with NamedTuple for good measure
    class Point(NamedTuple):
        x: int
        y: int

    def func_returning_namedtuple() -> Point:
        return Point(1, 2)

    # Should work without structured_output=True (returns None for output_schema)
    meta = func_metadata(func_returning_namedtuple)
    assert meta.output_schema is None

    # Should raise error with structured_output=True
    with pytest.raises(InvalidSignature) as exc_info:
        func_metadata(func_returning_namedtuple, structured_output=True)
    assert "is not serializable for structured output" in str(exc_info.value)
    assert "Point" in str(exc_info.value)

## make_fastmcp_app

**Type**: Function

**Description**: def make_fastmcp_app():
    """Create a FastMCP server without auth settings."""
    transport_security = TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*"], allowed_origins=["http://127.0.0.1:*", "http://localhost:*"]
    )
    mcp = FastMCP(name="NoAuthServer", transport_security=transport_security)

    # Add a simple tool
    @mcp.tool(description="A simple echo tool")
    def echo(message: str) -> str:
        return f"Echo: {message}"

    # Add a tool that uses elicitation
    @mcp.tool(description="A tool that uses elicitation")
    async def ask_user(prompt: str, ctx: Context) -> str:
        class AnswerSchema(BaseModel):
            answer: str = Field(description="The user's answer to the question")

        result = await ctx.elicit(message=f"Tool wants to ask: {prompt}", schema=AnswerSchema)

        if result.action == "accept" and result.data:
            return f"User answered: {result.data.answer}"
        else:
            # Handle cancellation or decline
            return f"User cancelled or declined: {result.action}"

    # Create the SSE app
    app = mcp.sse_app()

    return mcp, app

## make_everything_fastmcp

**Type**: Function

**Description**: def make_everything_fastmcp() -> FastMCP:
    """Create a FastMCP server with all features enabled for testing."""
    transport_security = TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*"], allowed_origins=["http://127.0.0.1:*", "http://localhost:*"]
    )
    mcp = FastMCP(name="EverythingServer", transport_security=transport_security)

    # Tool with context for logging and progress
    @mcp.tool(description="A tool that demonstrates logging and progress", title="Progress Tool")
    async def tool_with_progress(message: str, ctx: Context, steps: int = 3) -> str:
        await ctx.info(f"Starting processing of '{message}' with {steps} steps")

        # Send progress notifications
        for i in range(steps):
            progress_value = (i + 1) / steps
            await ctx.report_progress(
                progress=progress_value,
                total=1.0,
                message=f"Processing step {i + 1} of {steps}",
            )
            await ctx.debug(f"Completed step {i + 1}")

        return f"Processed '{message}' in {steps} steps"

    # Simple tool for basic functionality
    @mcp.tool(description="A simple echo tool", title="Echo Tool")
    def echo(message: str) -> str:
        return f"Echo: {message}"

    # Tool that returns ResourceLinks
    @mcp.tool(description="Lists files and returns resource links", title="List Files Tool")
    def list_files() -> list[ResourceLink]:
        """Returns a list of resource links for files matching the pattern."""

        # Mock some file resources for testing
        file_resources = [
            {
                "type": "resource_link",
                "uri": "file:///project/README.md",
                "name": "README.md",
                "mimeType": "text/markdown",
            }
        ]

        result: list[ResourceLink] = [ResourceLink.model_validate(file_json) for file_json in file_resources]

        return result

    # Tool with sampling capability
    @mcp.tool(description="A tool that uses sampling to generate content", title="Sampling Tool")
    async def sampling_tool(prompt: str, ctx: Context) -> str:
        await ctx.info(f"Requesting sampling for prompt: {prompt}")

        # Request sampling from the client
        result = await ctx.session.create_message(
            messages=[SamplingMessage(role="user", content=TextContent(type="text", text=prompt))],
            max_tokens=100,
            temperature=0.7,
        )

        await ctx.info(f"Received sampling result from model: {result.model}")
        # Handle different content types
        if result.content.type == "text":
            return f"Sampling result: {result.content.text[:100]}..."
        else:
            return f"Sampling result: {str(result.content)[:100]}..."

    # Tool that sends notifications and logging
    @mcp.tool(description="A tool that demonstrates notifications and logging", title="Notification Tool")
    async def notification_tool(message: str, ctx: Context) -> str:
        # Send different log levels
        await ctx.debug("Debug: Starting notification tool")
        await ctx.info(f"Info: Processing message '{message}'")
        await ctx.warning("Warning: This is a test warning")

        # Send resource change notifications
        await ctx.session.send_resource_list_changed()
        await ctx.session.send_tool_list_changed()

        await ctx.info("Completed notification tool successfully")
        return f"Sent notifications and logs for: {message}"

    # Resource - static
    def get_static_info() -> str:
        return "This is static resource content"

    static_resource = FunctionResource(
        uri=AnyUrl("resource://static/info"),
        name="Static Info",
        title="Static Information",
        description="Static information resource",
        fn=get_static_info,
    )
    mcp.add_resource(static_resource)

    # Resource - dynamic function
    @mcp.resource("resource://dynamic/{category}", title="Dynamic Resource")
    def dynamic_resource(category: str) -> str:
        return f"Dynamic resource content for category: {category}"

    # Resource template
    @mcp.resource("resource://template/{id}/data", title="Template Resource")
    def template_resource(id: str) -> str:
        return f"Template resource data for ID: {id}"

    # Prompt - simple
    @mcp.prompt(description="A simple prompt", title="Simple Prompt")
    def simple_prompt(topic: str) -> str:
        return f"Tell me about {topic}"

    # Prompt - complex with multiple messages
    @mcp.prompt(description="Complex prompt with context", title="Complex Prompt")
    def complex_prompt(user_query: str, context: str = "general") -> str:
        # For simplicity, return a single string that incorporates the context
        # Since FastMCP doesn't support system messages in the same way
        return f"Context: {context}. Query: {user_query}"

    # Resource template with completion support
    @mcp.resource("github://repos/{owner}/{repo}", title="GitHub Repository")
    def github_repo_resource(owner: str, repo: str) -> str:
        return f"Repository: {owner}/{repo}"

    # Add completion handler for the server
    @mcp.completion()
    async def handle_completion(
        ref: PromptReference | ResourceTemplateReference,
        argument: CompletionArgument,
        context: CompletionContext | None,
    ) -> Completion | None:
        # Handle GitHub repository completion
        if isinstance(ref, ResourceTemplateReference):
            if ref.uri == "github://repos/{owner}/{repo}" and argument.name == "repo":
                if context and context.arguments and context.arguments.get("owner") == "modelcontextprotocol":
                    # Return repos for modelcontextprotocol org
                    return Completion(values=["python-sdk", "typescript-sdk", "specification"], total=3, hasMore=False)
                elif context and context.arguments and context.arguments.get("owner") == "test-org":
                    # Return repos for test-org
                    return Completion(values=["test-repo1", "test-repo2"], total=2, hasMore=False)

        # Handle prompt completions
        if isinstance(ref, PromptReference):
            if ref.name == "complex_prompt" and argument.name == "context":
                # Complete context values
                contexts = ["general", "technical", "business", "academic"]
                return Completion(
                    values=[c for c in contexts if c.startswith(argument.value)], total=None, hasMore=False
                )

        # Default: no completion available
        return Completion(values=[], total=0, hasMore=False)

    # Tool that echoes request headers from context
    @mcp.tool(description="Echo request headers from context", title="Echo Headers")
    def echo_headers(ctx: Context[Any, Any, Request]) -> str:
        """Returns the request headers as JSON."""
        headers_info = {}
        if ctx.request_context.request:
            # Now the type system knows request is a Starlette Request object
            headers_info = dict(ctx.request_context.request.headers)
        return json.dumps(headers_info)

    # Tool that returns full request context
    @mcp.tool(description="Echo request context with custom data", title="Echo Context")
    def echo_context(custom_request_id: str, ctx: Context[Any, Any, Request]) -> str:
        """Returns request context including headers and custom data."""
        context_data = {
            "custom_request_id": custom_request_id,
            "headers": {},
            "method": None,
            "path": None,
        }
        if ctx.request_context.request:
            request = ctx.request_context.request
            context_data["headers"] = dict(request.headers)
            context_data["method"] = request.method
            context_data["path"] = request.url.path
        return json.dumps(context_data)

    # Restaurant booking tool with elicitation
    @mcp.tool(description="Book a table at a restaurant with elicitation", title="Restaurant Booking")
    async def book_restaurant(
        date: str,
        time: str,
        party_size: int,
        ctx: Context,
    ) -> str:
        """Book a table - uses elicitation if requested date is unavailable."""

        class AlternativeDateSchema(BaseModel):
            checkAlternative: bool = Field(description="Would you like to try another date?")
            alternativeDate: str = Field(
                default="2024-12-26",
                description="What date would you prefer? (YYYY-MM-DD)",
            )

        # For testing: assume dates starting with "2024-12-25" are unavailable
        if date.startswith("2024-12-25"):
            # Use elicitation to ask about alternatives
            result = await ctx.elicit(
                message=(
                    f"No tables available for {party_size} people on {date} "
                    f"at {time}. Would you like to check another date?"
                ),
                schema=AlternativeDateSchema,
            )

            if result.action == "accept" and result.data:
                if result.data.checkAlternative:
                    alt_date = result.data.alternativeDate
                    return f"✅ Booked table for {party_size} on {alt_date} at {time}"
                else:
                    return "❌ No booking made"
            elif result.action in ("decline", "cancel"):
                return "❌ Booking cancelled"
            else:
                # Handle case where action is "accept" but data is None
                return "❌ No booking data received"
        else:
            # Available - book directly
            return f"✅ Booked table for {party_size} on {date} at {time}"

    return mcp

## make_everything_fastmcp_app

**Type**: Function

**Description**: def make_everything_fastmcp_app():
    """Create a comprehensive FastMCP server with SSE transport."""
    mcp = make_everything_fastmcp()
    # Create the SSE app
    app = mcp.sse_app()
    return mcp, app

## make_fastmcp_streamable_http_app

**Type**: Function

**Description**: def make_fastmcp_streamable_http_app():
    """Create a FastMCP server with StreamableHTTP transport."""
    transport_security = TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*"], allowed_origins=["http://127.0.0.1:*", "http://localhost:*"]
    )
    mcp = FastMCP(name="NoAuthServer", transport_security=transport_security)

    # Add a simple tool
    @mcp.tool(description="A simple echo tool")
    def echo(message: str) -> str:
        return f"Echo: {message}"

    # Create the StreamableHTTP app
    app: Starlette = mcp.streamable_http_app()

    return mcp, app

## make_everything_fastmcp_streamable_http_app

**Type**: Function

**Description**: def make_everything_fastmcp_streamable_http_app():
    """Create a comprehensive FastMCP server with StreamableHTTP transport."""
    # Create a new instance with different name for HTTP transport
    mcp = make_everything_fastmcp()
    # We can't change the name after creation, so we'll use the same name
    # Create the StreamableHTTP app
    app: Starlette = mcp.streamable_http_app()
    return mcp, app

## make_fastmcp_stateless_http_app

**Type**: Function

**Description**: def make_fastmcp_stateless_http_app():
    """Create a FastMCP server with stateless StreamableHTTP transport."""
    transport_security = TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*"], allowed_origins=["http://127.0.0.1:*", "http://localhost:*"]
    )
    mcp = FastMCP(name="StatelessServer", stateless_http=True, transport_security=transport_security)

    # Add a simple tool
    @mcp.tool(description="A simple echo tool")
    def echo(message: str) -> str:
        return f"Echo: {message}"

    # Create the StreamableHTTP app
    app: Starlette = mcp.streamable_http_app()

    return mcp, app

## run_server

**Type**: Function

**Description**: def run_server(server_port: int) -> None:
    """Run the server."""
    _, app = make_fastmcp_app()
    server = uvicorn.Server(config=uvicorn.Config(app=app, host="127.0.0.1", port=server_port, log_level="error"))
    print(f"Starting server on port {server_port}")
    server.run()

## run_everything_legacy_sse_http_server

**Type**: Function

**Description**: def run_everything_legacy_sse_http_server(server_port: int) -> None:
    """Run the comprehensive server with all features."""
    _, app = make_everything_fastmcp_app()
    server = uvicorn.Server(config=uvicorn.Config(app=app, host="127.0.0.1", port=server_port, log_level="error"))
    print(f"Starting comprehensive server on port {server_port}")
    server.run()

## run_streamable_http_server

**Type**: Function

**Description**: def run_streamable_http_server(server_port: int) -> None:
    """Run the StreamableHTTP server."""
    _, app = make_fastmcp_streamable_http_app()
    server = uvicorn.Server(config=uvicorn.Config(app=app, host="127.0.0.1", port=server_port, log_level="error"))
    print(f"Starting StreamableHTTP server on port {server_port}")
    server.run()

## run_everything_server

**Type**: Function

**Description**: def run_everything_server(server_port: int) -> None:
    """Run the comprehensive StreamableHTTP server with all features."""
    _, app = make_everything_fastmcp_streamable_http_app()
    server = uvicorn.Server(config=uvicorn.Config(app=app, host="127.0.0.1", port=server_port, log_level="error"))
    print(f"Starting comprehensive StreamableHTTP server on port {server_port}")
    server.run()

## run_stateless_http_server

**Type**: Function

**Description**: def run_stateless_http_server(server_port: int) -> None:
    """Run the stateless StreamableHTTP server."""
    _, app = make_fastmcp_stateless_http_app()
    server = uvicorn.Server(config=uvicorn.Config(app=app, host="127.0.0.1", port=server_port, log_level="error"))
    print(f"Starting stateless StreamableHTTP server on port {server_port}")
    server.run()

## NotificationCollector

**Type**: Class

**Description**: class NotificationCollector:
    def __init__(self):
        self.progress_notifications: list = []
        self.log_messages: list = []
        self.resource_notifications: list = []
        self.tool_notifications: list = []

    async def handle_progress(self, params) -> None:
        self.progress_notifications.append(params)

    async def handle_log(self, params) -> None:
        self.log_messages.append(params)

    async def handle_resource_list_changed(self, params) -> None:
        self.resource_notifications.append(params)

    async def handle_tool_list_changed(self, params) -> None:
        self.tool_notifications.append(params)

    async def handle_generic_notification(self, message) -> None:
        # Check if this is a ServerNotification
        if isinstance(message, ServerNotification):
            # Check the specific notification type
            if isinstance(message.root, ProgressNotification):
                await self.handle_progress(message.root.params)
            elif isinstance(message.root, LoggingMessageNotification):
                await self.handle_log(message.root.params)
            elif isinstance(message.root, ResourceListChangedNotification):
                await self.handle_resource_list_changed(message.root.params)
            elif isinstance(message.root, ToolListChangedNotification):
                await self.handle_tool_list_changed(message.root.params)

## create_test_elicitation_callback

**Type**: Function

**Description**: async def create_test_elicitation_callback(context, params):
    """Shared elicitation callback for tests.

    Handles elicitation requests for restaurant booking tests.
    """
    # For restaurant booking test
    if "No tables available" in params.message:
        return ElicitResult(
            action="accept",
            content={"checkAlternative": True, "alternativeDate": "2024-12-26"},
        )
    else:
        # Default response
        return ElicitResult(action="decline")

## call_all_mcp_features

**Type**: Function

**Description**: async def call_all_mcp_features(session: ClientSession, collector: NotificationCollector) -> None:
    """
    Test all MCP features using the provided session.

    Args:
        session: The MCP client session to test with
        collector: Notification collector for capturing server notifications
    """
    # Test initialization
    result = await session.initialize()
    assert isinstance(result, InitializeResult)
    assert result.serverInfo.name == "EverythingServer"

    # Check server features are reported
    assert result.capabilities.prompts is not None
    assert result.capabilities.resources is not None
    assert result.capabilities.tools is not None
    # Note: logging capability may be None if no tools use context logging

    # Test tools
    # 1. Simple echo tool
    tool_result = await session.call_tool("echo", {"message": "hello"})
    assert len(tool_result.content) == 1
    assert isinstance(tool_result.content[0], TextContent)
    assert tool_result.content[0].text == "Echo: hello"

    # 2. Test tool that returns ResourceLinks
    list_files_result = await session.call_tool("list_files")
    assert len(list_files_result.content) == 1

    # Rest should be ResourceLinks
    content = list_files_result.content[0]
    assert isinstance(content, ResourceLink)
    assert str(content.uri).startswith("file:///")
    assert content.name is not None
    assert content.mimeType is not None

    # Test progress callback functionality
    progress_updates = []

    async def progress_callback(progress: float, total: float | None, message: str | None) -> None:
        """Collect progress updates for testing (async version)."""
        progress_updates.append((progress, total, message))
        print(f"Progress: {progress}/{total} - {message}")

    test_message = "test"
    steps = 3
    params = {
        "message": test_message,
        "steps": steps,
    }
    tool_result = await session.call_tool(
        "tool_with_progress",
        params,
        progress_callback=progress_callback,
    )
    assert len(tool_result.content) == 1
    assert isinstance(tool_result.content[0], TextContent)
    assert f"Processed '{test_message}' in {steps} steps" in tool_result.content[0].text

    # Verify progress callback was called
    assert len(progress_updates) == steps
    for i, (progress, total, message) in enumerate(progress_updates):
        expected_progress = (i + 1) / steps
        assert abs(progress - expected_progress) < 0.01
        assert total == 1.0
        assert message is not None
        assert f"step {i + 1} of {steps}" in message

    # Verify we received log messages from the tool
    # Note: Progress notifications require special handling in the MCP client
    # that's not implemented by default, so we focus on testing logging
    assert len(collector.log_messages) > 0

    # 3. Test sampling tool
    prompt = "What is the meaning of life?"
    sampling_result = await session.call_tool("sampling_tool", {"prompt": prompt})
    assert len(sampling_result.content) == 1
    assert isinstance(sampling_result.content[0], TextContent)
    assert "Sampling result:" in sampling_result.content[0].text
    assert "This is a simulated LLM response" in sampling_result.content[0].text

    # Verify we received log messages from the sampling tool
    assert len(collector.log_messages) > 0
    assert any("Requesting sampling for prompt" in msg.data for msg in collector.log_messages)
    assert any("Received sampling result from model" in msg.data for msg in collector.log_messages)

    # 4. Test notification tool
    notification_message = "test_notifications"
    notification_result = await session.call_tool("notification_tool", {"message": notification_message})
    assert len(notification_result.content) == 1
    assert isinstance(notification_result.content[0], TextContent)
    assert "Sent notifications and logs" in notification_result.content[0].text

    # Verify we received various notification types
    assert len(collector.log_messages) > 3  # Should have logs from both tools
    assert len(collector.resource_notifications) > 0
    assert len(collector.tool_notifications) > 0

    # Check that we got different log levels
    log_levels = [msg.level for msg in collector.log_messages]
    assert "debug" in log_levels
    assert "info" in log_levels
    assert "warning" in log_levels

    # 5. Test elicitation tool
    # Test restaurant booking with unavailable date (triggers elicitation)
    booking_result = await session.call_tool(
        "book_restaurant",
        {
            "date": "2024-12-25",  # Unavailable date to trigger elicitation
            "time": "19:00",
            "party_size": 4,
        },
    )
    assert len(booking_result.content) == 1
    assert isinstance(booking_result.content[0], TextContent)
    # Should have booked the alternative date from elicitation callback
    assert "✅ Booked table for 4 on 2024-12-26" in booking_result.content[0].text

    # Test resources
    # 1. Static resource
    resources = await session.list_resources()
    # Try using string comparison since AnyUrl might not match directly
    static_resource = next(
        (r for r in resources.resources if str(r.uri) == "resource://static/info"),
        None,
    )
    assert static_resource is not None
    assert static_resource.name == "Static Info"

    static_content = await session.read_resource(AnyUrl("resource://static/info"))
    assert isinstance(static_content, ReadResourceResult)
    assert len(static_content.contents) == 1
    assert isinstance(static_content.contents[0], TextResourceContents)
    assert static_content.contents[0].text == "This is static resource content"

    # 2. Dynamic resource
    resource_category = "test"
    dynamic_content = await session.read_resource(AnyUrl(f"resource://dynamic/{resource_category}"))
    assert isinstance(dynamic_content, ReadResourceResult)
    assert len(dynamic_content.contents) == 1
    assert isinstance(dynamic_content.contents[0], TextResourceContents)
    assert f"Dynamic resource content for category: {resource_category}" in dynamic_content.contents[0].text

    # 3. Template resource
    resource_id = "456"
    template_content = await session.read_resource(AnyUrl(f"resource://template/{resource_id}/data"))
    assert isinstance(template_content, ReadResourceResult)
    assert len(template_content.contents) == 1
    assert isinstance(template_content.contents[0], TextResourceContents)
    assert f"Template resource data for ID: {resource_id}" in template_content.contents[0].text

    # Test prompts
    # 1. Simple prompt
    prompts = await session.list_prompts()
    simple_prompt = next((p for p in prompts.prompts if p.name == "simple_prompt"), None)
    assert simple_prompt is not None

    prompt_topic = "AI"
    prompt_result = await session.get_prompt("simple_prompt", {"topic": prompt_topic})
    assert isinstance(prompt_result, GetPromptResult)
    assert len(prompt_result.messages) >= 1
    # The actual message structure depends on the prompt implementation

    # 2. Complex prompt
    complex_prompt = next((p for p in prompts.prompts if p.name == "complex_prompt"), None)
    assert complex_prompt is not None

    query = "What is AI?"
    context = "technical"
    complex_result = await session.get_prompt("complex_prompt", {"user_query": query, "context": context})
    assert isinstance(complex_result, GetPromptResult)
    assert len(complex_result.messages) >= 1

    # Test request context propagation (only works when headers are available)

    headers_result = await session.call_tool("echo_headers", {})
    assert len(headers_result.content) == 1
    assert isinstance(headers_result.content[0], TextContent)

    # If we got headers, verify they exist
    headers_data = json.loads(headers_result.content[0].text)
    # The headers depend on the transport and test setup
    print(f"Received headers: {headers_data}")

    # Test 6: Call tool that returns full context
    context_result = await session.call_tool("echo_context", {"custom_request_id": "test-123"})
    assert len(context_result.content) == 1
    assert isinstance(context_result.content[0], TextContent)

    context_data = json.loads(context_result.content[0].text)
    assert context_data["custom_request_id"] == "test-123"
    # The method should be POST for most transports
    if context_data["method"]:
        assert context_data["method"] == "POST"

    # Test completion functionality
    # 1. Test resource template completion with context
    repo_result = await session.complete(
        ref=ResourceTemplateReference(type="ref/resource", uri="github://repos/{owner}/{repo}"),
        argument={"name": "repo", "value": ""},
        context_arguments={"owner": "modelcontextprotocol"},
    )
    assert repo_result.completion.values == ["python-sdk", "typescript-sdk", "specification"]
    assert repo_result.completion.total == 3
    assert repo_result.completion.hasMore is False

    # 2. Test with different context
    repo_result2 = await session.complete(
        ref=ResourceTemplateReference(type="ref/resource", uri="github://repos/{owner}/{repo}"),
        argument={"name": "repo", "value": ""},
        context_arguments={"owner": "test-org"},
    )
    assert repo_result2.completion.values == ["test-repo1", "test-repo2"]
    assert repo_result2.completion.total == 2

    # 3. Test prompt argument completion
    context_result = await session.complete(
        ref=PromptReference(type="ref/prompt", name="complex_prompt"),
        argument={"name": "context", "value": "tech"},
    )
    assert "technical" in context_result.completion.values

    # 4. Test completion without context (should return empty)
    no_context_result = await session.complete(
        ref=ResourceTemplateReference(type="ref/resource", uri="github://repos/{owner}/{repo}"),
        argument={"name": "repo", "value": "test"},
    )
    assert no_context_result.completion.values == []
    assert no_context_result.completion.total == 0

## sampling_callback

**Type**: Function

**Description**: async def sampling_callback(
    context: RequestContext[ClientSession, None],
    params: CreateMessageRequestParams,
) -> CreateMessageResult:
    # Simulate LLM response based on the input
    if params.messages and isinstance(params.messages[0].content, TextContent):
        input_text = params.messages[0].content.text
    else:
        input_text = "No input"
    response_text = f"This is a simulated LLM response to: {input_text}"

    model_name = "test-llm-model"
    return CreateMessageResult(
        role="assistant",
        content=TextContent(type="text", text=response_text),
        model=model_name,
        stopReason="endTurn",
    )

## TestServer

**Type**: Class

**Description**: class TestServer:
    @pytest.mark.anyio
    async def test_create_server(self):
        mcp = FastMCP(instructions="Server instructions")
        assert mcp.name == "FastMCP"
        assert mcp.instructions == "Server instructions"

    @pytest.mark.anyio
    async def test_normalize_path(self):
        """Test path normalization for mount paths."""
        mcp = FastMCP()

        # Test root path
        assert mcp._normalize_path("/", "/messages/") == "/messages/"

        # Test path with trailing slash
        assert mcp._normalize_path("/github/", "/messages/") == "/github/messages/"

        # Test path without trailing slash
        assert mcp._normalize_path("/github", "/messages/") == "/github/messages/"

        # Test endpoint without leading slash
        assert mcp._normalize_path("/github", "messages/") == "/github/messages/"

        # Test both with trailing/leading slashes
        assert mcp._normalize_path("/api/", "/v1/") == "/api/v1/"

    @pytest.mark.anyio
    async def test_sse_app_with_mount_path(self):
        """Test SSE app creation with different mount paths."""
        # Test with default mount path
        mcp = FastMCP()
        with patch.object(mcp, "_normalize_path", return_value="/messages/") as mock_normalize:
            mcp.sse_app()
            # Verify _normalize_path was called with correct args
            mock_normalize.assert_called_once_with("/", "/messages/")

        # Test with custom mount path in settings
        mcp = FastMCP()
        mcp.settings.mount_path = "/custom"
        with patch.object(mcp, "_normalize_path", return_value="/custom/messages/") as mock_normalize:
            mcp.sse_app()
            # Verify _normalize_path was called with correct args
            mock_normalize.assert_called_once_with("/custom", "/messages/")

        # Test with mount_path parameter
        mcp = FastMCP()
        with patch.object(mcp, "_normalize_path", return_value="/param/messages/") as mock_normalize:
            mcp.sse_app(mount_path="/param")
            # Verify _normalize_path was called with correct args
            mock_normalize.assert_called_once_with("/param", "/messages/")

    @pytest.mark.anyio
    async def test_starlette_routes_with_mount_path(self):
        """Test that Starlette routes are correctly configured with mount path."""
        # Test with mount path in settings
        mcp = FastMCP()
        mcp.settings.mount_path = "/api"
        app = mcp.sse_app()

        # Find routes by type
        sse_routes = [r for r in app.routes if isinstance(r, Route)]
        mount_routes = [r for r in app.routes if isinstance(r, Mount)]

        # Verify routes exist
        assert len(sse_routes) == 1, "Should have one SSE route"
        assert len(mount_routes) == 1, "Should have one mount route"

        # Verify path values
        assert sse_routes[0].path == "/sse", "SSE route path should be /sse"
        assert mount_routes[0].path == "/messages", "Mount route path should be /messages"

        # Test with mount path as parameter
        mcp = FastMCP()
        app = mcp.sse_app(mount_path="/param")

        # Find routes by type
        sse_routes = [r for r in app.routes if isinstance(r, Route)]
        mount_routes = [r for r in app.routes if isinstance(r, Mount)]

        # Verify routes exist
        assert len(sse_routes) == 1, "Should have one SSE route"
        assert len(mount_routes) == 1, "Should have one mount route"

        # Verify path values
        assert sse_routes[0].path == "/sse", "SSE route path should be /sse"
        assert mount_routes[0].path == "/messages", "Mount route path should be /messages"

    @pytest.mark.anyio
    async def test_non_ascii_description(self):
        """Test that FastMCP handles non-ASCII characters in descriptions correctly"""
        mcp = FastMCP()

        @mcp.tool(description=("🌟 This tool uses emojis and UTF-8 characters: á é í ó ú ñ 漢字 🎉"))
        def hello_world(name: str = "世界") -> str:
            return f"¡Hola, {name}! 👋"

        async with client_session(mcp._mcp_server) as client:
            tools = await client.list_tools()
            assert len(tools.tools) == 1
            tool = tools.tools[0]
            assert tool.description is not None
            assert "🌟" in tool.description
            assert "漢字" in tool.description
            assert "🎉" in tool.description

            result = await client.call_tool("hello_world", {})
            assert len(result.content) == 1
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert "¡Hola, 世界! 👋" == content.text

    @pytest.mark.anyio
    async def test_add_tool_decorator(self):
        mcp = FastMCP()

        @mcp.tool()
        def add(x: int, y: int) -> int:
            return x + y

        assert len(mcp._tool_manager.list_tools()) == 1

    @pytest.mark.anyio
    async def test_add_tool_decorator_incorrect_usage(self):
        mcp = FastMCP()

        with pytest.raises(TypeError, match="The @tool decorator was used incorrectly"):

            @mcp.tool  # Missing parentheses #type: ignore
            def add(x: int, y: int) -> int:
                return x + y

    @pytest.mark.anyio
    async def test_add_resource_decorator(self):
        mcp = FastMCP()

        @mcp.resource("r://{x}")
        def get_data(x: str) -> str:
            return f"Data: {x}"

        assert len(mcp._resource_manager._templates) == 1

    @pytest.mark.anyio
    async def test_add_resource_decorator_incorrect_usage(self):
        mcp = FastMCP()

        with pytest.raises(TypeError, match="The @resource decorator was used incorrectly"):

            @mcp.resource  # Missing parentheses #type: ignore
            def get_data(x: str) -> str:
                return f"Data: {x}"

## tool_fn

**Type**: Function

**Description**: def tool_fn(x: int, y: int) -> int:
    return x + y

## error_tool_fn

**Type**: Function

**Description**: def error_tool_fn() -> None:
    raise ValueError("Test error")

## image_tool_fn

**Type**: Function

**Description**: def image_tool_fn(path: str) -> Image:
    return Image(path)

## mixed_content_tool_fn

**Type**: Function

**Description**: def mixed_content_tool_fn() -> list[ContentBlock]:
    return [
        TextContent(type="text", text="Hello"),
        ImageContent(type="image", data="abc", mimeType="image/png"),
        AudioContent(type="audio", data="def", mimeType="audio/wav"),
    ]

## TestServerTools

**Type**: Class

**Description**: class TestServerTools:
    @pytest.mark.anyio
    async def test_add_tool(self):
        mcp = FastMCP()
        mcp.add_tool(tool_fn)
        mcp.add_tool(tool_fn)
        assert len(mcp._tool_manager.list_tools()) == 1

    @pytest.mark.anyio
    async def test_list_tools(self):
        mcp = FastMCP()
        mcp.add_tool(tool_fn)
        async with client_session(mcp._mcp_server) as client:
            tools = await client.list_tools()
            assert len(tools.tools) == 1

    @pytest.mark.anyio
    async def test_call_tool(self):
        mcp = FastMCP()
        mcp.add_tool(tool_fn)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("my_tool", {"arg1": "value"})
            assert not hasattr(result, "error")
            assert len(result.content) > 0

    @pytest.mark.anyio
    async def test_tool_exception_handling(self):
        mcp = FastMCP()
        mcp.add_tool(error_tool_fn)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("error_tool_fn", {})
            assert len(result.content) == 1
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert "Test error" in content.text
            assert result.isError is True

    @pytest.mark.anyio
    async def test_tool_error_handling(self):
        mcp = FastMCP()
        mcp.add_tool(error_tool_fn)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("error_tool_fn", {})
            assert len(result.content) == 1
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert "Test error" in content.text
            assert result.isError is True

    @pytest.mark.anyio
    async def test_tool_error_details(self):
        """Test that exception details are properly formatted in the response"""
        mcp = FastMCP()
        mcp.add_tool(error_tool_fn)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("error_tool_fn", {})
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert isinstance(content.text, str)
            assert "Test error" in content.text
            assert result.isError is True

    @pytest.mark.anyio
    async def test_tool_return_value_conversion(self):
        mcp = FastMCP()
        mcp.add_tool(tool_fn)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("tool_fn", {"x": 1, "y": 2})
            assert len(result.content) == 1
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert content.text == "3"
            # Check structured content - int return type should have structured output
            assert result.structuredContent is not None
            assert result.structuredContent == {"result": 3}

    @pytest.mark.anyio
    async def test_tool_image_helper(self, tmp_path: Path):
        # Create a test image
        image_path = tmp_path / "test.png"
        image_path.write_bytes(b"fake png data")

        mcp = FastMCP()
        mcp.add_tool(image_tool_fn)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("image_tool_fn", {"path": str(image_path)})
            assert len(result.content) == 1
            content = result.content[0]
            assert isinstance(content, ImageContent)
            assert content.type == "image"
            assert content.mimeType == "image/png"
            # Verify base64 encoding
            decoded = base64.b64decode(content.data)
            assert decoded == b"fake png data"
            # Check structured content - Image return type should NOT have structured output
            assert result.structuredContent is None

    @pytest.mark.anyio
    async def test_tool_mixed_content(self):
        mcp = FastMCP()
        mcp.add_tool(mixed_content_tool_fn)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("mixed_content_tool_fn", {})
            assert len(result.content) == 3
            content1, content2, content3 = result.content
            assert isinstance(content1, TextContent)
            assert content1.text == "Hello"
            assert isinstance(content2, ImageContent)
            assert content2.mimeType == "image/png"
            assert content2.data == "abc"
            assert isinstance(content3, AudioContent)
            assert content3.mimeType == "audio/wav"
            assert content3.data == "def"
            assert result.structuredContent is not None
            assert "result" in result.structuredContent
            structured_result = result.structuredContent["result"]
            assert len(structured_result) == 3

            expected_content = [
                {"type": "text", "text": "Hello"},
                {"type": "image", "data": "abc", "mimeType": "image/png"},
                {"type": "audio", "data": "def", "mimeType": "audio/wav"},
            ]

            for i, expected in enumerate(expected_content):
                for key, value in expected.items():
                    assert structured_result[i][key] == value

    @pytest.mark.anyio
    async def test_tool_mixed_list_with_image(self, tmp_path: Path):
        """Test that lists containing Image objects and other types are handled
        correctly"""
        # Create a test image
        image_path = tmp_path / "test.png"
        image_path.write_bytes(b"test image data")

        def mixed_list_fn() -> list:
            return [
                "text message",
                Image(image_path),
                {"key": "value"},
                TextContent(type="text", text="direct content"),
            ]

        mcp = FastMCP()
        mcp.add_tool(mixed_list_fn)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("mixed_list_fn", {})
            assert len(result.content) == 4
            # Check text conversion
            content1 = result.content[0]
            assert isinstance(content1, TextContent)
            assert content1.text == "text message"
            # Check image conversion
            content2 = result.content[1]
            assert isinstance(content2, ImageContent)
            assert content2.mimeType == "image/png"
            assert base64.b64decode(content2.data) == b"test image data"
            # Check dict conversion
            content3 = result.content[2]
            assert isinstance(content3, TextContent)
            assert '"key": "value"' in content3.text
            # Check direct TextContent
            content4 = result.content[3]
            assert isinstance(content4, TextContent)
            assert content4.text == "direct content"
            # Check structured content - untyped list with Image objects should NOT have structured output
            assert result.structuredContent is None

    @pytest.mark.anyio
    async def test_tool_structured_output_basemodel(self):
        """Test tool with structured output returning BaseModel"""

        class UserOutput(BaseModel):
            name: str
            age: int
            active: bool = True

        def get_user(user_id: int) -> UserOutput:
            """Get user by ID"""
            return UserOutput(name="John Doe", age=30)

        mcp = FastMCP()
        mcp.add_tool(get_user)

        async with client_session(mcp._mcp_server) as client:
            # Check that the tool has outputSchema
            tools = await client.list_tools()
            tool = next(t for t in tools.tools if t.name == "get_user")
            assert tool.outputSchema is not None
            assert tool.outputSchema["type"] == "object"
            assert "name" in tool.outputSchema["properties"]
            assert "age" in tool.outputSchema["properties"]

            # Call the tool and check structured output
            result = await client.call_tool("get_user", {"user_id": 123})
            assert result.isError is False
            assert result.structuredContent is not None
            assert result.structuredContent == {"name": "John Doe", "age": 30, "active": True}
            # Content should be JSON serialized version
            assert len(result.content) == 1
            assert isinstance(result.content[0], TextContent)
            assert '"name": "John Doe"' in result.content[0].text

    @pytest.mark.anyio
    async def test_tool_structured_output_primitive(self):
        """Test tool with structured output returning primitive type"""

        def calculate_sum(a: int, b: int) -> int:
            """Add two numbers"""
            return a + b

        mcp = FastMCP()
        mcp.add_tool(calculate_sum)

        async with client_session(mcp._mcp_server) as client:
            # Check that the tool has outputSchema
            tools = await client.list_tools()
            tool = next(t for t in tools.tools if t.name == "calculate_sum")
            assert tool.outputSchema is not None
            # Primitive types are wrapped
            assert tool.outputSchema["type"] == "object"
            assert "result" in tool.outputSchema["properties"]
            assert tool.outputSchema["properties"]["result"]["type"] == "integer"

            # Call the tool
            result = await client.call_tool("calculate_sum", {"a": 5, "b": 7})
            assert result.isError is False
            assert result.structuredContent is not None
            assert result.structuredContent == {"result": 12}

    @pytest.mark.anyio
    async def test_tool_structured_output_list(self):
        """Test tool with structured output returning list"""

        def get_numbers() -> list[int]:
            """Get a list of numbers"""
            return [1, 2, 3, 4, 5]

        mcp = FastMCP()
        mcp.add_tool(get_numbers)

        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("get_numbers", {})
            assert result.isError is False
            assert result.structuredContent is not None
            assert result.structuredContent == {"result": [1, 2, 3, 4, 5]}

    @pytest.mark.anyio
    async def test_tool_structured_output_server_side_validation_error(self):
        """Test that server-side validation errors are handled properly"""

        def get_numbers() -> list[int]:
            return [1, 2, 3, 4, [5]]  # type: ignore

        mcp = FastMCP()
        mcp.add_tool(get_numbers)

        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("get_numbers", {})
            assert result.isError is True
            assert result.structuredContent is None
            assert len(result.content) == 1
            assert isinstance(result.content[0], TextContent)

    @pytest.mark.anyio
    async def test_tool_structured_output_dict_str_any(self):
        """Test tool with dict[str, Any] structured output"""

        def get_metadata() -> dict[str, Any]:
            """Get metadata dictionary"""
            return {
                "version": "1.0.0",
                "enabled": True,
                "count": 42,
                "tags": ["production", "stable"],
                "config": {"nested": {"value": 123}},
            }

        mcp = FastMCP()
        mcp.add_tool(get_metadata)

        async with client_session(mcp._mcp_server) as client:
            # Check schema
            tools = await client.list_tools()
            tool = next(t for t in tools.tools if t.name == "get_metadata")
            assert tool.outputSchema is not None
            assert tool.outputSchema["type"] == "object"
            # dict[str, Any] should have minimal schema
            assert (
                "additionalProperties" not in tool.outputSchema or tool.outputSchema.get("additionalProperties") is True
            )

            # Call tool
            result = await client.call_tool("get_metadata", {})
            assert result.isError is False
            assert result.structuredContent is not None
            expected = {
                "version": "1.0.0",
                "enabled": True,
                "count": 42,
                "tags": ["production", "stable"],
                "config": {"nested": {"value": 123}},
            }
            assert result.structuredContent == expected

    @pytest.mark.anyio
    async def test_tool_structured_output_dict_str_typed(self):
        """Test tool with dict[str, T] structured output for specific T"""

        def get_settings() -> dict[str, str]:
            """Get settings as string dictionary"""
            return {"theme": "dark", "language": "en", "timezone": "UTC"}

        mcp = FastMCP()
        mcp.add_tool(get_settings)

        async with client_session(mcp._mcp_server) as client:
            # Check schema
            tools = await client.list_tools()
            tool = next(t for t in tools.tools if t.name == "get_settings")
            assert tool.outputSchema is not None
            assert tool.outputSchema["type"] == "object"
            assert tool.outputSchema["additionalProperties"]["type"] == "string"

            # Call tool
            result = await client.call_tool("get_settings", {})
            assert result.isError is False
            assert result.structuredContent == {"theme": "dark", "language": "en", "timezone": "UTC"}

## TestServerResources

**Type**: Class

**Description**: class TestServerResources:
    @pytest.mark.anyio
    async def test_text_resource(self):
        mcp = FastMCP()

        def get_text():
            return "Hello, world!"

        resource = FunctionResource(uri=AnyUrl("resource://test"), name="test", fn=get_text)
        mcp.add_resource(resource)

        async with client_session(mcp._mcp_server) as client:
            result = await client.read_resource(AnyUrl("resource://test"))
            assert isinstance(result.contents[0], TextResourceContents)
            assert result.contents[0].text == "Hello, world!"

    @pytest.mark.anyio
    async def test_binary_resource(self):
        mcp = FastMCP()

        def get_binary():
            return b"Binary data"

        resource = FunctionResource(
            uri=AnyUrl("resource://binary"),
            name="binary",
            fn=get_binary,
            mime_type="application/octet-stream",
        )
        mcp.add_resource(resource)

        async with client_session(mcp._mcp_server) as client:
            result = await client.read_resource(AnyUrl("resource://binary"))
            assert isinstance(result.contents[0], BlobResourceContents)
            assert result.contents[0].blob == base64.b64encode(b"Binary data").decode()

    @pytest.mark.anyio
    async def test_file_resource_text(self, tmp_path: Path):
        mcp = FastMCP()

        # Create a text file
        text_file = tmp_path / "test.txt"
        text_file.write_text("Hello from file!")

        resource = FileResource(uri=AnyUrl("file://test.txt"), name="test.txt", path=text_file)
        mcp.add_resource(resource)

        async with client_session(mcp._mcp_server) as client:
            result = await client.read_resource(AnyUrl("file://test.txt"))
            assert isinstance(result.contents[0], TextResourceContents)
            assert result.contents[0].text == "Hello from file!"

    @pytest.mark.anyio
    async def test_file_resource_binary(self, tmp_path: Path):
        mcp = FastMCP()

        # Create a binary file
        binary_file = tmp_path / "test.bin"
        binary_file.write_bytes(b"Binary file data")

        resource = FileResource(
            uri=AnyUrl("file://test.bin"),
            name="test.bin",
            path=binary_file,
            mime_type="application/octet-stream",
        )
        mcp.add_resource(resource)

        async with client_session(mcp._mcp_server) as client:
            result = await client.read_resource(AnyUrl("file://test.bin"))
            assert isinstance(result.contents[0], BlobResourceContents)
            assert result.contents[0].blob == base64.b64encode(b"Binary file data").decode()

    @pytest.mark.anyio
    async def test_function_resource(self):
        mcp = FastMCP()

        @mcp.resource("function://test", name="test_get_data")
        def get_data() -> str:
            """get_data returns a string"""
            return "Hello, world!"

        async with client_session(mcp._mcp_server) as client:
            resources = await client.list_resources()
            assert len(resources.resources) == 1
            resource = resources.resources[0]
            assert resource.description == "get_data returns a string"
            assert resource.uri == AnyUrl("function://test")
            assert resource.name == "test_get_data"
            assert resource.mimeType == "text/plain"

## TestServerResourceTemplates

**Type**: Class

**Description**: class TestServerResourceTemplates:
    @pytest.mark.anyio
    async def test_resource_with_params(self):
        """Test that a resource with function parameters raises an error if the URI
        parameters don't match"""
        mcp = FastMCP()

        with pytest.raises(ValueError, match="Mismatch between URI parameters"):

            @mcp.resource("resource://data")
            def get_data_fn(param: str) -> str:
                return f"Data: {param}"

    @pytest.mark.anyio
    async def test_resource_with_uri_params(self):
        """Test that a resource with URI parameters is automatically a template"""
        mcp = FastMCP()

        with pytest.raises(ValueError, match="Mismatch between URI parameters"):

            @mcp.resource("resource://{param}")
            def get_data() -> str:
                return "Data"

    @pytest.mark.anyio
    async def test_resource_with_untyped_params(self):
        """Test that a resource with untyped parameters raises an error"""
        mcp = FastMCP()

        @mcp.resource("resource://{param}")
        def get_data(param) -> str:
            return "Data"

    @pytest.mark.anyio
    async def test_resource_matching_params(self):
        """Test that a resource with matching URI and function parameters works"""
        mcp = FastMCP()

        @mcp.resource("resource://{name}/data")
        def get_data(name: str) -> str:
            return f"Data for {name}"

        async with client_session(mcp._mcp_server) as client:
            result = await client.read_resource(AnyUrl("resource://test/data"))
            assert isinstance(result.contents[0], TextResourceContents)
            assert result.contents[0].text == "Data for test"

    @pytest.mark.anyio
    async def test_resource_mismatched_params(self):
        """Test that mismatched parameters raise an error"""
        mcp = FastMCP()

        with pytest.raises(ValueError, match="Mismatch between URI parameters"):

            @mcp.resource("resource://{name}/data")
            def get_data(user: str) -> str:
                return f"Data for {user}"

    @pytest.mark.anyio
    async def test_resource_multiple_params(self):
        """Test that multiple parameters work correctly"""
        mcp = FastMCP()

        @mcp.resource("resource://{org}/{repo}/data")
        def get_data(org: str, repo: str) -> str:
            return f"Data for {org}/{repo}"

        async with client_session(mcp._mcp_server) as client:
            result = await client.read_resource(AnyUrl("resource://cursor/fastmcp/data"))
            assert isinstance(result.contents[0], TextResourceContents)
            assert result.contents[0].text == "Data for cursor/fastmcp"

    @pytest.mark.anyio
    async def test_resource_multiple_mismatched_params(self):
        """Test that mismatched parameters raise an error"""
        mcp = FastMCP()

        with pytest.raises(ValueError, match="Mismatch between URI parameters"):

            @mcp.resource("resource://{org}/{repo}/data")
            def get_data_mismatched(org: str, repo_2: str) -> str:
                return f"Data for {org}"

        """Test that a resource with no parameters works as a regular resource"""
        mcp = FastMCP()

        @mcp.resource("resource://static")
        def get_static_data() -> str:
            return "Static data"

        async with client_session(mcp._mcp_server) as client:
            result = await client.read_resource(AnyUrl("resource://static"))
            assert isinstance(result.contents[0], TextResourceContents)
            assert result.contents[0].text == "Static data"

    @pytest.mark.anyio
    async def test_template_to_resource_conversion(self):
        """Test that templates are properly converted to resources when accessed"""
        mcp = FastMCP()

        @mcp.resource("resource://{name}/data")
        def get_data(name: str) -> str:
            return f"Data for {name}"

        # Should be registered as a template
        assert len(mcp._resource_manager._templates) == 1
        assert len(await mcp.list_resources()) == 0

        # When accessed, should create a concrete resource
        resource = await mcp._resource_manager.get_resource("resource://test/data")
        assert isinstance(resource, FunctionResource)
        result = await resource.read()
        assert result == "Data for test"

## TestContextInjection

**Type**: Class

**Description**: class TestContextInjection:
    """Test context injection in tools."""

    @pytest.mark.anyio
    async def test_context_detection(self):
        """Test that context parameters are properly detected."""
        mcp = FastMCP()

        def tool_with_context(x: int, ctx: Context) -> str:
            return f"Request {ctx.request_id}: {x}"

        tool = mcp._tool_manager.add_tool(tool_with_context)
        assert tool.context_kwarg == "ctx"

    @pytest.mark.anyio
    async def test_context_injection(self):
        """Test that context is properly injected into tool calls."""
        mcp = FastMCP()

        def tool_with_context(x: int, ctx: Context) -> str:
            assert ctx.request_id is not None
            return f"Request {ctx.request_id}: {x}"

        mcp.add_tool(tool_with_context)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("tool_with_context", {"x": 42})
            assert len(result.content) == 1
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert "Request" in content.text
            assert "42" in content.text

    @pytest.mark.anyio
    async def test_async_context(self):
        """Test that context works in async functions."""
        mcp = FastMCP()

        async def async_tool(x: int, ctx: Context) -> str:
            assert ctx.request_id is not None
            return f"Async request {ctx.request_id}: {x}"

        mcp.add_tool(async_tool)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("async_tool", {"x": 42})
            assert len(result.content) == 1
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert "Async request" in content.text
            assert "42" in content.text

    @pytest.mark.anyio
    async def test_context_logging(self):
        import mcp.server.session

        """Test that context logging methods work."""
        mcp = FastMCP()

        async def logging_tool(msg: str, ctx: Context) -> str:
            await ctx.debug("Debug message")
            await ctx.info("Info message")
            await ctx.warning("Warning message")
            await ctx.error("Error message")
            return f"Logged messages for {msg}"

        mcp.add_tool(logging_tool)

        with patch("mcp.server.session.ServerSession.send_log_message") as mock_log:
            async with client_session(mcp._mcp_server) as client:
                result = await client.call_tool("logging_tool", {"msg": "test"})
                assert len(result.content) == 1
                content = result.content[0]
                assert isinstance(content, TextContent)
                assert "Logged messages for test" in content.text

                assert mock_log.call_count == 4
                mock_log.assert_any_call(
                    level="debug",
                    data="Debug message",
                    logger=None,
                    related_request_id="1",
                )
                mock_log.assert_any_call(
                    level="info",
                    data="Info message",
                    logger=None,
                    related_request_id="1",
                )
                mock_log.assert_any_call(
                    level="warning",
                    data="Warning message",
                    logger=None,
                    related_request_id="1",
                )
                mock_log.assert_any_call(
                    level="error",
                    data="Error message",
                    logger=None,
                    related_request_id="1",
                )

    @pytest.mark.anyio
    async def test_optional_context(self):
        """Test that context is optional."""
        mcp = FastMCP()

        def no_context(x: int) -> int:
            return x * 2

        mcp.add_tool(no_context)
        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("no_context", {"x": 21})
            assert len(result.content) == 1
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert content.text == "42"

    @pytest.mark.anyio
    async def test_context_resource_access(self):
        """Test that context can access resources."""
        mcp = FastMCP()

        @mcp.resource("test://data")
        def test_resource() -> str:
            return "resource data"

        @mcp.tool()
        async def tool_with_resource(ctx: Context) -> str:
            r_iter = await ctx.read_resource("test://data")
            r_list = list(r_iter)
            assert len(r_list) == 1
            r = r_list[0]
            return f"Read resource: {r.content} with mime type {r.mime_type}"

        async with client_session(mcp._mcp_server) as client:
            result = await client.call_tool("tool_with_resource", {})
            assert len(result.content) == 1
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert "Read resource: resource data" in content.text

## TestServerPrompts

**Type**: Class

**Description**: class TestServerPrompts:
    """Test prompt functionality in FastMCP server."""

    @pytest.mark.anyio
    async def test_prompt_decorator(self):
        """Test that the prompt decorator registers prompts correctly."""
        mcp = FastMCP()

        @mcp.prompt()
        def fn() -> str:
            return "Hello, world!"

        prompts = mcp._prompt_manager.list_prompts()
        assert len(prompts) == 1
        assert prompts[0].name == "fn"
        # Don't compare functions directly since validate_call wraps them
        content = await prompts[0].render()
        assert isinstance(content[0].content, TextContent)
        assert content[0].content.text == "Hello, world!"

    @pytest.mark.anyio
    async def test_prompt_decorator_with_name(self):
        """Test prompt decorator with custom name."""
        mcp = FastMCP()

        @mcp.prompt(name="custom_name")
        def fn() -> str:
            return "Hello, world!"

        prompts = mcp._prompt_manager.list_prompts()
        assert len(prompts) == 1
        assert prompts[0].name == "custom_name"
        content = await prompts[0].render()
        assert isinstance(content[0].content, TextContent)
        assert content[0].content.text == "Hello, world!"

    @pytest.mark.anyio
    async def test_prompt_decorator_with_description(self):
        """Test prompt decorator with custom description."""
        mcp = FastMCP()

        @mcp.prompt(description="A custom description")
        def fn() -> str:
            return "Hello, world!"

        prompts = mcp._prompt_manager.list_prompts()
        assert len(prompts) == 1
        assert prompts[0].description == "A custom description"
        content = await prompts[0].render()
        assert isinstance(content[0].content, TextContent)
        assert content[0].content.text == "Hello, world!"

    def test_prompt_decorator_error(self):
        """Test error when decorator is used incorrectly."""
        mcp = FastMCP()
        with pytest.raises(TypeError, match="decorator was used incorrectly"):

            @mcp.prompt  # type: ignore
            def fn() -> str:
                return "Hello, world!"

    @pytest.mark.anyio
    async def test_list_prompts(self):
        """Test listing prompts through MCP protocol."""
        mcp = FastMCP()

        @mcp.prompt()
        def fn(name: str, optional: str = "default") -> str:
            return f"Hello, {name}!"

        async with client_session(mcp._mcp_server) as client:
            result = await client.list_prompts()
            assert result.prompts is not None
            assert len(result.prompts) == 1
            prompt = result.prompts[0]
            assert prompt.name == "fn"
            assert prompt.arguments is not None
            assert len(prompt.arguments) == 2
            assert prompt.arguments[0].name == "name"
            assert prompt.arguments[0].required is True
            assert prompt.arguments[1].name == "optional"
            assert prompt.arguments[1].required is False

    @pytest.mark.anyio
    async def test_get_prompt(self):
        """Test getting a prompt through MCP protocol."""
        mcp = FastMCP()

        @mcp.prompt()
        def fn(name: str) -> str:
            return f"Hello, {name}!"

        async with client_session(mcp._mcp_server) as client:
            result = await client.get_prompt("fn", {"name": "World"})
            assert len(result.messages) == 1
            message = result.messages[0]
            assert message.role == "user"
            content = message.content
            assert isinstance(content, TextContent)
            assert content.text == "Hello, World!"

    @pytest.mark.anyio
    async def test_get_prompt_with_resource(self):
        """Test getting a prompt that returns resource content."""
        mcp = FastMCP()

        @mcp.prompt()
        def fn() -> Message:
            return UserMessage(
                content=EmbeddedResource(
                    type="resource",
                    resource=TextResourceContents(
                        uri=AnyUrl("file://file.txt"),
                        text="File contents",
                        mimeType="text/plain",
                    ),
                )
            )

        async with client_session(mcp._mcp_server) as client:
            result = await client.get_prompt("fn")
            assert len(result.messages) == 1
            message = result.messages[0]
            assert message.role == "user"
            content = message.content
            assert isinstance(content, EmbeddedResource)
            resource = content.resource
            assert isinstance(resource, TextResourceContents)
            assert resource.text == "File contents"
            assert resource.mimeType == "text/plain"

    @pytest.mark.anyio
    async def test_get_unknown_prompt(self):
        """Test error when getting unknown prompt."""
        mcp = FastMCP()
        async with client_session(mcp._mcp_server) as client:
            with pytest.raises(McpError, match="Unknown prompt"):
                await client.get_prompt("unknown")

    @pytest.mark.anyio
    async def test_get_prompt_missing_args(self):
        """Test error when required arguments are missing."""
        mcp = FastMCP()

        @mcp.prompt()
        def prompt_fn(name: str) -> str:
            return f"Hello, {name}!"

        async with client_session(mcp._mcp_server) as client:
            with pytest.raises(McpError, match="Missing required arguments"):
                await client.get_prompt("prompt_fn")

## TestAddTools

**Type**: Class

**Description**: class TestAddTools:
    def test_basic_function(self):
        """Test registering and running a basic function."""

        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        manager = ToolManager()
        manager.add_tool(add)

        tool = manager.get_tool("add")
        assert tool is not None
        assert tool.name == "add"
        assert tool.description == "Add two numbers."
        assert tool.is_async is False
        assert tool.parameters["properties"]["a"]["type"] == "integer"
        assert tool.parameters["properties"]["b"]["type"] == "integer"

    def test_init_with_tools(self, caplog):
        def add(a: int, b: int) -> int:
            return a + b

        class AddArguments(ArgModelBase):
            a: int
            b: int

        fn_metadata = FuncMetadata(arg_model=AddArguments)

        original_tool = Tool(
            name="add",
            title="Add Tool",
            description="Add two numbers.",
            fn=add,
            fn_metadata=fn_metadata,
            is_async=False,
            parameters=AddArguments.model_json_schema(),
            context_kwarg=None,
            annotations=None,
        )
        manager = ToolManager(tools=[original_tool])
        saved_tool = manager.get_tool("add")
        assert saved_tool == original_tool

        # warn on duplicate tools
        with caplog.at_level(logging.WARNING):
            manager = ToolManager(True, tools=[original_tool, original_tool])
            assert "Tool already exists: add" in caplog.text

    @pytest.mark.anyio
    async def test_async_function(self):
        """Test registering and running an async function."""

        async def fetch_data(url: str) -> str:
            """Fetch data from URL."""
            return f"Data from {url}"

        manager = ToolManager()
        manager.add_tool(fetch_data)

        tool = manager.get_tool("fetch_data")
        assert tool is not None
        assert tool.name == "fetch_data"
        assert tool.description == "Fetch data from URL."
        assert tool.is_async is True
        assert tool.parameters["properties"]["url"]["type"] == "string"

    def test_pydantic_model_function(self):
        """Test registering a function that takes a Pydantic model."""

        class UserInput(BaseModel):
            name: str
            age: int

        def create_user(user: UserInput, flag: bool) -> dict:
            """Create a new user."""
            return {"id": 1, **user.model_dump()}

        manager = ToolManager()
        manager.add_tool(create_user)

        tool = manager.get_tool("create_user")
        assert tool is not None
        assert tool.name == "create_user"
        assert tool.description == "Create a new user."
        assert tool.is_async is False
        assert "name" in tool.parameters["$defs"]["UserInput"]["properties"]
        assert "age" in tool.parameters["$defs"]["UserInput"]["properties"]
        assert "flag" in tool.parameters["properties"]

    def test_add_callable_object(self):
        """Test registering a callable object."""

        class MyTool:
            def __init__(self):
                self.__name__ = "MyTool"

            def __call__(self, x: int) -> int:
                return x * 2

        manager = ToolManager()
        tool = manager.add_tool(MyTool())
        assert tool.name == "MyTool"
        assert tool.is_async is False
        assert tool.parameters["properties"]["x"]["type"] == "integer"

    @pytest.mark.anyio
    async def test_add_async_callable_object(self):
        """Test registering an async callable object."""

        class MyAsyncTool:
            def __init__(self):
                self.__name__ = "MyAsyncTool"

            async def __call__(self, x: int) -> int:
                return x * 2

        manager = ToolManager()
        tool = manager.add_tool(MyAsyncTool())
        assert tool.name == "MyAsyncTool"
        assert tool.is_async is True
        assert tool.parameters["properties"]["x"]["type"] == "integer"

    def test_add_invalid_tool(self):
        manager = ToolManager()
        with pytest.raises(AttributeError):
            manager.add_tool(1)  # type: ignore

    def test_add_lambda(self):
        manager = ToolManager()
        tool = manager.add_tool(lambda x: x, name="my_tool")
        assert tool.name == "my_tool"

    def test_add_lambda_with_no_name(self):
        manager = ToolManager()
        with pytest.raises(ValueError, match="You must provide a name for lambda functions"):
            manager.add_tool(lambda x: x)

    def test_warn_on_duplicate_tools(self, caplog):
        """Test warning on duplicate tools."""

        def f(x: int) -> int:
            return x

        manager = ToolManager()
        manager.add_tool(f)
        with caplog.at_level(logging.WARNING):
            manager.add_tool(f)
            assert "Tool already exists: f" in caplog.text

    def test_disable_warn_on_duplicate_tools(self, caplog):
        """Test disabling warning on duplicate tools."""

        def f(x: int) -> int:
            return x

        manager = ToolManager()
        manager.add_tool(f)
        manager.warn_on_duplicate_tools = False
        with caplog.at_level(logging.WARNING):
            manager.add_tool(f)
            assert "Tool already exists: f" not in caplog.text

## TestCallTools

**Type**: Class

**Description**: class TestCallTools:
    @pytest.mark.anyio
    async def test_call_tool(self):
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        manager = ToolManager()
        manager.add_tool(add)
        result = await manager.call_tool("add", {"a": 1, "b": 2})
        assert result == 3

    @pytest.mark.anyio
    async def test_call_async_tool(self):
        async def double(n: int) -> int:
            """Double a number."""
            return n * 2

        manager = ToolManager()
        manager.add_tool(double)
        result = await manager.call_tool("double", {"n": 5})
        assert result == 10

    @pytest.mark.anyio
    async def test_call_object_tool(self):
        class MyTool:
            def __init__(self):
                self.__name__ = "MyTool"

            def __call__(self, x: int) -> int:
                return x * 2

        manager = ToolManager()
        tool = manager.add_tool(MyTool())
        result = await tool.run({"x": 5})
        assert result == 10

    @pytest.mark.anyio
    async def test_call_async_object_tool(self):
        class MyAsyncTool:
            def __init__(self):
                self.__name__ = "MyAsyncTool"

            async def __call__(self, x: int) -> int:
                return x * 2

        manager = ToolManager()
        tool = manager.add_tool(MyAsyncTool())
        result = await tool.run({"x": 5})
        assert result == 10

    @pytest.mark.anyio
    async def test_call_tool_with_default_args(self):
        def add(a: int, b: int = 1) -> int:
            """Add two numbers."""
            return a + b

        manager = ToolManager()
        manager.add_tool(add)
        result = await manager.call_tool("add", {"a": 1})
        assert result == 2

    @pytest.mark.anyio
    async def test_call_tool_with_missing_args(self):
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        manager = ToolManager()
        manager.add_tool(add)
        with pytest.raises(ToolError):
            await manager.call_tool("add", {"a": 1})

    @pytest.mark.anyio
    async def test_call_unknown_tool(self):
        manager = ToolManager()
        with pytest.raises(ToolError):
            await manager.call_tool("unknown", {"a": 1})

    @pytest.mark.anyio
    async def test_call_tool_with_list_int_input(self):
        def sum_vals(vals: list[int]) -> int:
            return sum(vals)

        manager = ToolManager()
        manager.add_tool(sum_vals)
        # Try both with plain list and with JSON list
        result = await manager.call_tool("sum_vals", {"vals": "[1, 2, 3]"})
        assert result == 6
        result = await manager.call_tool("sum_vals", {"vals": [1, 2, 3]})
        assert result == 6

    @pytest.mark.anyio
    async def test_call_tool_with_list_str_or_str_input(self):
        def concat_strs(vals: list[str] | str) -> str:
            return vals if isinstance(vals, str) else "".join(vals)

        manager = ToolManager()
        manager.add_tool(concat_strs)
        # Try both with plain python object and with JSON list
        result = await manager.call_tool("concat_strs", {"vals": ["a", "b", "c"]})
        assert result == "abc"
        result = await manager.call_tool("concat_strs", {"vals": '["a", "b", "c"]'})
        assert result == "abc"
        result = await manager.call_tool("concat_strs", {"vals": "a"})
        assert result == "a"
        result = await manager.call_tool("concat_strs", {"vals": '"a"'})
        assert result == '"a"'

    @pytest.mark.anyio
    async def test_call_tool_with_complex_model(self):
        class MyShrimpTank(BaseModel):
            class Shrimp(BaseModel):
                name: str

            shrimp: list[Shrimp]
            x: None

        def name_shrimp(tank: MyShrimpTank, ctx: Context) -> list[str]:
            return [x.name for x in tank.shrimp]

        manager = ToolManager()
        manager.add_tool(name_shrimp)
        result = await manager.call_tool(
            "name_shrimp",
            {"tank": {"x": None, "shrimp": [{"name": "rex"}, {"name": "gertrude"}]}},
        )
        assert result == ["rex", "gertrude"]
        result = await manager.call_tool(
            "name_shrimp",
            {"tank": '{"x": null, "shrimp": [{"name": "rex"}, {"name": "gertrude"}]}'},
        )
        assert result == ["rex", "gertrude"]

## TestToolSchema

**Type**: Class

**Description**: class TestToolSchema:
    @pytest.mark.anyio
    async def test_context_arg_excluded_from_schema(self):
        def something(a: int, ctx: Context) -> int:
            return a

        manager = ToolManager()
        tool = manager.add_tool(something)
        assert "ctx" not in json.dumps(tool.parameters)
        assert "Context" not in json.dumps(tool.parameters)
        assert "ctx" not in tool.fn_metadata.arg_model.model_fields

## TestContextHandling

**Type**: Class

**Description**: class TestContextHandling:
    """Test context handling in the tool manager."""

    def test_context_parameter_detection(self):
        """Test that context parameters are properly detected in
        Tool.from_function()."""

        def tool_with_context(x: int, ctx: Context) -> str:
            return str(x)

        manager = ToolManager()
        tool = manager.add_tool(tool_with_context)
        assert tool.context_kwarg == "ctx"

        def tool_without_context(x: int) -> str:
            return str(x)

        tool = manager.add_tool(tool_without_context)
        assert tool.context_kwarg is None

        def tool_with_parametrized_context(x: int, ctx: Context[ServerSessionT, LifespanContextT, RequestT]) -> str:
            return str(x)

        tool = manager.add_tool(tool_with_parametrized_context)
        assert tool.context_kwarg == "ctx"

    @pytest.mark.anyio
    async def test_context_injection(self):
        """Test that context is properly injected during tool execution."""

        def tool_with_context(x: int, ctx: Context) -> str:
            assert isinstance(ctx, Context)
            return str(x)

        manager = ToolManager()
        manager.add_tool(tool_with_context)

        mcp = FastMCP()
        ctx = mcp.get_context()
        result = await manager.call_tool("tool_with_context", {"x": 42}, context=ctx)
        assert result == "42"

    @pytest.mark.anyio
    async def test_context_injection_async(self):
        """Test that context is properly injected in async tools."""

        async def async_tool(x: int, ctx: Context) -> str:
            assert isinstance(ctx, Context)
            return str(x)

        manager = ToolManager()
        manager.add_tool(async_tool)

        mcp = FastMCP()
        ctx = mcp.get_context()
        result = await manager.call_tool("async_tool", {"x": 42}, context=ctx)
        assert result == "42"

    @pytest.mark.anyio
    async def test_context_optional(self):
        """Test that context is optional when calling tools."""

        def tool_with_context(x: int, ctx: Context | None = None) -> str:
            return str(x)

        manager = ToolManager()
        manager.add_tool(tool_with_context)
        # Should not raise an error when context is not provided
        result = await manager.call_tool("tool_with_context", {"x": 42})
        assert result == "42"

    @pytest.mark.anyio
    async def test_context_error_handling(self):
        """Test error handling when context injection fails."""

        def tool_with_context(x: int, ctx: Context) -> str:
            raise ValueError("Test error")

        manager = ToolManager()
        manager.add_tool(tool_with_context)

        mcp = FastMCP()
        ctx = mcp.get_context()
        with pytest.raises(ToolError, match="Error executing tool tool_with_context"):
            await manager.call_tool("tool_with_context", {"x": 42}, context=ctx)

## TestToolAnnotations

**Type**: Class

**Description**: class TestToolAnnotations:
    def test_tool_annotations(self):
        """Test that tool annotations are correctly added to tools."""

        def read_data(path: str) -> str:
            """Read data from a file."""
            return f"Data from {path}"

        annotations = ToolAnnotations(
            title="File Reader",
            readOnlyHint=True,
            openWorldHint=False,
        )

        manager = ToolManager()
        tool = manager.add_tool(read_data, annotations=annotations)

        assert tool.annotations is not None
        assert tool.annotations.title == "File Reader"
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.openWorldHint is False

    @pytest.mark.anyio
    async def test_tool_annotations_in_fastmcp(self):
        """Test that tool annotations are included in MCPTool conversion."""

        app = FastMCP()

        @app.tool(annotations=ToolAnnotations(title="Echo Tool", readOnlyHint=True))
        def echo(message: str) -> str:
            """Echo a message back."""
            return message

        tools = await app.list_tools()
        assert len(tools) == 1
        assert tools[0].annotations is not None
        assert tools[0].annotations.title == "Echo Tool"
        assert tools[0].annotations.readOnlyHint is True

## TestStructuredOutput

**Type**: Class

**Description**: class TestStructuredOutput:
    """Test structured output functionality in tools."""

    @pytest.mark.anyio
    async def test_tool_with_basemodel_output(self):
        """Test tool with BaseModel return type."""

        class UserOutput(BaseModel):
            name: str
            age: int

        def get_user(user_id: int) -> UserOutput:
            """Get user by ID."""
            return UserOutput(name="John", age=30)

        manager = ToolManager()
        manager.add_tool(get_user)
        result = await manager.call_tool("get_user", {"user_id": 1}, convert_result=True)
        # don't test unstructured output here, just the structured conversion
        assert len(result) == 2 and result[1] == {"name": "John", "age": 30}

    @pytest.mark.anyio
    async def test_tool_with_primitive_output(self):
        """Test tool with primitive return type."""

        def double_number(n: int) -> int:
            """Double a number."""
            return 10

        manager = ToolManager()
        manager.add_tool(double_number)
        result = await manager.call_tool("double_number", {"n": 5})
        assert result == 10
        result = await manager.call_tool("double_number", {"n": 5}, convert_result=True)
        assert isinstance(result[0][0], TextContent) and result[1] == {"result": 10}

    @pytest.mark.anyio
    async def test_tool_with_typeddict_output(self):
        """Test tool with TypedDict return type."""

        class UserDict(TypedDict):
            name: str
            age: int

        expected_output = {"name": "Alice", "age": 25}

        def get_user_dict(user_id: int) -> UserDict:
            """Get user as dict."""
            return UserDict(name="Alice", age=25)

        manager = ToolManager()
        manager.add_tool(get_user_dict)
        result = await manager.call_tool("get_user_dict", {"user_id": 1})
        assert result == expected_output

    @pytest.mark.anyio
    async def test_tool_with_dataclass_output(self):
        """Test tool with dataclass return type."""

        @dataclass
        class Person:
            name: str
            age: int

        expected_output = {"name": "Bob", "age": 40}

        def get_person() -> Person:
            """Get a person."""
            return Person("Bob", 40)

        manager = ToolManager()
        manager.add_tool(get_person)
        result = await manager.call_tool("get_person", {}, convert_result=True)
        # don't test unstructured output here, just the structured conversion
        assert len(result) == 2 and result[1] == expected_output

    @pytest.mark.anyio
    async def test_tool_with_list_output(self):
        """Test tool with list return type."""

        expected_list = [1, 2, 3, 4, 5]
        expected_output = {"result": expected_list}

        def get_numbers() -> list[int]:
            """Get a list of numbers."""
            return expected_list

        manager = ToolManager()
        manager.add_tool(get_numbers)
        result = await manager.call_tool("get_numbers", {})
        assert result == expected_list
        result = await manager.call_tool("get_numbers", {}, convert_result=True)
        assert isinstance(result[0][0], TextContent) and result[1] == expected_output

    @pytest.mark.anyio
    async def test_tool_without_structured_output(self):
        """Test that tools work normally when structured_output=False."""

        def get_dict() -> dict:
            """Get a dict."""
            return {"key": "value"}

        manager = ToolManager()
        manager.add_tool(get_dict, structured_output=False)
        result = await manager.call_tool("get_dict", {})
        assert isinstance(result, dict)
        assert result == {"key": "value"}

    def test_tool_output_schema_property(self):
        """Test that Tool.output_schema property works correctly."""

        class UserOutput(BaseModel):
            name: str
            age: int

        def get_user() -> UserOutput:
            return UserOutput(name="Test", age=25)

        manager = ToolManager()
        tool = manager.add_tool(get_user)

        # Test that output_schema is populated
        expected_schema = {
            "properties": {"name": {"type": "string", "title": "Name"}, "age": {"type": "integer", "title": "Age"}},
            "required": ["name", "age"],
            "title": "UserOutput",
            "type": "object",
        }
        assert tool.output_schema == expected_schema

    @pytest.mark.anyio
    async def test_tool_with_dict_str_any_output(self):
        """Test tool with dict[str, Any] return type."""

        def get_config() -> dict[str, Any]:
            """Get configuration"""
            return {"debug": True, "port": 8080, "features": ["auth", "logging"]}

        manager = ToolManager()
        tool = manager.add_tool(get_config)

        # Check output schema
        assert tool.output_schema is not None
        assert tool.output_schema["type"] == "object"
        assert "properties" not in tool.output_schema  # dict[str, Any] has no constraints

        # Test raw result
        result = await manager.call_tool("get_config", {})
        expected = {"debug": True, "port": 8080, "features": ["auth", "logging"]}
        assert result == expected

        # Test converted result
        result = await manager.call_tool("get_config", {})
        assert result == expected

    @pytest.mark.anyio
    async def test_tool_with_dict_str_typed_output(self):
        """Test tool with dict[str, T] return type for specific T."""

        def get_scores() -> dict[str, int]:
            """Get player scores"""
            return {"alice": 100, "bob": 85, "charlie": 92}

        manager = ToolManager()
        tool = manager.add_tool(get_scores)

        # Check output schema
        assert tool.output_schema is not None
        assert tool.output_schema["type"] == "object"
        assert tool.output_schema["additionalProperties"]["type"] == "integer"

        # Test raw result
        result = await manager.call_tool("get_scores", {})
        expected = {"alice": 100, "bob": 85, "charlie": 92}
        assert result == expected

        # Test converted result
        result = await manager.call_tool("get_scores", {})
        assert result == expected

## MockOAuthProvider

**Type**: Class

**Description**: class MockOAuthProvider(OAuthAuthorizationServerProvider):
    def __init__(self):
        self.clients = {}
        self.auth_codes = {}  # code -> {client_id, code_challenge, redirect_uri}
        self.tokens = {}  # token -> {client_id, scopes, expires_at}
        self.refresh_tokens = {}  # refresh_token -> access_token

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        # toy authorize implementation which just immediately generates an authorization
        # code and completes the redirect
        code = AuthorizationCode(
            code=f"code_{int(time.time())}",
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=params.scopes or ["read", "write"],
        )
        self.auth_codes[code.code] = code

        return construct_redirect_uri(str(params.redirect_uri), code=code.code, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        assert authorization_code.code in self.auth_codes

        # Generate an access token and refresh token
        access_token = f"access_{secrets.token_hex(32)}"
        refresh_token = f"refresh_{secrets.token_hex(32)}"

        # Store the tokens
        self.tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
        )

        self.refresh_tokens[refresh_token] = access_token

        # Remove the used code
        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=3600,
            scope="read write",
            refresh_token=refresh_token,
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        old_access_token = self.refresh_tokens.get(refresh_token)
        if old_access_token is None:
            return None
        token_info = self.tokens.get(old_access_token)
        if token_info is None:
            return None

        # Create a RefreshToken object that matches what is expected in later code
        refresh_obj = RefreshToken(
            token=refresh_token,
            client_id=token_info.client_id,
            scopes=token_info.scopes,
            expires_at=token_info.expires_at,
        )

        return refresh_obj

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Check if refresh token exists
        assert refresh_token.token in self.refresh_tokens

        old_access_token = self.refresh_tokens[refresh_token.token]

        # Check if the access token exists
        assert old_access_token in self.tokens

        # Check if the token was issued to this client
        token_info = self.tokens[old_access_token]
        assert token_info.client_id == client.client_id

        # Generate a new access token and refresh token
        new_access_token = f"access_{secrets.token_hex(32)}"
        new_refresh_token = f"refresh_{secrets.token_hex(32)}"

        # Store the new tokens
        self.tokens[new_access_token] = AccessToken(
            token=new_access_token,
            client_id=client.client_id,
            scopes=scopes or token_info.scopes,
            expires_at=int(time.time()) + 3600,
        )

        self.refresh_tokens[new_refresh_token] = new_access_token

        # Remove the old tokens
        del self.refresh_tokens[refresh_token.token]
        del self.tokens[old_access_token]

        return OAuthToken(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(scopes) if scopes else " ".join(token_info.scopes),
            refresh_token=new_refresh_token,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        token_info = self.tokens.get(token)

        # Check if token is expired
        # if token_info.expires_at < int(time.time()):
        #     raise InvalidTokenError("Access token has expired")

        return token_info and AccessToken(
            token=token,
            client_id=token_info.client_id,
            scopes=token_info.scopes,
            expires_at=token_info.expires_at,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        match token:
            case RefreshToken():
                # Remove the refresh token
                del self.refresh_tokens[token.token]

            case AccessToken():
                # Remove the access token
                del self.tokens[token.token]

                # Also remove any refresh tokens that point to this access token
                for refresh_token, access_token in list(self.refresh_tokens.items()):
                    if access_token == token.token:
                        del self.refresh_tokens[refresh_token]

## TestAuthEndpoints

**Type**: Class

**Description**: class TestAuthEndpoints:
    @pytest.mark.anyio
    async def test_metadata_endpoint(self, test_client: httpx.AsyncClient):
        """Test the OAuth 2.0 metadata endpoint."""
        print("Sending request to metadata endpoint")
        response = await test_client.get("/.well-known/oauth-authorization-server")
        print(f"Got response: {response.status_code}")
        if response.status_code != 200:
            print(f"Response content: {response.content}")
        assert response.status_code == 200

        metadata = response.json()
        assert metadata["issuer"] == "https://auth.example.com/"
        assert metadata["authorization_endpoint"] == "https://auth.example.com/authorize"
        assert metadata["token_endpoint"] == "https://auth.example.com/token"
        assert metadata["registration_endpoint"] == "https://auth.example.com/register"
        assert metadata["revocation_endpoint"] == "https://auth.example.com/revoke"
        assert metadata["response_types_supported"] == ["code"]
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        assert metadata["token_endpoint_auth_methods_supported"] == ["client_secret_post"]
        assert metadata["grant_types_supported"] == [
            "authorization_code",
            "refresh_token",
        ]
        assert metadata["service_documentation"] == "https://docs.example.com/"

    @pytest.mark.anyio
    async def test_token_validation_error(self, test_client: httpx.AsyncClient):
        """Test token endpoint error - validation error."""
        # Missing required fields
        response = await test_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                # Missing code, code_verifier, client_id, etc.
            },
        )
        error_response = response.json()
        assert error_response["error"] == "invalid_request"
        assert "error_description" in error_response  # Contains validation error messages

    @pytest.mark.anyio
    async def test_token_invalid_auth_code(self, test_client, registered_client, pkce_challenge):
        """Test token endpoint error - authorization code does not exist."""
        # Try to use a non-existent authorization code
        response = await test_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "code": "non_existent_auth_code",
                "code_verifier": pkce_challenge["code_verifier"],
                "redirect_uri": "https://client.example.com/callback",
            },
        )
        print(f"Status code: {response.status_code}")
        print(f"Response body: {response.content}")
        print(f"Response JSON: {response.json()}")
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["error"] == "invalid_grant"
        assert "authorization code does not exist" in error_response["error_description"]

    @pytest.mark.anyio
    async def test_token_expired_auth_code(
        self,
        test_client,
        registered_client,
        auth_code,
        pkce_challenge,
        mock_oauth_provider,
    ):
        """Test token endpoint error - authorization code has expired."""
        # Get the current time for our time mocking
        current_time = time.time()

        # Find the auth code object
        code_value = auth_code["code"]
        found_code = None
        for code_obj in mock_oauth_provider.auth_codes.values():
            if code_obj.code == code_value:
                found_code = code_obj
                break

        assert found_code is not None

        # Authorization codes are typically short-lived (5 minutes = 300 seconds)
        # So we'll mock time to be 10 minutes (600 seconds) in the future
        with unittest.mock.patch("time.time", return_value=current_time + 600):
            # Try to use the expired authorization code
            response = await test_client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": registered_client["client_id"],
                    "client_secret": registered_client["client_secret"],
                    "code": code_value,
                    "code_verifier": pkce_challenge["code_verifier"],
                    "redirect_uri": auth_code["redirect_uri"],
                },
            )
            assert response.status_code == 400
            error_response = response.json()
            assert error_response["error"] == "invalid_grant"
            assert "authorization code has expired" in error_response["error_description"]

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "registered_client",
        [
            {
                "redirect_uris": [
                    "https://client.example.com/callback",
                    "https://client.example.com/other-callback",
                ]
            }
        ],
        indirect=True,
    )
    async def test_token_redirect_uri_mismatch(self, test_client, registered_client, auth_code, pkce_challenge):
        """Test token endpoint error - redirect URI mismatch."""
        # Try to use the code with a different redirect URI
        response = await test_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "code": auth_code["code"],
                "code_verifier": pkce_challenge["code_verifier"],
                # Different from the one used in /authorize
                "redirect_uri": "https://client.example.com/other-callback",
            },
        )
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["error"] == "invalid_request"
        assert "redirect_uri did not match" in error_response["error_description"]

    @pytest.mark.anyio
    async def test_token_code_verifier_mismatch(self, test_client, registered_client, auth_code):
        """Test token endpoint error - PKCE code verifier mismatch."""
        # Try to use the code with an incorrect code verifier
        response = await test_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "code": auth_code["code"],
                # Different from the one used to create challenge
                "code_verifier": "incorrect_code_verifier",
                "redirect_uri": auth_code["redirect_uri"],
            },
        )
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["error"] == "invalid_grant"
        assert "incorrect code_verifier" in error_response["error_description"]

    @pytest.mark.anyio
    async def test_token_invalid_refresh_token(self, test_client, registered_client):
        """Test token endpoint error - refresh token does not exist."""
        # Try to use a non-existent refresh token
        response = await test_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "refresh_token": "non_existent_refresh_token",
            },
        )
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["error"] == "invalid_grant"
        assert "refresh token does not exist" in error_response["error_description"]

    @pytest.mark.anyio
    async def test_token_expired_refresh_token(
        self,
        test_client,
        registered_client,
        auth_code,
        pkce_challenge,
        mock_oauth_provider,
    ):
        """Test token endpoint error - refresh token has expired."""
        # Step 1: First, let's create a token and refresh token at the current time
        current_time = time.time()

        # Exchange authorization code for tokens normally
        token_response = await test_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "code": auth_code["code"],
                "code_verifier": pkce_challenge["code_verifier"],
                "redirect_uri": auth_code["redirect_uri"],
            },
        )
        assert token_response.status_code == 200
        tokens = token_response.json()
        refresh_token = tokens["refresh_token"]

        # Step 2: Time travel forward 4 hours (tokens expire in 1 hour by default)
        # Mock the time.time() function to return a value 4 hours in the future
        with unittest.mock.patch("time.time", return_value=current_time + 14400):  # 4 hours = 14400 seconds
            # Try to use the refresh token which should now be considered expired
            response = await test_client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": registered_client["client_id"],
                    "client_secret": registered_client["client_secret"],
                    "refresh_token": refresh_token,
                },
            )

            # In the "future", the token should be considered expired
            assert response.status_code == 400
            error_response = response.json()
            assert error_response["error"] == "invalid_grant"
            assert "refresh token has expired" in error_response["error_description"]

    @pytest.mark.anyio
    async def test_token_invalid_scope(self, test_client, registered_client, auth_code, pkce_challenge):
        """Test token endpoint error - invalid scope in refresh token request."""
        # Exchange authorization code for tokens
        token_response = await test_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "code": auth_code["code"],
                "code_verifier": pkce_challenge["code_verifier"],
                "redirect_uri": auth_code["redirect_uri"],
            },
        )
        assert token_response.status_code == 200

        tokens = token_response.json()
        refresh_token = tokens["refresh_token"]

        # Try to use refresh token with an invalid scope
        response = await test_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "refresh_token": refresh_token,
                "scope": "read write invalid_scope",  # Adding an invalid scope
            },
        )
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["error"] == "invalid_scope"
        assert "cannot request scope" in error_response["error_description"]

    @pytest.mark.anyio
    async def test_client_registration(self, test_client: httpx.AsyncClient, mock_oauth_provider: MockOAuthProvider):
        """Test client registration."""
        client_metadata = {
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "Test Client",
            "client_uri": "https://client.example.com",
        }

        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 201, response.content

        client_info = response.json()
        assert "client_id" in client_info
        assert "client_secret" in client_info
        assert client_info["client_name"] == "Test Client"
        assert client_info["redirect_uris"] == ["https://client.example.com/callback"]

        # Verify that the client was registered
        # assert await mock_oauth_provider.clients_store.get_client(
        #     client_info["client_id"]
        # ) is not None

    @pytest.mark.anyio
    async def test_client_registration_missing_required_fields(self, test_client: httpx.AsyncClient):
        """Test client registration with missing required fields."""
        # Missing redirect_uris which is a required field
        client_metadata = {
            "client_name": "Test Client",
            "client_uri": "https://client.example.com",
        }

        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 400
        error_data = response.json()
        assert "error" in error_data
        assert error_data["error"] == "invalid_client_metadata"
        assert error_data["error_description"] == "redirect_uris: Field required"

    @pytest.mark.anyio
    async def test_client_registration_invalid_uri(self, test_client: httpx.AsyncClient):
        """Test client registration with invalid URIs."""
        # Invalid redirect_uri format
        client_metadata = {
            "redirect_uris": ["not-a-valid-uri"],
            "client_name": "Test Client",
        }

        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 400
        error_data = response.json()
        assert "error" in error_data
        assert error_data["error"] == "invalid_client_metadata"
        assert error_data["error_description"] == (
            "redirect_uris.0: Input should be a valid URL, " "relative URL without a base"
        )

    @pytest.mark.anyio
    async def test_client_registration_empty_redirect_uris(self, test_client: httpx.AsyncClient):
        """Test client registration with empty redirect_uris array."""
        client_metadata = {
            "redirect_uris": [],  # Empty array
            "client_name": "Test Client",
        }

        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 400
        error_data = response.json()
        assert "error" in error_data
        assert error_data["error"] == "invalid_client_metadata"
        assert (
            error_data["error_description"] == "redirect_uris: List should have at least 1 item after validation, not 0"
        )

    @pytest.mark.anyio
    async def test_authorize_form_post(
        self,
        test_client: httpx.AsyncClient,
        mock_oauth_provider: MockOAuthProvider,
        pkce_challenge,
    ):
        """Test the authorization endpoint using POST with form-encoded data."""
        # Register a client
        client_metadata = {
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "Test Client",
            "grant_types": ["authorization_code", "refresh_token"],
        }

        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 201
        client_info = response.json()

        # Use POST with form-encoded data for authorization
        response = await test_client.post(
            "/authorize",
            data={
                "response_type": "code",
                "client_id": client_info["client_id"],
                "redirect_uri": "https://client.example.com/callback",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_form_state",
            },
        )
        assert response.status_code == 302

        # Extract the authorization code from the redirect URL
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)

        assert "code" in query_params
        assert query_params["state"][0] == "test_form_state"

    @pytest.mark.anyio
    async def test_authorization_get(
        self,
        test_client: httpx.AsyncClient,
        mock_oauth_provider: MockOAuthProvider,
        pkce_challenge,
    ):
        """Test the full authorization flow."""
        # 1. Register a client
        client_metadata = {
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "Test Client",
            "grant_types": ["authorization_code", "refresh_token"],
        }

        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 201
        client_info = response.json()

        # 2. Request authorization using GET with query params
        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_info["client_id"],
                "redirect_uri": "https://client.example.com/callback",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )
        assert response.status_code == 302

        # 3. Extract the authorization code from the redirect URL
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)

        assert "code" in query_params
        assert query_params["state"][0] == "test_state"
        auth_code = query_params["code"][0]

        # 4. Exchange the authorization code for tokens
        response = await test_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
                "code": auth_code,
                "code_verifier": pkce_challenge["code_verifier"],
                "redirect_uri": "https://client.example.com/callback",
            },
        )
        assert response.status_code == 200

        token_response = response.json()
        assert "access_token" in token_response
        assert "token_type" in token_response
        assert "refresh_token" in token_response
        assert "expires_in" in token_response
        assert token_response["token_type"] == "Bearer"

        # 5. Verify the access token
        access_token = token_response["access_token"]
        refresh_token = token_response["refresh_token"]

        # Create a test client with the token
        auth_info = await mock_oauth_provider.load_access_token(access_token)
        assert auth_info
        assert auth_info.client_id == client_info["client_id"]
        assert "read" in auth_info.scopes
        assert "write" in auth_info.scopes

        # 6. Refresh the token
        response = await test_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
                "refresh_token": refresh_token,
                "redirect_uri": "https://client.example.com/callback",
            },
        )
        assert response.status_code == 200

        new_token_response = response.json()
        assert "access_token" in new_token_response
        assert "refresh_token" in new_token_response
        assert new_token_response["access_token"] != access_token
        assert new_token_response["refresh_token"] != refresh_token

        # 7. Revoke the token
        response = await test_client.post(
            "/revoke",
            data={
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
                "token": new_token_response["access_token"],
            },
        )
        assert response.status_code == 200

        # Verify that the token was revoked
        assert await mock_oauth_provider.load_access_token(new_token_response["access_token"]) is None

    @pytest.mark.anyio
    async def test_revoke_invalid_token(self, test_client, registered_client):
        """Test revoking an invalid token."""
        response = await test_client.post(
            "/revoke",
            data={
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "token": "invalid_token",
            },
        )
        # per RFC, this should return 200 even if the token is invalid
        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_revoke_with_malformed_token(self, test_client, registered_client):
        response = await test_client.post(
            "/revoke",
            data={
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "token": 123,
                "token_type_hint": "asdf",
            },
        )
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["error"] == "invalid_request"
        assert "token_type_hint" in error_response["error_description"]

    @pytest.mark.anyio
    async def test_client_registration_disallowed_scopes(self, test_client: httpx.AsyncClient):
        """Test client registration with scopes that are not allowed."""
        client_metadata = {
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "Test Client",
            "scope": "read write profile admin",  # 'admin' is not in valid_scopes
        }

        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 400
        error_data = response.json()
        assert "error" in error_data
        assert error_data["error"] == "invalid_client_metadata"
        assert "scope" in error_data["error_description"]
        assert "admin" in error_data["error_description"]

    @pytest.mark.anyio
    async def test_client_registration_default_scopes(
        self, test_client: httpx.AsyncClient, mock_oauth_provider: MockOAuthProvider
    ):
        client_metadata = {
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "Test Client",
            # No scope specified
        }

        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 201
        client_info = response.json()

        # Verify client was registered successfully
        assert client_info["scope"] == "read write"

        # Retrieve the client from the store to verify default scopes
        registered_client = await mock_oauth_provider.get_client(client_info["client_id"])
        assert registered_client is not None

        # Check that default scopes were applied
        assert registered_client.scope == "read write"

    @pytest.mark.anyio
    async def test_client_registration_invalid_grant_type(self, test_client: httpx.AsyncClient):
        client_metadata = {
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "Test Client",
            "grant_types": ["authorization_code"],
        }

        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 400
        error_data = response.json()
        assert "error" in error_data
        assert error_data["error"] == "invalid_client_metadata"
        assert error_data["error_description"] == "grant_types must be authorization_code and refresh_token"

## TestAuthorizeEndpointErrors

**Type**: Class

**Description**: class TestAuthorizeEndpointErrors:
    """Test error handling in the OAuth authorization endpoint."""

    @pytest.mark.anyio
    async def test_authorize_missing_client_id(self, test_client: httpx.AsyncClient, pkce_challenge):
        """Test authorization endpoint with missing client_id.

        According to the OAuth2.0 spec, if client_id is missing, the server should
        inform the resource owner and NOT redirect.
        """
        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                # Missing client_id
                "redirect_uri": "https://client.example.com/callback",
                "state": "test_state",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
            },
        )

        # Should NOT redirect, should show an error page
        assert response.status_code == 400
        # The response should include an error message about missing client_id
        assert "client_id" in response.text.lower()

    @pytest.mark.anyio
    async def test_authorize_invalid_client_id(self, test_client: httpx.AsyncClient, pkce_challenge):
        """Test authorization endpoint with invalid client_id.

        According to the OAuth2.0 spec, if client_id is invalid, the server should
        inform the resource owner and NOT redirect.
        """
        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "invalid_client_id_that_does_not_exist",
                "redirect_uri": "https://client.example.com/callback",
                "state": "test_state",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
            },
        )

        # Should NOT redirect, should show an error page
        assert response.status_code == 400
        # The response should include an error message about invalid client_id
        assert "client" in response.text.lower()

    @pytest.mark.anyio
    async def test_authorize_missing_redirect_uri(
        self, test_client: httpx.AsyncClient, registered_client, pkce_challenge
    ):
        """Test authorization endpoint with missing redirect_uri.

        If client has only one registered redirect_uri, it can be omitted.
        """

        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                # Missing redirect_uri
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )

        # Should redirect to the registered redirect_uri
        assert response.status_code == 302, response.content
        redirect_url = response.headers["location"]
        assert redirect_url.startswith("https://client.example.com/callback")

    @pytest.mark.anyio
    async def test_authorize_invalid_redirect_uri(
        self, test_client: httpx.AsyncClient, registered_client, pkce_challenge
    ):
        """Test authorization endpoint with invalid redirect_uri.

        According to the OAuth2.0 spec, if redirect_uri is invalid or doesn't match,
        the server should inform the resource owner and NOT redirect.
        """

        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                # Non-matching URI
                "redirect_uri": "https://attacker.example.com/callback",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )

        # Should NOT redirect, should show an error page
        assert response.status_code == 400, response.content
        # The response should include an error message about redirect_uri mismatch
        assert "redirect" in response.text.lower()

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "registered_client",
        [
            {
                "redirect_uris": [
                    "https://client.example.com/callback",
                    "https://client.example.com/other-callback",
                ]
            }
        ],
        indirect=True,
    )
    async def test_authorize_missing_redirect_uri_multiple_registered(
        self, test_client: httpx.AsyncClient, registered_client, pkce_challenge
    ):
        """Test endpoint with missing redirect_uri with multiple registered URIs.

        If client has multiple registered redirect_uris, redirect_uri must be provided.
        """

        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                # Missing redirect_uri
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )

        # Should NOT redirect, should return a 400 error
        assert response.status_code == 400
        # The response should include an error message about missing redirect_uri
        assert "redirect_uri" in response.text.lower()

    @pytest.mark.anyio
    async def test_authorize_unsupported_response_type(
        self, test_client: httpx.AsyncClient, registered_client, pkce_challenge
    ):
        """Test authorization endpoint with unsupported response_type.

        According to the OAuth2.0 spec, for other errors like unsupported_response_type,
        the server should redirect with error parameters.
        """

        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "token",  # Unsupported (we only support "code")
                "client_id": registered_client["client_id"],
                "redirect_uri": "https://client.example.com/callback",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )

        # Should redirect with error parameters
        assert response.status_code == 302
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)

        assert "error" in query_params
        assert query_params["error"][0] == "unsupported_response_type"
        # State should be preserved
        assert "state" in query_params
        assert query_params["state"][0] == "test_state"

    @pytest.mark.anyio
    async def test_authorize_missing_response_type(
        self, test_client: httpx.AsyncClient, registered_client, pkce_challenge
    ):
        """Test authorization endpoint with missing response_type.

        Missing required parameter should result in invalid_request error.
        """

        response = await test_client.get(
            "/authorize",
            params={
                # Missing response_type
                "client_id": registered_client["client_id"],
                "redirect_uri": "https://client.example.com/callback",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )

        # Should redirect with error parameters
        assert response.status_code == 302
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)

        assert "error" in query_params
        assert query_params["error"][0] == "invalid_request"
        # State should be preserved
        assert "state" in query_params
        assert query_params["state"][0] == "test_state"

    @pytest.mark.anyio
    async def test_authorize_missing_pkce_challenge(self, test_client: httpx.AsyncClient, registered_client):
        """Test authorization endpoint with missing PKCE code_challenge.

        Missing PKCE parameters should result in invalid_request error.
        """
        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                # Missing code_challenge
                "state": "test_state",
                # using default URL
            },
        )

        # Should redirect with error parameters
        assert response.status_code == 302
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)

        assert "error" in query_params
        assert query_params["error"][0] == "invalid_request"
        # State should be preserved
        assert "state" in query_params
        assert query_params["state"][0] == "test_state"

    @pytest.mark.anyio
    async def test_authorize_invalid_scope(self, test_client: httpx.AsyncClient, registered_client, pkce_challenge):
        """Test authorization endpoint with invalid scope.

        Invalid scope should redirect with invalid_scope error.
        """

        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": "https://client.example.com/callback",
                "code_challenge": pkce_challenge["code_challenge"],
                "code_challenge_method": "S256",
                "scope": "invalid_scope_that_does_not_exist",
                "state": "test_state",
            },
        )

        # Should redirect with error parameters
        assert response.status_code == 302
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)

        assert "error" in query_params
        assert query_params["error"][0] == "invalid_scope"
        # State should be preserved
        assert "state" in query_params
        assert query_params["state"][0] == "test_state"

## TestRenderPrompt

**Type**: Class

**Description**: class TestRenderPrompt:
    @pytest.mark.anyio
    async def test_basic_fn(self):
        def fn() -> str:
            return "Hello, world!"

        prompt = Prompt.from_function(fn)
        assert await prompt.render() == [UserMessage(content=TextContent(type="text", text="Hello, world!"))]

    @pytest.mark.anyio
    async def test_async_fn(self):
        async def fn() -> str:
            return "Hello, world!"

        prompt = Prompt.from_function(fn)
        assert await prompt.render() == [UserMessage(content=TextContent(type="text", text="Hello, world!"))]

    @pytest.mark.anyio
    async def test_fn_with_args(self):
        async def fn(name: str, age: int = 30) -> str:
            return f"Hello, {name}! You're {age} years old."

        prompt = Prompt.from_function(fn)
        assert await prompt.render(arguments={"name": "World"}) == [
            UserMessage(content=TextContent(type="text", text="Hello, World! You're 30 years old."))
        ]

    @pytest.mark.anyio
    async def test_fn_with_invalid_kwargs(self):
        async def fn(name: str, age: int = 30) -> str:
            return f"Hello, {name}! You're {age} years old."

        prompt = Prompt.from_function(fn)
        with pytest.raises(ValueError):
            await prompt.render(arguments={"age": 40})

    @pytest.mark.anyio
    async def test_fn_returns_message(self):
        async def fn() -> UserMessage:
            return UserMessage(content="Hello, world!")

        prompt = Prompt.from_function(fn)
        assert await prompt.render() == [UserMessage(content=TextContent(type="text", text="Hello, world!"))]

    @pytest.mark.anyio
    async def test_fn_returns_assistant_message(self):
        async def fn() -> AssistantMessage:
            return AssistantMessage(content=TextContent(type="text", text="Hello, world!"))

        prompt = Prompt.from_function(fn)
        assert await prompt.render() == [AssistantMessage(content=TextContent(type="text", text="Hello, world!"))]

    @pytest.mark.anyio
    async def test_fn_returns_multiple_messages(self):
        expected = [
            UserMessage("Hello, world!"),
            AssistantMessage("How can I help you today?"),
            UserMessage("I'm looking for a restaurant in the center of town."),
        ]

        async def fn() -> list[Message]:
            return expected

        prompt = Prompt.from_function(fn)
        assert await prompt.render() == expected

    @pytest.mark.anyio
    async def test_fn_returns_list_of_strings(self):
        expected = [
            "Hello, world!",
            "I'm looking for a restaurant in the center of town.",
        ]

        async def fn() -> list[str]:
            return expected

        prompt = Prompt.from_function(fn)
        assert await prompt.render() == [UserMessage(t) for t in expected]

    @pytest.mark.anyio
    async def test_fn_returns_resource_content(self):
        """Test returning a message with resource content."""

        async def fn() -> UserMessage:
            return UserMessage(
                content=EmbeddedResource(
                    type="resource",
                    resource=TextResourceContents(
                        uri=FileUrl("file://file.txt"),
                        text="File contents",
                        mimeType="text/plain",
                    ),
                )
            )

        prompt = Prompt.from_function(fn)
        assert await prompt.render() == [
            UserMessage(
                content=EmbeddedResource(
                    type="resource",
                    resource=TextResourceContents(
                        uri=FileUrl("file://file.txt"),
                        text="File contents",
                        mimeType="text/plain",
                    ),
                )
            )
        ]

    @pytest.mark.anyio
    async def test_fn_returns_mixed_content(self):
        """Test returning messages with mixed content types."""

        async def fn() -> list[Message]:
            return [
                UserMessage(content="Please analyze this file:"),
                UserMessage(
                    content=EmbeddedResource(
                        type="resource",
                        resource=TextResourceContents(
                            uri=FileUrl("file://file.txt"),
                            text="File contents",
                            mimeType="text/plain",
                        ),
                    )
                ),
                AssistantMessage(content="I'll help analyze that file."),
            ]

        prompt = Prompt.from_function(fn)
        assert await prompt.render() == [
            UserMessage(content=TextContent(type="text", text="Please analyze this file:")),
            UserMessage(
                content=EmbeddedResource(
                    type="resource",
                    resource=TextResourceContents(
                        uri=FileUrl("file://file.txt"),
                        text="File contents",
                        mimeType="text/plain",
                    ),
                )
            ),
            AssistantMessage(content=TextContent(type="text", text="I'll help analyze that file.")),
        ]

    @pytest.mark.anyio
    async def test_fn_returns_dict_with_resource(self):
        """Test returning a dict with resource content."""

        async def fn() -> dict:
            return {
                "role": "user",
                "content": {
                    "type": "resource",
                    "resource": {
                        "uri": FileUrl("file://file.txt"),
                        "text": "File contents",
                        "mimeType": "text/plain",
                    },
                },
            }

        prompt = Prompt.from_function(fn)
        assert await prompt.render() == [
            UserMessage(
                content=EmbeddedResource(
                    type="resource",
                    resource=TextResourceContents(
                        uri=FileUrl("file://file.txt"),
                        text="File contents",
                        mimeType="text/plain",
                    ),
                )
            )
        ]

## TestPromptManager

**Type**: Class

**Description**: class TestPromptManager:
    def test_add_prompt(self):
        """Test adding a prompt to the manager."""

        def fn() -> str:
            return "Hello, world!"

        manager = PromptManager()
        prompt = Prompt.from_function(fn)
        added = manager.add_prompt(prompt)
        assert added == prompt
        assert manager.get_prompt("fn") == prompt

    def test_add_duplicate_prompt(self, caplog):
        """Test adding the same prompt twice."""

        def fn() -> str:
            return "Hello, world!"

        manager = PromptManager()
        prompt = Prompt.from_function(fn)
        first = manager.add_prompt(prompt)
        second = manager.add_prompt(prompt)
        assert first == second
        assert "Prompt already exists" in caplog.text

    def test_disable_warn_on_duplicate_prompts(self, caplog):
        """Test disabling warning on duplicate prompts."""

        def fn() -> str:
            return "Hello, world!"

        manager = PromptManager(warn_on_duplicate_prompts=False)
        prompt = Prompt.from_function(fn)
        first = manager.add_prompt(prompt)
        second = manager.add_prompt(prompt)
        assert first == second
        assert "Prompt already exists" not in caplog.text

    def test_list_prompts(self):
        """Test listing all prompts."""

        def fn1() -> str:
            return "Hello, world!"

        def fn2() -> str:
            return "Goodbye, world!"

        manager = PromptManager()
        prompt1 = Prompt.from_function(fn1)
        prompt2 = Prompt.from_function(fn2)
        manager.add_prompt(prompt1)
        manager.add_prompt(prompt2)
        prompts = manager.list_prompts()
        assert len(prompts) == 2
        assert prompts == [prompt1, prompt2]

    @pytest.mark.anyio
    async def test_render_prompt(self):
        """Test rendering a prompt."""

        def fn() -> str:
            return "Hello, world!"

        manager = PromptManager()
        prompt = Prompt.from_function(fn)
        manager.add_prompt(prompt)
        messages = await manager.render_prompt("fn")
        assert messages == [UserMessage(content=TextContent(type="text", text="Hello, world!"))]

    @pytest.mark.anyio
    async def test_render_prompt_with_args(self):
        """Test rendering a prompt with arguments."""

        def fn(name: str) -> str:
            return f"Hello, {name}!"

        manager = PromptManager()
        prompt = Prompt.from_function(fn)
        manager.add_prompt(prompt)
        messages = await manager.render_prompt("fn", arguments={"name": "World"})
        assert messages == [UserMessage(content=TextContent(type="text", text="Hello, World!"))]

    @pytest.mark.anyio
    async def test_render_unknown_prompt(self):
        """Test rendering a non-existent prompt."""
        manager = PromptManager()
        with pytest.raises(ValueError, match="Unknown prompt: unknown"):
            await manager.render_prompt("unknown")

    @pytest.mark.anyio
    async def test_render_prompt_with_missing_args(self):
        """Test rendering a prompt with missing required arguments."""

        def fn(name: str) -> str:
            return f"Hello, {name}!"

        manager = PromptManager()
        prompt = Prompt.from_function(fn)
        manager.add_prompt(prompt)
        with pytest.raises(ValueError, match="Missing required arguments"):
            await manager.render_prompt("fn")

## TestFileResource

**Type**: Class

**Description**: class TestFileResource:
    """Test FileResource functionality."""

    def test_file_resource_creation(self, temp_file: Path):
        """Test creating a FileResource."""
        resource = FileResource(
            uri=FileUrl(temp_file.as_uri()),
            name="test",
            description="test file",
            path=temp_file,
        )
        assert str(resource.uri) == temp_file.as_uri()
        assert resource.name == "test"
        assert resource.description == "test file"
        assert resource.mime_type == "text/plain"  # default
        assert resource.path == temp_file
        assert resource.is_binary is False  # default

    def test_file_resource_str_path_conversion(self, temp_file: Path):
        """Test FileResource handles string paths."""
        resource = FileResource(
            uri=FileUrl(f"file://{temp_file}"),
            name="test",
            path=Path(str(temp_file)),
        )
        assert isinstance(resource.path, Path)
        assert resource.path.is_absolute()

    @pytest.mark.anyio
    async def test_read_text_file(self, temp_file: Path):
        """Test reading a text file."""
        resource = FileResource(
            uri=FileUrl(f"file://{temp_file}"),
            name="test",
            path=temp_file,
        )
        content = await resource.read()
        assert content == "test content"
        assert resource.mime_type == "text/plain"

    @pytest.mark.anyio
    async def test_read_binary_file(self, temp_file: Path):
        """Test reading a file as binary."""
        resource = FileResource(
            uri=FileUrl(f"file://{temp_file}"),
            name="test",
            path=temp_file,
            is_binary=True,
        )
        content = await resource.read()
        assert isinstance(content, bytes)
        assert content == b"test content"

    def test_relative_path_error(self):
        """Test error on relative path."""
        with pytest.raises(ValueError, match="Path must be absolute"):
            FileResource(
                uri=FileUrl("file:///test.txt"),
                name="test",
                path=Path("test.txt"),
            )

    @pytest.mark.anyio
    async def test_missing_file_error(self, temp_file: Path):
        """Test error when file doesn't exist."""
        # Create path to non-existent file
        missing = temp_file.parent / "missing.txt"
        resource = FileResource(
            uri=FileUrl("file:///missing.txt"),
            name="test",
            path=missing,
        )
        with pytest.raises(ValueError, match="Error reading file"):
            await resource.read()

    @pytest.mark.skipif(os.name == "nt", reason="File permissions behave differently on Windows")
    @pytest.mark.anyio
    async def test_permission_error(self, temp_file: Path):
        """Test reading a file without permissions."""
        temp_file.chmod(0o000)  # Remove all permissions
        try:
            resource = FileResource(
                uri=FileUrl(temp_file.as_uri()),
                name="test",
                path=temp_file,
            )
            with pytest.raises(ValueError, match="Error reading file"):
                await resource.read()
        finally:
            temp_file.chmod(0o644)  # Restore permissions

## TestFunctionResource

**Type**: Class

**Description**: class TestFunctionResource:
    """Test FunctionResource functionality."""

    def test_function_resource_creation(self):
        """Test creating a FunctionResource."""

        def my_func() -> str:
            return "test content"

        resource = FunctionResource(
            uri=AnyUrl("fn://test"),
            name="test",
            description="test function",
            fn=my_func,
        )
        assert str(resource.uri) == "fn://test"
        assert resource.name == "test"
        assert resource.description == "test function"
        assert resource.mime_type == "text/plain"  # default
        assert resource.fn == my_func

    @pytest.mark.anyio
    async def test_read_text(self):
        """Test reading text from a FunctionResource."""

        def get_data() -> str:
            return "Hello, world!"

        resource = FunctionResource(
            uri=AnyUrl("function://test"),
            name="test",
            fn=get_data,
        )
        content = await resource.read()
        assert content == "Hello, world!"
        assert resource.mime_type == "text/plain"

    @pytest.mark.anyio
    async def test_read_binary(self):
        """Test reading binary data from a FunctionResource."""

        def get_data() -> bytes:
            return b"Hello, world!"

        resource = FunctionResource(
            uri=AnyUrl("function://test"),
            name="test",
            fn=get_data,
        )
        content = await resource.read()
        assert content == b"Hello, world!"

    @pytest.mark.anyio
    async def test_json_conversion(self):
        """Test automatic JSON conversion of non-string results."""

        def get_data() -> dict:
            return {"key": "value"}

        resource = FunctionResource(
            uri=AnyUrl("function://test"),
            name="test",
            fn=get_data,
        )
        content = await resource.read()
        assert isinstance(content, str)
        assert '"key": "value"' in content

    @pytest.mark.anyio
    async def test_error_handling(self):
        """Test error handling in FunctionResource."""

        def failing_func() -> str:
            raise ValueError("Test error")

        resource = FunctionResource(
            uri=AnyUrl("function://test"),
            name="test",
            fn=failing_func,
        )
        with pytest.raises(ValueError, match="Error reading resource function://test"):
            await resource.read()

    @pytest.mark.anyio
    async def test_basemodel_conversion(self):
        """Test handling of BaseModel types."""

        class MyModel(BaseModel):
            name: str

        resource = FunctionResource(
            uri=AnyUrl("function://test"),
            name="test",
            fn=lambda: MyModel(name="test"),
        )
        content = await resource.read()
        assert content == '{\n  "name": "test"\n}'

    @pytest.mark.anyio
    async def test_custom_type_conversion(self):
        """Test handling of custom types."""

        class CustomData:
            def __str__(self) -> str:
                return "custom data"

        def get_data() -> CustomData:
            return CustomData()

        resource = FunctionResource(
            uri=AnyUrl("function://test"),
            name="test",
            fn=get_data,
        )
        content = await resource.read()
        assert isinstance(content, str)

    @pytest.mark.anyio
    async def test_async_read_text(self):
        """Test reading text from async FunctionResource."""

        async def get_data() -> str:
            return "Hello, world!"

        resource = FunctionResource(
            uri=AnyUrl("function://test"),
            name="test",
            fn=get_data,
        )
        content = await resource.read()
        assert content == "Hello, world!"
        assert resource.mime_type == "text/plain"

    @pytest.mark.anyio
    async def test_from_function(self):
        """Test creating a FunctionResource from a function."""

        async def get_data() -> str:
            """get_data returns a string"""
            return "Hello, world!"

        resource = FunctionResource.from_function(
            fn=get_data,
            uri="function://test",
            name="test",
        )

        assert resource.description == "get_data returns a string"
        assert resource.mime_type == "text/plain"
        assert resource.name == "test"
        assert resource.uri == AnyUrl("function://test")

## TestResourceValidation

**Type**: Class

**Description**: class TestResourceValidation:
    """Test base Resource validation."""

    def test_resource_uri_validation(self):
        """Test URI validation."""

        def dummy_func() -> str:
            return "data"

        # Valid URI
        resource = FunctionResource(
            uri=AnyUrl("http://example.com/data"),
            name="test",
            fn=dummy_func,
        )
        assert str(resource.uri) == "http://example.com/data"

        # Missing protocol
        with pytest.raises(ValueError, match="Input should be a valid URL"):
            FunctionResource(
                uri=AnyUrl("invalid"),
                name="test",
                fn=dummy_func,
            )

        # Missing host
        with pytest.raises(ValueError, match="Input should be a valid URL"):
            FunctionResource(
                uri=AnyUrl("http://"),
                name="test",
                fn=dummy_func,
            )

    def test_resource_name_from_uri(self):
        """Test name is extracted from URI if not provided."""

        def dummy_func() -> str:
            return "data"

        resource = FunctionResource(
            uri=AnyUrl("resource://my-resource"),
            fn=dummy_func,
        )
        assert resource.name == "resource://my-resource"

    def test_resource_name_validation(self):
        """Test name validation."""

        def dummy_func() -> str:
            return "data"

        # Must provide either name or URI
        with pytest.raises(ValueError, match="Either name or uri must be provided"):
            FunctionResource(
                fn=dummy_func,
            )

        # Explicit name takes precedence over URI
        resource = FunctionResource(
            uri=AnyUrl("resource://uri-name"),
            name="explicit-name",
            fn=dummy_func,
        )
        assert resource.name == "explicit-name"

    def test_resource_mime_type(self):
        """Test mime type handling."""

        def dummy_func() -> str:
            return "data"

        # Default mime type
        resource = FunctionResource(
            uri=AnyUrl("resource://test"),
            fn=dummy_func,
        )
        assert resource.mime_type == "text/plain"

        # Custom mime type
        resource = FunctionResource(
            uri=AnyUrl("resource://test"),
            fn=dummy_func,
            mime_type="application/json",
        )
        assert resource.mime_type == "application/json"

    @pytest.mark.anyio
    async def test_resource_read_abstract(self):
        """Test that Resource.read() is abstract."""

        class ConcreteResource(Resource):
            pass

        with pytest.raises(TypeError, match="abstract method"):
            ConcreteResource(uri=AnyUrl("test://test"), name="test")  # type: ignore

## TestResourceManager

**Type**: Class

**Description**: class TestResourceManager:
    """Test ResourceManager functionality."""

    def test_add_resource(self, temp_file: Path):
        """Test adding a resource."""
        manager = ResourceManager()
        resource = FileResource(
            uri=FileUrl(f"file://{temp_file}"),
            name="test",
            path=temp_file,
        )
        added = manager.add_resource(resource)
        assert added == resource
        assert manager.list_resources() == [resource]

    def test_add_duplicate_resource(self, temp_file: Path):
        """Test adding the same resource twice."""
        manager = ResourceManager()
        resource = FileResource(
            uri=FileUrl(f"file://{temp_file}"),
            name="test",
            path=temp_file,
        )
        first = manager.add_resource(resource)
        second = manager.add_resource(resource)
        assert first == second
        assert manager.list_resources() == [resource]

    def test_warn_on_duplicate_resources(self, temp_file: Path, caplog):
        """Test warning on duplicate resources."""
        manager = ResourceManager()
        resource = FileResource(
            uri=FileUrl(f"file://{temp_file}"),
            name="test",
            path=temp_file,
        )
        manager.add_resource(resource)
        manager.add_resource(resource)
        assert "Resource already exists" in caplog.text

    def test_disable_warn_on_duplicate_resources(self, temp_file: Path, caplog):
        """Test disabling warning on duplicate resources."""
        manager = ResourceManager(warn_on_duplicate_resources=False)
        resource = FileResource(
            uri=FileUrl(f"file://{temp_file}"),
            name="test",
            path=temp_file,
        )
        manager.add_resource(resource)
        manager.add_resource(resource)
        assert "Resource already exists" not in caplog.text

    @pytest.mark.anyio
    async def test_get_resource(self, temp_file: Path):
        """Test getting a resource by URI."""
        manager = ResourceManager()
        resource = FileResource(
            uri=FileUrl(f"file://{temp_file}"),
            name="test",
            path=temp_file,
        )
        manager.add_resource(resource)
        retrieved = await manager.get_resource(resource.uri)
        assert retrieved == resource

    @pytest.mark.anyio
    async def test_get_resource_from_template(self):
        """Test getting a resource through a template."""
        manager = ResourceManager()

        def greet(name: str) -> str:
            return f"Hello, {name}!"

        template = ResourceTemplate.from_function(
            fn=greet,
            uri_template="greet://{name}",
            name="greeter",
        )
        manager._templates[template.uri_template] = template

        resource = await manager.get_resource(AnyUrl("greet://world"))
        assert isinstance(resource, FunctionResource)
        content = await resource.read()
        assert content == "Hello, world!"

    @pytest.mark.anyio
    async def test_get_unknown_resource(self):
        """Test getting a non-existent resource."""
        manager = ResourceManager()
        with pytest.raises(ValueError, match="Unknown resource"):
            await manager.get_resource(AnyUrl("unknown://test"))

    def test_list_resources(self, temp_file: Path):
        """Test listing all resources."""
        manager = ResourceManager()
        resource1 = FileResource(
            uri=FileUrl(f"file://{temp_file}"),
            name="test1",
            path=temp_file,
        )
        resource2 = FileResource(
            uri=FileUrl(f"file://{temp_file}2"),
            name="test2",
            path=temp_file,
        )
        manager.add_resource(resource1)
        manager.add_resource(resource2)
        resources = manager.list_resources()
        assert len(resources) == 2
        assert resources == [resource1, resource2]

## TestResourceTemplate

**Type**: Class

**Description**: class TestResourceTemplate:
    """Test ResourceTemplate functionality."""

    def test_template_creation(self):
        """Test creating a template from a function."""

        def my_func(key: str, value: int) -> dict:
            return {"key": key, "value": value}

        template = ResourceTemplate.from_function(
            fn=my_func,
            uri_template="test://{key}/{value}",
            name="test",
        )
        assert template.uri_template == "test://{key}/{value}"
        assert template.name == "test"
        assert template.mime_type == "text/plain"  # default
        test_input = {"key": "test", "value": 42}
        assert template.fn(**test_input) == my_func(**test_input)

    def test_template_matches(self):
        """Test matching URIs against a template."""

        def my_func(key: str, value: int) -> dict:
            return {"key": key, "value": value}

        template = ResourceTemplate.from_function(
            fn=my_func,
            uri_template="test://{key}/{value}",
            name="test",
        )

        # Valid match
        params = template.matches("test://foo/123")
        assert params == {"key": "foo", "value": "123"}

        # No match
        assert template.matches("test://foo") is None
        assert template.matches("other://foo/123") is None

    @pytest.mark.anyio
    async def test_create_resource(self):
        """Test creating a resource from a template."""

        def my_func(key: str, value: int) -> dict:
            return {"key": key, "value": value}

        template = ResourceTemplate.from_function(
            fn=my_func,
            uri_template="test://{key}/{value}",
            name="test",
        )

        resource = await template.create_resource(
            "test://foo/123",
            {"key": "foo", "value": 123},
        )

        assert isinstance(resource, FunctionResource)
        content = await resource.read()
        assert isinstance(content, str)
        data = json.loads(content)
        assert data == {"key": "foo", "value": 123}

    @pytest.mark.anyio
    async def test_template_error(self):
        """Test error handling in template resource creation."""

        def failing_func(x: str) -> str:
            raise ValueError("Test error")

        template = ResourceTemplate.from_function(
            fn=failing_func,
            uri_template="fail://{x}",
            name="fail",
        )

        with pytest.raises(ValueError, match="Error creating resource from template"):
            await template.create_resource("fail://test", {"x": "test"})

    @pytest.mark.anyio
    async def test_async_text_resource(self):
        """Test creating a text resource from async function."""

        async def greet(name: str) -> str:
            return f"Hello, {name}!"

        template = ResourceTemplate.from_function(
            fn=greet,
            uri_template="greet://{name}",
            name="greeter",
        )

        resource = await template.create_resource(
            "greet://world",
            {"name": "world"},
        )

        assert isinstance(resource, FunctionResource)
        content = await resource.read()
        assert content == "Hello, world!"

    @pytest.mark.anyio
    async def test_async_binary_resource(self):
        """Test creating a binary resource from async function."""

        async def get_bytes(value: str) -> bytes:
            return value.encode()

        template = ResourceTemplate.from_function(
            fn=get_bytes,
            uri_template="bytes://{value}",
            name="bytes",
        )

        resource = await template.create_resource(
            "bytes://test",
            {"value": "test"},
        )

        assert isinstance(resource, FunctionResource)
        content = await resource.read()
        assert content == b"test"

    @pytest.mark.anyio
    async def test_basemodel_conversion(self):
        """Test handling of BaseModel types."""

        class MyModel(BaseModel):
            key: str
            value: int

        def get_data(key: str, value: int) -> MyModel:
            return MyModel(key=key, value=value)

        template = ResourceTemplate.from_function(
            fn=get_data,
            uri_template="test://{key}/{value}",
            name="test",
        )

        resource = await template.create_resource(
            "test://foo/123",
            {"key": "foo", "value": 123},
        )

        assert isinstance(resource, FunctionResource)
        content = await resource.read()
        assert isinstance(content, str)
        data = json.loads(content)
        assert data == {"key": "foo", "value": 123}

    @pytest.mark.anyio
    async def test_custom_type_conversion(self):
        """Test handling of custom types."""

        class CustomData:
            def __init__(self, value: str):
                self.value = value

            def __str__(self) -> str:
                return self.value

        def get_data(value: str) -> CustomData:
            return CustomData(value)

        template = ResourceTemplate.from_function(
            fn=get_data,
            uri_template="test://{value}",
            name="test",
        )

        resource = await template.create_resource(
            "test://hello",
            {"value": "hello"},
        )

        assert isinstance(resource, FunctionResource)
        content = await resource.read()
        assert content == '"hello"'

## TestResourceUrlFromServerUrl

**Type**: Class

**Description**: class TestResourceUrlFromServerUrl:
    """Tests for resource_url_from_server_url function."""

    def test_removes_fragment(self):
        """Fragment should be removed per RFC 8707."""
        assert resource_url_from_server_url("https://example.com/path#fragment") == "https://example.com/path"
        assert resource_url_from_server_url("https://example.com/#fragment") == "https://example.com/"

    def test_preserves_path(self):
        """Path should be preserved."""
        assert (
            resource_url_from_server_url("https://example.com/path/to/resource")
            == "https://example.com/path/to/resource"
        )
        assert resource_url_from_server_url("https://example.com/") == "https://example.com/"
        assert resource_url_from_server_url("https://example.com") == "https://example.com"

    def test_preserves_query(self):
        """Query parameters should be preserved."""
        assert resource_url_from_server_url("https://example.com/path?foo=bar") == "https://example.com/path?foo=bar"
        assert resource_url_from_server_url("https://example.com/?key=value") == "https://example.com/?key=value"

    def test_preserves_port(self):
        """Non-default ports should be preserved."""
        assert resource_url_from_server_url("https://example.com:8443/path") == "https://example.com:8443/path"
        assert resource_url_from_server_url("http://example.com:8080/") == "http://example.com:8080/"

    def test_lowercase_scheme_and_host(self):
        """Scheme and host should be lowercase for canonical form."""
        assert resource_url_from_server_url("HTTPS://EXAMPLE.COM/path") == "https://example.com/path"
        assert resource_url_from_server_url("Http://Example.Com:8080/") == "http://example.com:8080/"

    def test_handles_pydantic_urls(self):
        """Should handle Pydantic URL types."""
        from pydantic import HttpUrl

        url = HttpUrl("https://example.com/path")
        assert resource_url_from_server_url(url) == "https://example.com/path"

## TestCheckResourceAllowed

**Type**: Class

**Description**: class TestCheckResourceAllowed:
    """Tests for check_resource_allowed function."""

    def test_identical_urls(self):
        """Identical URLs should match."""
        assert check_resource_allowed("https://example.com/path", "https://example.com/path") is True
        assert check_resource_allowed("https://example.com/", "https://example.com/") is True
        assert check_resource_allowed("https://example.com", "https://example.com") is True

    def test_different_schemes(self):
        """Different schemes should not match."""
        assert check_resource_allowed("https://example.com/path", "http://example.com/path") is False
        assert check_resource_allowed("http://example.com/", "https://example.com/") is False

    def test_different_domains(self):
        """Different domains should not match."""
        assert check_resource_allowed("https://example.com/path", "https://example.org/path") is False
        assert check_resource_allowed("https://sub.example.com/", "https://example.com/") is False

    def test_different_ports(self):
        """Different ports should not match."""
        assert check_resource_allowed("https://example.com:8443/path", "https://example.com/path") is False
        assert check_resource_allowed("https://example.com:8080/", "https://example.com:8443/") is False

    def test_hierarchical_matching(self):
        """Child paths should match parent paths."""
        # Parent resource allows child resources
        assert check_resource_allowed("https://example.com/api/v1/users", "https://example.com/api") is True
        assert check_resource_allowed("https://example.com/api/v1", "https://example.com/api") is True
        assert check_resource_allowed("https://example.com/mcp/server", "https://example.com/mcp") is True

        # Exact match
        assert check_resource_allowed("https://example.com/api", "https://example.com/api") is True

        # Parent cannot use child's token
        assert check_resource_allowed("https://example.com/api", "https://example.com/api/v1") is False
        assert check_resource_allowed("https://example.com/", "https://example.com/api") is False

    def test_path_boundary_matching(self):
        """Path matching should respect boundaries."""
        # Should not match partial path segments
        assert check_resource_allowed("https://example.com/apiextra", "https://example.com/api") is False
        assert check_resource_allowed("https://example.com/api123", "https://example.com/api") is False

        # Should match with trailing slash
        assert check_resource_allowed("https://example.com/api/", "https://example.com/api") is True
        assert check_resource_allowed("https://example.com/api/v1", "https://example.com/api/") is True

    def test_trailing_slash_handling(self):
        """Trailing slashes should be handled correctly."""
        # With and without trailing slashes
        assert check_resource_allowed("https://example.com/api/", "https://example.com/api") is True
        assert check_resource_allowed("https://example.com/api", "https://example.com/api/") is False
        assert check_resource_allowed("https://example.com/api/v1", "https://example.com/api") is True
        assert check_resource_allowed("https://example.com/api/v1", "https://example.com/api/") is True

    def test_case_insensitive_origin(self):
        """Origin comparison should be case-insensitive."""
        assert check_resource_allowed("https://EXAMPLE.COM/path", "https://example.com/path") is True
        assert check_resource_allowed("HTTPS://example.com/path", "https://example.com/path") is True
        assert check_resource_allowed("https://Example.Com:8080/api", "https://example.com:8080/api") is True

    def test_empty_paths(self):
        """Empty paths should be handled correctly."""
        assert check_resource_allowed("https://example.com", "https://example.com") is True
        assert check_resource_allowed("https://example.com/", "https://example.com") is True
        assert check_resource_allowed("https://example.com/api", "https://example.com") is True

## test_default_settings

**Type**: Function

**Description**: def test_default_settings():
    """Test that default settings are applied correctly."""
    client = create_mcp_http_client()

    assert client.follow_redirects is True
    assert client.timeout.connect == 30.0

## test_custom_parameters

**Type**: Function

**Description**: def test_custom_parameters():
    """Test custom headers and timeout are set correctly."""
    headers = {"Authorization": "Bearer token"}
    timeout = httpx.Timeout(60.0)

    client = create_mcp_http_client(headers, timeout)

    assert client.headers["Authorization"] == "Bearer token"
    assert client.timeout.connect == 60.0

## ServerTest

**Type**: Class

**Description**: class ServerTest(Server):
    def __init__(self):
        super().__init__(SERVER_NAME)

        @self.read_resource()
        async def handle_read_resource(uri: AnyUrl) -> str | bytes:
            if uri.scheme == "foobar":
                return f"Read {uri.host}"
            elif uri.scheme == "slow":
                # Simulate a slow resource
                await anyio.sleep(2.0)
                return f"Slow response from {uri.host}"

            raise McpError(error=ErrorData(code=404, message="OOPS! no resource with that URI was found"))

        @self.list_tools()
        async def handle_list_tools() -> list[Tool]:
            return [
                Tool(
                    name="test_tool",
                    description="A test tool",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]

        @self.call_tool()
        async def handle_call_tool(name: str, args: dict) -> list[TextContent]:
            return [TextContent(type="text", text=f"Called {name}")]

## make_server_app

**Type**: Function

**Description**: def make_server_app() -> Starlette:
    """Create test Starlette app with SSE transport"""
    # Configure security with allowed hosts/origins for testing
    security_settings = TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*"], allowed_origins=["http://127.0.0.1:*", "http://localhost:*"]
    )
    sse = SseServerTransport("/messages/", security_settings=security_settings)
    server = ServerTest()

    async def handle_sse(request: Request) -> Response:
        async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
            await server.run(streams[0], streams[1], server.create_initialization_options())
        return Response()

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ]
    )

    return app

## run_server

**Type**: Function

**Description**: def run_server(server_port: int) -> None:
    app = make_server_app()
    server = uvicorn.Server(config=uvicorn.Config(app=app, host="127.0.0.1", port=server_port, log_level="error"))
    print(f"starting server on {server_port}")
    server.run()

    # Give server time to start
    while not server.started:
        print("waiting for server to start")
        time.sleep(0.5)

## run_mounted_server

**Type**: Function

**Description**: def run_mounted_server(server_port: int) -> None:
    app = make_server_app()
    main_app = Starlette(routes=[Mount("/mounted_app", app=app)])
    server = uvicorn.Server(config=uvicorn.Config(app=main_app, host="127.0.0.1", port=server_port, log_level="error"))
    print(f"starting server on {server_port}")
    server.run()

    # Give server time to start
    while not server.started:
        print("waiting for server to start")
        time.sleep(0.5)

## RequestContextServer

**Type**: Class

**Description**: class RequestContextServer(Server[object, Request]):
    def __init__(self):
        super().__init__("request_context_server")

        @self.call_tool()
        async def handle_call_tool(name: str, args: dict) -> list[TextContent]:
            headers_info = {}
            context = self.request_context
            if context.request:
                headers_info = dict(context.request.headers)

            if name == "echo_headers":
                return [TextContent(type="text", text=json.dumps(headers_info))]
            elif name == "echo_context":
                context_data = {
                    "request_id": args.get("request_id"),
                    "headers": headers_info,
                }
                return [TextContent(type="text", text=json.dumps(context_data))]

            return [TextContent(type="text", text=f"Called {name}")]

        @self.list_tools()
        async def handle_list_tools() -> list[Tool]:
            return [
                Tool(
                    name="echo_headers",
                    description="Echoes request headers",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="echo_context",
                    description="Echoes request context",
                    inputSchema={
                        "type": "object",
                        "properties": {"request_id": {"type": "string"}},
                        "required": ["request_id"],
                    },
                ),
            ]

## run_context_server

**Type**: Function

**Description**: def run_context_server(server_port: int) -> None:
    """Run a server that captures request context"""
    # Configure security with allowed hosts/origins for testing
    security_settings = TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*"], allowed_origins=["http://127.0.0.1:*", "http://localhost:*"]
    )
    sse = SseServerTransport("/messages/", security_settings=security_settings)
    context_server = RequestContextServer()

    async def handle_sse(request: Request) -> Response:
        async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
            await context_server.run(streams[0], streams[1], context_server.create_initialization_options())
        return Response()

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ]
    )

    server = uvicorn.Server(config=uvicorn.Config(app=app, host="127.0.0.1", port=server_port, log_level="error"))
    print(f"starting context server on {server_port}")
    server.run()

## test_sse_message_id_coercion

**Type**: Function

**Description**: def test_sse_message_id_coercion():
    """Test that string message IDs that look like integers are parsed as integers.

    See <https://github.com/modelcontextprotocol/python-sdk/pull/851> for more details.
    """
    json_message = '{"jsonrpc": "2.0", "id": "123", "method": "ping", "params": null}'
    msg = types.JSONRPCMessage.model_validate_json(json_message)
    assert msg == snapshot(types.JSONRPCMessage(root=types.JSONRPCRequest(method="ping", jsonrpc="2.0", id=123)))

## extract_protocol_version_from_sse

**Type**: Function

**Description**: def extract_protocol_version_from_sse(response: requests.Response) -> str:
    """Extract the negotiated protocol version from an SSE initialization response."""
    assert response.headers.get("Content-Type") == "text/event-stream"
    for line in response.text.splitlines():
        if line.startswith("data: "):
            init_data = json.loads(line[6:])
            return init_data["result"]["protocolVersion"]
    raise ValueError("Could not extract protocol version from SSE response")

## SimpleEventStore

**Type**: Class

**Description**: class SimpleEventStore(EventStore):
    """Simple in-memory event store for testing."""

    def __init__(self):
        self._events: list[tuple[StreamId, EventId, types.JSONRPCMessage]] = []
        self._event_id_counter = 0

    async def store_event(self, stream_id: StreamId, message: types.JSONRPCMessage) -> EventId:
        """Store an event and return its ID."""
        self._event_id_counter += 1
        event_id = str(self._event_id_counter)
        self._events.append((stream_id, event_id, message))
        return event_id

    async def replay_events_after(
        self,
        last_event_id: EventId,
        send_callback: EventCallback,
    ) -> StreamId | None:
        """Replay events after the specified ID."""
        # Find the index of the last event ID
        start_index = None
        for i, (_, event_id, _) in enumerate(self._events):
            if event_id == last_event_id:
                start_index = i + 1
                break

        if start_index is None:
            # If event ID not found, start from beginning
            start_index = 0

        stream_id = None
        # Replay events
        for _, event_id, message in self._events[start_index:]:
            await send_callback(EventMessage(message, event_id))
            # Capture the stream ID from the first replayed event
            if stream_id is None and len(self._events) > start_index:
                stream_id = self._events[start_index][0]

        return stream_id

## ServerTest

**Type**: Class

**Description**: class ServerTest(Server):
    def __init__(self):
        super().__init__(SERVER_NAME)

        @self.read_resource()
        async def handle_read_resource(uri: AnyUrl) -> str | bytes:
            if uri.scheme == "foobar":
                return f"Read {uri.host}"
            elif uri.scheme == "slow":
                # Simulate a slow resource
                await anyio.sleep(2.0)
                return f"Slow response from {uri.host}"

            raise ValueError(f"Unknown resource: {uri}")

        @self.list_tools()
        async def handle_list_tools() -> list[Tool]:
            return [
                Tool(
                    name="test_tool",
                    description="A test tool",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="test_tool_with_standalone_notification",
                    description="A test tool that sends a notification",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="long_running_with_checkpoints",
                    description="A long-running tool that sends periodic notifications",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="test_sampling_tool",
                    description="A tool that triggers server-side sampling",
                    inputSchema={"type": "object", "properties": {}},
                ),
            ]

        @self.call_tool()
        async def handle_call_tool(name: str, args: dict) -> list[TextContent]:
            ctx = self.request_context

            # When the tool is called, send a notification to test GET stream
            if name == "test_tool_with_standalone_notification":
                await ctx.session.send_resource_updated(uri=AnyUrl("http://test_resource"))
                return [TextContent(type="text", text=f"Called {name}")]

            elif name == "long_running_with_checkpoints":
                # Send notifications that are part of the response stream
                # This simulates a long-running tool that sends logs

                await ctx.session.send_log_message(
                    level="info",
                    data="Tool started",
                    logger="tool",
                    related_request_id=ctx.request_id,  # need for stream association
                )

                await anyio.sleep(0.1)

                await ctx.session.send_log_message(
                    level="info",
                    data="Tool is almost done",
                    logger="tool",
                    related_request_id=ctx.request_id,
                )

                return [TextContent(type="text", text="Completed!")]

            elif name == "test_sampling_tool":
                # Test sampling by requesting the client to sample a message
                sampling_result = await ctx.session.create_message(
                    messages=[
                        types.SamplingMessage(
                            role="user",
                            content=types.TextContent(type="text", text="Server needs client sampling"),
                        )
                    ],
                    max_tokens=100,
                    related_request_id=ctx.request_id,
                )

                # Return the sampling result in the tool response
                response = sampling_result.content.text if sampling_result.content.type == "text" else None
                return [
                    TextContent(
                        type="text",
                        text=f"Response from sampling: {response}",
                    )
                ]

            return [TextContent(type="text", text=f"Called {name}")]

## create_app

**Type**: Function

**Description**: def create_app(is_json_response_enabled=False, event_store: EventStore | None = None) -> Starlette:
    """Create a Starlette application for testing using the session manager.

    Args:
        is_json_response_enabled: If True, use JSON responses instead of SSE streams.
        event_store: Optional event store for testing resumability.
    """
    # Create server instance
    server = ServerTest()

    # Create the session manager
    security_settings = TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*"], allowed_origins=["http://127.0.0.1:*", "http://localhost:*"]
    )
    session_manager = StreamableHTTPSessionManager(
        app=server,
        event_store=event_store,
        json_response=is_json_response_enabled,
        security_settings=security_settings,
    )

    # Create an ASGI application that uses the session manager
    app = Starlette(
        debug=True,
        routes=[
            Mount("/mcp", app=session_manager.handle_request),
        ],
        lifespan=lambda app: session_manager.run(),
    )

    return app

## run_server

**Type**: Function

**Description**: def run_server(port: int, is_json_response_enabled=False, event_store: EventStore | None = None) -> None:
    """Run the test server.

    Args:
        port: Port to listen on.
        is_json_response_enabled: If True, use JSON responses instead of SSE streams.
        event_store: Optional event store for testing resumability.
    """

    app = create_app(is_json_response_enabled, event_store)
    # Configure server
    config = uvicorn.Config(
        app=app,
        host="127.0.0.1",
        port=port,
        log_level="info",
        limit_concurrency=10,
        timeout_keep_alive=5,
        access_log=False,
    )

    # Start the server
    server = uvicorn.Server(config=config)

    # This is important to catch exceptions and prevent test hangs
    try:
        server.run()
    except Exception:
        import traceback

        traceback.print_exc()

## test_accept_header_validation

**Type**: Function

**Description**: def test_accept_header_validation(basic_server, basic_server_url):
    """Test that Accept header is properly validated."""
    # Test without Accept header
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={"Content-Type": "application/json"},
        json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
    )
    assert response.status_code == 406
    assert "Not Acceptable" in response.text

## test_content_type_validation

**Type**: Function

**Description**: def test_content_type_validation(basic_server, basic_server_url):
    """Test that Content-Type header is properly validated."""
    # Test with incorrect Content-Type
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "text/plain",
        },
        data="This is not JSON",
    )

    assert response.status_code == 400
    assert "Invalid Content-Type" in response.text

## test_json_validation

**Type**: Function

**Description**: def test_json_validation(basic_server, basic_server_url):
    """Test that JSON content is properly validated."""
    # Test with invalid JSON
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        data="this is not valid json",
    )
    assert response.status_code == 400
    assert "Parse error" in response.text

## test_json_parsing

**Type**: Function

**Description**: def test_json_parsing(basic_server, basic_server_url):
    """Test that JSON content is properly parse."""
    # Test with valid JSON but invalid JSON-RPC
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json={"foo": "bar"},
    )
    assert response.status_code == 400
    assert "Validation error" in response.text

## test_method_not_allowed

**Type**: Function

**Description**: def test_method_not_allowed(basic_server, basic_server_url):
    """Test that unsupported HTTP methods are rejected."""
    # Test with unsupported method (PUT)
    response = requests.put(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
    )
    assert response.status_code == 405
    assert "Method Not Allowed" in response.text

## test_session_validation

**Type**: Function

**Description**: def test_session_validation(basic_server, basic_server_url):
    """Test session ID validation."""
    # session_id not used directly in this test

    # Test without session ID
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json={"jsonrpc": "2.0", "method": "list_tools", "id": 1},
    )
    assert response.status_code == 400
    assert "Missing session ID" in response.text

## test_session_id_pattern

**Type**: Function

**Description**: def test_session_id_pattern():
    """Test that SESSION_ID_PATTERN correctly validates session IDs."""
    # Valid session IDs (visible ASCII characters from 0x21 to 0x7E)
    valid_session_ids = [
        "test-session-id",
        "1234567890",
        "session!@#$%^&*()_+-=[]{}|;:,.<>?/",
        "~`",
    ]

    for session_id in valid_session_ids:
        assert SESSION_ID_PATTERN.match(session_id) is not None
        # Ensure fullmatch matches too (whole string)
        assert SESSION_ID_PATTERN.fullmatch(session_id) is not None

    # Invalid session IDs
    invalid_session_ids = [
        "",  # Empty string
        " test",  # Space (0x20)
        "test\t",  # Tab
        "test\n",  # Newline
        "test\r",  # Carriage return
        "test" + chr(0x7F),  # DEL character
        "test" + chr(0x80),  # Extended ASCII
        "test" + chr(0x00),  # Null character
        "test" + chr(0x20),  # Space (0x20)
    ]

    for session_id in invalid_session_ids:
        # For invalid IDs, either match will fail or fullmatch will fail
        if SESSION_ID_PATTERN.match(session_id) is not None:
            # If match succeeds, fullmatch should fail (partial match case)
            assert SESSION_ID_PATTERN.fullmatch(session_id) is None

## test_streamable_http_transport_init_validation

**Type**: Function

**Description**: def test_streamable_http_transport_init_validation():
    """Test that StreamableHTTPServerTransport validates session ID on init."""
    # Valid session ID should initialize without errors
    valid_transport = StreamableHTTPServerTransport(mcp_session_id="valid-id")
    assert valid_transport.mcp_session_id == "valid-id"

    # None should be accepted
    none_transport = StreamableHTTPServerTransport(mcp_session_id=None)
    assert none_transport.mcp_session_id is None

    # Invalid session ID should raise ValueError
    with pytest.raises(ValueError) as excinfo:
        StreamableHTTPServerTransport(mcp_session_id="invalid id with space")
    assert "Session ID must only contain visible ASCII characters" in str(excinfo.value)

    # Test with control characters
    with pytest.raises(ValueError):
        StreamableHTTPServerTransport(mcp_session_id="test\nid")

    with pytest.raises(ValueError):
        StreamableHTTPServerTransport(mcp_session_id="test\n")

## test_session_termination

**Type**: Function

**Description**: def test_session_termination(basic_server, basic_server_url):
    """Test session termination via DELETE and subsequent request handling."""
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json=INIT_REQUEST,
    )
    assert response.status_code == 200

    # Extract negotiated protocol version from SSE response
    negotiated_version = extract_protocol_version_from_sse(response)

    # Now terminate the session
    session_id = response.headers.get(MCP_SESSION_ID_HEADER)
    response = requests.delete(
        f"{basic_server_url}/mcp",
        headers={
            MCP_SESSION_ID_HEADER: session_id,
            MCP_PROTOCOL_VERSION_HEADER: negotiated_version,
        },
    )
    assert response.status_code == 200

    # Try to use the terminated session
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            MCP_SESSION_ID_HEADER: session_id,
        },
        json={"jsonrpc": "2.0", "method": "ping", "id": 2},
    )
    assert response.status_code == 404
    assert "Session has been terminated" in response.text

## test_response

**Type**: Function

**Description**: def test_response(basic_server, basic_server_url):
    """Test response handling for a valid request."""
    mcp_url = f"{basic_server_url}/mcp"
    response = requests.post(
        mcp_url,
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json=INIT_REQUEST,
    )
    assert response.status_code == 200

    # Extract negotiated protocol version from SSE response
    negotiated_version = extract_protocol_version_from_sse(response)

    # Now get the session ID
    session_id = response.headers.get(MCP_SESSION_ID_HEADER)

    # Try to use the session with proper headers
    tools_response = requests.post(
        mcp_url,
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            MCP_SESSION_ID_HEADER: session_id,  # Use the session ID we got earlier
            MCP_PROTOCOL_VERSION_HEADER: negotiated_version,
        },
        json={"jsonrpc": "2.0", "method": "tools/list", "id": "tools-1"},
        stream=True,
    )
    assert tools_response.status_code == 200
    assert tools_response.headers.get("Content-Type") == "text/event-stream"

## test_json_response

**Type**: Function

**Description**: def test_json_response(json_response_server, json_server_url):
    """Test response handling when is_json_response_enabled is True."""
    mcp_url = f"{json_server_url}/mcp"
    response = requests.post(
        mcp_url,
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json=INIT_REQUEST,
    )
    assert response.status_code == 200
    assert response.headers.get("Content-Type") == "application/json"

## test_get_sse_stream

**Type**: Function

**Description**: def test_get_sse_stream(basic_server, basic_server_url):
    """Test establishing an SSE stream via GET request."""
    # First, we need to initialize a session
    mcp_url = f"{basic_server_url}/mcp"
    init_response = requests.post(
        mcp_url,
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json=INIT_REQUEST,
    )
    assert init_response.status_code == 200

    # Get the session ID
    session_id = init_response.headers.get(MCP_SESSION_ID_HEADER)
    assert session_id is not None

    # Extract negotiated protocol version from SSE response
    init_data = None
    assert init_response.headers.get("Content-Type") == "text/event-stream"
    for line in init_response.text.splitlines():
        if line.startswith("data: "):
            init_data = json.loads(line[6:])
            break
    assert init_data is not None
    negotiated_version = init_data["result"]["protocolVersion"]

    # Now attempt to establish an SSE stream via GET
    get_response = requests.get(
        mcp_url,
        headers={
            "Accept": "text/event-stream",
            MCP_SESSION_ID_HEADER: session_id,
            MCP_PROTOCOL_VERSION_HEADER: negotiated_version,
        },
        stream=True,
    )

    # Verify we got a successful response with the right content type
    assert get_response.status_code == 200
    assert get_response.headers.get("Content-Type") == "text/event-stream"

    # Test that a second GET request gets rejected (only one stream allowed)
    second_get = requests.get(
        mcp_url,
        headers={
            "Accept": "text/event-stream",
            MCP_SESSION_ID_HEADER: session_id,
            MCP_PROTOCOL_VERSION_HEADER: negotiated_version,
        },
        stream=True,
    )

    # Should get CONFLICT (409) since there's already a stream
    # Note: This might fail if the first stream fully closed before this runs,
    # but generally it should work in the test environment where it runs quickly
    assert second_get.status_code == 409

## test_get_validation

**Type**: Function

**Description**: def test_get_validation(basic_server, basic_server_url):
    """Test validation for GET requests."""
    # First, we need to initialize a session
    mcp_url = f"{basic_server_url}/mcp"
    init_response = requests.post(
        mcp_url,
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json=INIT_REQUEST,
    )
    assert init_response.status_code == 200

    # Get the session ID
    session_id = init_response.headers.get(MCP_SESSION_ID_HEADER)
    assert session_id is not None

    # Extract negotiated protocol version from SSE response
    init_data = None
    assert init_response.headers.get("Content-Type") == "text/event-stream"
    for line in init_response.text.splitlines():
        if line.startswith("data: "):
            init_data = json.loads(line[6:])
            break
    assert init_data is not None
    negotiated_version = init_data["result"]["protocolVersion"]

    # Test without Accept header
    response = requests.get(
        mcp_url,
        headers={
            MCP_SESSION_ID_HEADER: session_id,
            MCP_PROTOCOL_VERSION_HEADER: negotiated_version,
        },
        stream=True,
    )
    assert response.status_code == 406
    assert "Not Acceptable" in response.text

    # Test with wrong Accept header
    response = requests.get(
        mcp_url,
        headers={
            "Accept": "application/json",
            MCP_SESSION_ID_HEADER: session_id,
            MCP_PROTOCOL_VERSION_HEADER: negotiated_version,
        },
    )
    assert response.status_code == 406
    assert "Not Acceptable" in response.text

## ContextAwareServerTest

**Type**: Class

**Description**: class ContextAwareServerTest(Server):
    def __init__(self):
        super().__init__("ContextAwareServer")

        @self.list_tools()
        async def handle_list_tools() -> list[Tool]:
            return [
                Tool(
                    name="echo_headers",
                    description="Echo request headers from context",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="echo_context",
                    description="Echo request context with custom data",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "request_id": {"type": "string"},
                        },
                        "required": ["request_id"],
                    },
                ),
            ]

        @self.call_tool()
        async def handle_call_tool(name: str, args: dict) -> list[TextContent]:
            ctx = self.request_context

            if name == "echo_headers":
                # Access the request object from context
                headers_info = {}
                if ctx.request and isinstance(ctx.request, Request):
                    headers_info = dict(ctx.request.headers)
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(headers_info),
                    )
                ]

            elif name == "echo_context":
                # Return full context information
                context_data = {
                    "request_id": args.get("request_id"),
                    "headers": {},
                    "method": None,
                    "path": None,
                }
                if ctx.request and isinstance(ctx.request, Request):
                    request = ctx.request
                    context_data["headers"] = dict(request.headers)
                    context_data["method"] = request.method
                    context_data["path"] = request.url.path
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(context_data),
                    )
                ]

            return [TextContent(type="text", text=f"Unknown tool: {name}")]

## run_context_aware_server

**Type**: Function

**Description**: def run_context_aware_server(port: int):
    """Run the context-aware test server."""
    server = ContextAwareServerTest()

    session_manager = StreamableHTTPSessionManager(
        app=server,
        event_store=None,
        json_response=False,
    )

    app = Starlette(
        debug=True,
        routes=[
            Mount("/mcp", app=session_manager.handle_request),
        ],
        lifespan=lambda app: session_manager.run(),
    )

    server_instance = uvicorn.Server(
        config=uvicorn.Config(
            app=app,
            host="127.0.0.1",
            port=port,
            log_level="error",
        )
    )
    server_instance.run()

## test_server_validates_protocol_version_header

**Type**: Function

**Description**: def test_server_validates_protocol_version_header(basic_server, basic_server_url):
    """Test that server returns 400 Bad Request version if header unsupported or invalid."""
    # First initialize a session to get a valid session ID
    init_response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json=INIT_REQUEST,
    )
    assert init_response.status_code == 200
    session_id = init_response.headers.get(MCP_SESSION_ID_HEADER)

    # Test request with invalid protocol version (should fail)
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            MCP_SESSION_ID_HEADER: session_id,
            MCP_PROTOCOL_VERSION_HEADER: "invalid-version",
        },
        json={"jsonrpc": "2.0", "method": "tools/list", "id": "test-2"},
    )
    assert response.status_code == 400
    assert MCP_PROTOCOL_VERSION_HEADER in response.text or "protocol version" in response.text.lower()

    # Test request with unsupported protocol version (should fail)
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            MCP_SESSION_ID_HEADER: session_id,
            MCP_PROTOCOL_VERSION_HEADER: "1999-01-01",  # Very old unsupported version
        },
        json={"jsonrpc": "2.0", "method": "tools/list", "id": "test-3"},
    )
    assert response.status_code == 400
    assert MCP_PROTOCOL_VERSION_HEADER in response.text or "protocol version" in response.text.lower()

    # Test request with valid protocol version (should succeed)
    negotiated_version = extract_protocol_version_from_sse(init_response)

    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            MCP_SESSION_ID_HEADER: session_id,
            MCP_PROTOCOL_VERSION_HEADER: negotiated_version,
        },
        json={"jsonrpc": "2.0", "method": "tools/list", "id": "test-4"},
    )
    assert response.status_code == 200

## test_server_backwards_compatibility_no_protocol_version

**Type**: Function

**Description**: def test_server_backwards_compatibility_no_protocol_version(basic_server, basic_server_url):
    """Test server accepts requests without protocol version header."""
    # First initialize a session to get a valid session ID
    init_response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json=INIT_REQUEST,
    )
    assert init_response.status_code == 200
    session_id = init_response.headers.get(MCP_SESSION_ID_HEADER)

    # Test request without mcp-protocol-version header (backwards compatibility)
    response = requests.post(
        f"{basic_server_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            MCP_SESSION_ID_HEADER: session_id,
        },
        json={"jsonrpc": "2.0", "method": "tools/list", "id": "test-backwards-compat"},
        stream=True,
    )
    assert response.status_code == 200  # Should succeed for backwards compatibility
    assert response.headers.get("Content-Type") == "text/event-stream"

## ServerTest

**Type**: Class

**Description**: class ServerTest(Server):
    def __init__(self):
        super().__init__(SERVER_NAME)

        @self.read_resource()
        async def handle_read_resource(uri: AnyUrl) -> str | bytes:
            if uri.scheme == "foobar":
                return f"Read {uri.host}"
            elif uri.scheme == "slow":
                # Simulate a slow resource
                await anyio.sleep(2.0)
                return f"Slow response from {uri.host}"

            raise McpError(error=ErrorData(code=404, message="OOPS! no resource with that URI was found"))

        @self.list_tools()
        async def handle_list_tools() -> list[Tool]:
            return [
                Tool(
                    name="test_tool",
                    description="A test tool",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]

        @self.call_tool()
        async def handle_call_tool(name: str, args: dict) -> list[TextContent]:
            return [TextContent(type="text", text=f"Called {name}")]

## make_server_app

**Type**: Function

**Description**: def make_server_app() -> Starlette:
    """Create test Starlette app with WebSocket transport"""
    server = ServerTest()

    async def handle_ws(websocket):
        async with websocket_server(websocket.scope, websocket.receive, websocket.send) as streams:
            await server.run(streams[0], streams[1], server.create_initialization_options())

    app = Starlette(
        routes=[
            WebSocketRoute("/ws", endpoint=handle_ws),
        ]
    )

    return app

## run_server

**Type**: Function

**Description**: def run_server(server_port: int) -> None:
    app = make_server_app()
    server = uvicorn.Server(config=uvicorn.Config(app=app, host="127.0.0.1", port=server_port, log_level="error"))
    print(f"starting server on {server_port}")
    server.run()

    # Give server time to start
    while not server.started:
        print("waiting for server to start")
        time.sleep(0.5)

