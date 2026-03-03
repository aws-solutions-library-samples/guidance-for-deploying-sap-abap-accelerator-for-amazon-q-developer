"""
FastMCP OAuth Integration
Integrates FastMCP's built-in OAuthProxy with our IdP-agnostic user extraction

IMPORTANT: FastMCP 2.13+ uses a token factory pattern:
- OAuthProxy receives tokens from upstream IdP (Okta)
- Encrypts and stores them internally
- Issues its OWN JWT tokens to MCP clients
- These FastMCP JWTs are signed with jwt_signing_key

The token_verifier validates UPSTREAM tokens (from Okta) AFTER FastMCP
validates its own JWT. This is a two-tier validation:
1. FastMCP validates its JWT (signature, audience, expiry)
2. FastMCP decrypts and validates upstream token using token_verifier

NOTE: Okta doesn't support RFC 8707 resource indicators. We patch the
OAuthProxy to not forward this parameter.

KIRO COMPATIBILITY: Kiro's MCP OAuth client has a bug where it doesn't send
client_id/client_secret during token exchange after dynamic client registration.
We patch the token endpoint to look up client info from the authorization code
when credentials are missing. This is safe because:
1. PKCE protects against code interception
2. Authorization codes are single-use and short-lived
3. The code is already bound to a specific client_id in the transaction store
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _patch_oauth_proxy_for_okta(oauth_proxy):
    """
    Patch OAuthProxy to not forward the 'resource' parameter to Okta.
    Okta doesn't support RFC 8707 and returns 'access_denied' when present.
    
    FastMCP's _build_upstream_authorize_url checks:
        if resource := transaction.get("resource"):
            query_params["resource"] = resource
    
    By removing 'resource' from the transaction dict, we prevent it from being
    added to the authorization URL sent to Okta.
    """
    original_build_url = oauth_proxy._build_upstream_authorize_url
    
    def patched_build_url(txn_id: str, transaction: dict) -> str:
        # Remove 'resource' from transaction before building URL
        if isinstance(transaction, dict) and 'resource' in transaction:
            transaction = dict(transaction)  # Make a copy to avoid modifying original
            del transaction['resource']  # Remove the key entirely
            logger.debug("OAuth: Stripped 'resource' parameter for Okta compatibility")
        return original_build_url(txn_id, transaction)
    
    oauth_proxy._build_upstream_authorize_url = patched_build_url
    logger.info("OAuth: Patched OAuthProxy to strip 'resource' parameter (Okta compatibility)")
    return oauth_proxy


def _patch_oauth_proxy_for_kiro(oauth_proxy):
    """
    Patch OAuthProxy to handle Kiro's broken OAuth client implementation.
    
    PROBLEM: Kiro doesn't send client_id/client_secret during token exchange
    after dynamic client registration. The MCP SDK's ClientAuthenticator
    middleware rejects the request with "Missing client_id".
    
    SOLUTION: We need to intercept the request BEFORE the ClientAuthenticator
    runs and inject the client_id from the authorization code. We do this by
    wrapping the token endpoint with a middleware that modifies the request.
    
    This is safe because:
    1. PKCE (code_challenge/code_verifier) protects against code interception
    2. Authorization codes are single-use and expire in 5 minutes
    3. The code is already bound to a specific client_id in the code store
    
    This patch does NOT affect Q Developer or other properly-behaving clients
    because they already send client_id in the token request.
    """
    from starlette.requests import Request
    from starlette.responses import Response, JSONResponse
    from starlette.routing import Route
    
    # Store reference to the code store for client_id lookup
    code_store = oauth_proxy._code_store
    
    async def _lookup_client_id_from_code(code: str) -> Optional[str]:
        """Look up client_id from authorization code in the code store."""
        try:
            code_model = await code_store.get(key=code)
            if code_model and hasattr(code_model, 'client_id'):
                return code_model.client_id
        except Exception as e:
            logger.debug(f"OAuth: Could not look up client_id from code: {e}")
        return None
    
    # Store the original get_routes method
    original_get_routes = oauth_proxy.get_routes
    
    def patched_get_routes(*args, **kwargs):
        """
        Return routes with a wrapper around the token endpoint.
        
        The wrapper intercepts requests, checks if client_id is missing,
        and if so, looks it up from the authorization code and creates
        a modified request with the client_id injected.
        
        NOTE: Must accept *args, **kwargs to handle mcp_path parameter from FastMCP.
        """
        # Call original with all arguments (including mcp_path if provided)
        routes = original_get_routes(*args, **kwargs)
        
        patched_routes = []
        for route in routes:
            if isinstance(route, Route) and route.path == "/token":
                original_endpoint = route.endpoint
                
                async def kiro_compatible_token_endpoint(request: Request, _original_endpoint=original_endpoint) -> Response:
                    """
                    Token endpoint wrapper that handles missing client_id for Kiro.
                    
                    This wrapper:
                    1. Reads the form data
                    2. If client_id is missing but code is present, looks up client_id
                    3. Creates a new request with injected client_id
                    4. Calls the original endpoint
                    """
                    from urllib.parse import parse_qs, urlencode
                    
                    try:
                        # Read the raw body
                        body = await request.body()
                        
                        # Parse form data manually
                        form_dict = {}
                        if body:
                            parsed = parse_qs(body.decode('utf-8'))
                            form_dict = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
                        
                        client_id = form_dict.get('client_id')
                        code = form_dict.get('code')
                        grant_type = form_dict.get('grant_type')
                        
                        # Only patch for authorization_code grant without client_id
                        if grant_type == 'authorization_code' and not client_id and code:
                            # Look up client_id from the authorization code
                            looked_up_client_id = await _lookup_client_id_from_code(str(code))
                            
                            if looked_up_client_id:
                                # Inject client_id into form data
                                form_dict['client_id'] = looked_up_client_id
                                
                                # Rebuild the body with injected client_id
                                new_body = urlencode(form_dict).encode('utf-8')
                                
                                # Create new scope with updated content-length
                                new_scope = dict(request.scope)
                                new_headers = []
                                for name, value in request.scope.get('headers', []):
                                    if name.lower() == b'content-length':
                                        new_headers.append((name, str(len(new_body)).encode()))
                                    else:
                                        new_headers.append((name, value))
                                new_scope['headers'] = new_headers
                                
                                # Check if original_endpoint is an ASGI app or a regular function
                                if hasattr(_original_endpoint, '__call__') and not callable(getattr(_original_endpoint, '__self__', None)):
                                    # Try to determine if it's an ASGI app by checking signature
                                    import inspect
                                    sig = inspect.signature(_original_endpoint)
                                    params = list(sig.parameters.keys())
                                    
                                    # ASGI apps have (scope, receive, send) or (self, scope, receive, send)
                                    if len(params) >= 3 and 'receive' in params and 'send' in params:
                                        # It's an ASGI app, call it with scope, receive, send
                                        response_started = False
                                        response_body = []
                                        response_status = 200
                                        response_headers = []
                                        
                                        async def receive():
                                            return {"type": "http.request", "body": new_body, "more_body": False}
                                        
                                        async def send(message):
                                            nonlocal response_started, response_status, response_headers
                                            if message["type"] == "http.response.start":
                                                response_started = True
                                                response_status = message.get("status", 200)
                                                response_headers = message.get("headers", [])
                                            elif message["type"] == "http.response.body":
                                                body_content = message.get("body", b"")
                                                if body_content:
                                                    response_body.append(body_content)
                                        
                                        await _original_endpoint(new_scope, receive, send)
                                        
                                        # Build response from captured data
                                        from starlette.responses import Response as StarletteResponse
                                        return StarletteResponse(
                                            content=b"".join(response_body),
                                            status_code=response_status,
                                            headers=dict((k.decode() if isinstance(k, bytes) else k, 
                                                         v.decode() if isinstance(v, bytes) else v) 
                                                        for k, v in response_headers)
                                        )
                                
                                # Fallback: try calling as regular endpoint with Request
                                async def receive():
                                    return {"type": "http.request", "body": new_body, "more_body": False}
                                
                                modified_request = Request(scope=new_scope, receive=receive)
                                return await _original_endpoint(modified_request)
                            else:
                                logger.warning("OAuth: Kiro compatibility - could not find client_id from code")
                                return JSONResponse(
                                    status_code=401,
                                    content={
                                        "error": "invalid_client",
                                        "error_description": "Client authentication failed - could not determine client_id"
                                    },
                                    headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
                                )
                        
                        # For normal requests (with client_id), recreate request and call original
                        # Check if original_endpoint is an ASGI app
                        import inspect
                        try:
                            sig = inspect.signature(_original_endpoint)
                            params = list(sig.parameters.keys())
                            
                            if len(params) >= 3 and 'receive' in params and 'send' in params:
                                # It's an ASGI app
                                response_body = []
                                response_status = 200
                                response_headers = []
                                
                                async def receive():
                                    return {"type": "http.request", "body": body, "more_body": False}
                                
                                async def send(message):
                                    nonlocal response_status, response_headers
                                    if message["type"] == "http.response.start":
                                        response_status = message.get("status", 200)
                                        response_headers = message.get("headers", [])
                                    elif message["type"] == "http.response.body":
                                        body_content = message.get("body", b"")
                                        if body_content:
                                            response_body.append(body_content)
                                
                                await _original_endpoint(request.scope, receive, send)
                                
                                from starlette.responses import Response as StarletteResponse
                                return StarletteResponse(
                                    content=b"".join(response_body),
                                    status_code=response_status,
                                    headers=dict((k.decode() if isinstance(k, bytes) else k,
                                                 v.decode() if isinstance(v, bytes) else v)
                                                for k, v in response_headers)
                                )
                        except (ValueError, TypeError):
                            pass
                        
                        # Fallback: call as regular endpoint
                        async def receive():
                            return {"type": "http.request", "body": body, "more_body": False}
                        
                        recreated_request = Request(scope=request.scope, receive=receive)
                        return await _original_endpoint(recreated_request)
                        
                    except Exception as e:
                        logger.error(f"OAuth: Error in Kiro compatibility wrapper: {e}", exc_info=True)
                        return JSONResponse(
                            status_code=500,
                            content={"error": "server_error", "error_description": str(e)}
                        )
                
                # Create patched route
                patched_route = Route(
                    path=route.path,
                    endpoint=kiro_compatible_token_endpoint,
                    methods=route.methods,
                    name=route.name
                )
                patched_routes.append(patched_route)
                logger.info("OAuth: Patched /token endpoint for Kiro compatibility")
            else:
                patched_routes.append(route)
        
        return patched_routes
    
    oauth_proxy.get_routes = patched_get_routes
    
    logger.info("OAuth: Applied Kiro compatibility patch (client_id injection for token exchange)")
    return oauth_proxy


def create_oauth_provider():
    """
    Create OAuth provider using FastMCP's OAuthProxy.
    
    CRITICAL: FastMCP 2.13+ requires jwt_signing_key for production!
    Without it, tokens are signed with ephemeral keys that:
    - Don't survive server restarts
    - Can cause "invalid_token" errors
    
    Returns:
        OAuthProxy instance or None if OAuth not configured
    """
    try:
        from fastmcp.server.auth import OAuthProxy
        from fastmcp.server.auth.providers.jwt import JWTVerifier
        
        logger.info("OAuth: Creating OAuthProxy with production configuration")
        
        # Check if OAuth is configured
        auth_endpoint = os.getenv('OAUTH_AUTH_ENDPOINT')
        token_endpoint = os.getenv('OAUTH_TOKEN_ENDPOINT')
        client_id = os.getenv('OAUTH_CLIENT_ID')
        base_url = os.getenv('SERVER_BASE_URL')
        
        if not all([auth_endpoint, token_endpoint, client_id, base_url]):
            logger.info("OAuth: Not all OAuth environment variables set, OAuth disabled")
            logger.info(f"OAuth:   OAUTH_AUTH_ENDPOINT: {'SET' if auth_endpoint else 'MISSING'}")
            logger.info(f"OAuth:   OAUTH_TOKEN_ENDPOINT: {'SET' if token_endpoint else 'MISSING'}")
            logger.info(f"OAuth:   OAUTH_CLIENT_ID: {'SET' if client_id else 'MISSING'}")
            logger.info(f"OAuth:   SERVER_BASE_URL: {'SET' if base_url else 'MISSING'}")
            return None
        
        client_secret = os.getenv('OAUTH_CLIENT_SECRET')
        jwt_signing_key = os.getenv('JWT_SIGNING_KEY')
        issuer = os.getenv('OAUTH_ISSUER')
        
        # Log configuration
        logger.info(f"OAuth: Configuration:")
        logger.info(f"OAuth:   Auth endpoint: {auth_endpoint}")
        logger.info(f"OAuth:   Token endpoint: {token_endpoint}")
        logger.info(f"OAuth:   Client ID: {client_id[:8]}...")
        logger.info(f"OAuth:   Base URL: {base_url}")
        logger.info(f"OAuth:   Issuer: {issuer}")
        
        # CRITICAL: jwt_signing_key is required for production
        if not jwt_signing_key:
            logger.warning("OAuth: ⚠️  JWT_SIGNING_KEY not set!")
            logger.warning("OAuth: ⚠️  FastMCP will use ephemeral keys (tokens won't survive restarts)")
            logger.warning("OAuth: ⚠️  Set JWT_SIGNING_KEY for production deployments")
        else:
            logger.info(f"OAuth:   JWT signing key: {len(jwt_signing_key)} chars ✓")
        
        # Create token_verifier - REQUIRED by OAuthProxy
        # This validates the UPSTREAM token from Okta
        token_verifier = None
        if issuer:
            import httpx
            import asyncio
            
            discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
            logger.info(f"OAuth: Discovering OIDC config from {discovery_url}")
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def fetch_config():
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        response = await client.get(discovery_url)
                        return response.json()
                
                config = loop.run_until_complete(fetch_config())
                jwks_uri = config.get('jwks_uri')
                
                if jwks_uri:
                    logger.info(f"OAuth: JWKS URI: {jwks_uri}")
                    
                    # Determine token audience with smart defaults
                    # Priority: OAUTH_AUDIENCE > OKTA_AUDIENCE (backward compat) > auto-detect
                    configured_audience = os.getenv('OAUTH_AUDIENCE') or os.getenv('OKTA_AUDIENCE')
                    
                    if configured_audience:
                        audience = configured_audience
                        logger.info(f"OAuth: Token audience (configured): {audience}")
                    else:
                        # Auto-detect based on issuer
                        # Okta's default authorization server uses "api://default" as audience
                        # Most other IdPs (Azure AD, Cognito, Federate, Auth0) use client_id
                        if '/oauth2/default' in issuer:
                            audience = 'api://default'
                            logger.info(f"OAuth: Token audience (auto-detect Okta default): {audience}")
                        else:
                            audience = client_id
                            logger.info(f"OAuth: Token audience (auto-detect, using client_id): {audience}")
                    
                    # Create verifier WITHOUT required_scopes to avoid token rejection
                    # required_scopes enforces scope validation on tokens, which breaks auth
                    token_verifier = JWTVerifier(
                        jwks_uri=jwks_uri,
                        issuer=issuer,
                        audience=audience
                        # NO required_scopes - it enforces scope validation and breaks tokens
                    )
                    logger.info("OAuth: ✓ Token verifier created (no required_scopes)")
            except Exception as e:
                logger.error(f"OAuth: Failed to discover OIDC config: {e}")
            finally:
                loop.close()
        
        if not token_verifier:
            logger.error("OAuth: Failed to create token_verifier - required by OAuthProxy")
            return None
        
        # Build OAuthProxy kwargs
        oauth_kwargs = {
            "upstream_authorization_endpoint": auth_endpoint,
            "upstream_token_endpoint": token_endpoint,
            "upstream_client_id": client_id,
            "upstream_client_secret": client_secret,
            "base_url": base_url,
            "redirect_path": "/oauth/callback",
            "token_verifier": token_verifier,  # REQUIRED
            # CRITICAL: Must specify valid_scopes or registration will reject all scopes
            "valid_scopes": ["openid", "email", "profile", "offline_access"],
        }
        
        # CRITICAL: Add jwt_signing_key for production
        if jwt_signing_key:
            oauth_kwargs["jwt_signing_key"] = jwt_signing_key
            logger.info("OAuth: ✓ Using persistent JWT signing key")
        else:
            # Generate a stable key from base_url to avoid ephemeral key issues
            import hashlib
            stable_key = hashlib.sha256(f"{base_url}:{client_id}".encode()).hexdigest()
            oauth_kwargs["jwt_signing_key"] = stable_key
            logger.warning("OAuth: ⚠️ JWT_SIGNING_KEY not set, using derived key (set for production)")
        
        # Create OAuthProxy
        oauth_proxy = OAuthProxy(**oauth_kwargs)
        
        # Patch for Okta compatibility (strip 'resource' parameter)
        oauth_proxy = _patch_oauth_proxy_for_okta(oauth_proxy)
        
        # Patch for Kiro compatibility (handle missing client_id in token exchange)
        # This MUST be applied before get_routes() is called
        oauth_proxy = _patch_oauth_proxy_for_kiro(oauth_proxy)
        
        # Patch for MCP clients that send empty scopes during registration (Kiro compatibility)
        # Set _default_scope_str directly so clients that don't send scopes get defaults
        # This doesn't affect token validation, only registration fallback
        default_scopes = ["openid", "email", "profile", "offline_access"]
        oauth_proxy._default_scope_str = " ".join(default_scopes)
        logger.info(f"OAuth: Set default registration scopes: {default_scopes}")
        
        logger.info("OAuth: ✓ OAuthProxy created successfully")
        logger.info("OAuth: Token flow: Client -> FastMCP JWT -> Decrypt -> Validate Okta token")
        
        return oauth_proxy
        
    except ImportError as e:
        logger.error(f"OAuth: Failed to import FastMCP auth modules: {e}")
        logger.error("OAuth: Ensure fastmcp >= 2.13.0 is installed")
        return None
    except Exception as e:
        logger.error(f"OAuth: Error creating OAuth provider: {e}", exc_info=True)
        return None


def extract_user_from_fastmcp_context(ctx) -> Optional[str]:
    """
    Extract user identity from FastMCP request context.
    
    FastMCP 2.13+ stores the validated access token in the context.
    The token contains claims from the upstream IdP (Okta).
    
    IMPORTANT: Returns the FULL login identifier (pass-through for certificate CN).
    Do NOT strip the @domain part - SAP CERTRULE handles the mapping.
    """
    try:
        # Method 1: Check for access_token in context (FastMCP 2.13+)
        if hasattr(ctx, 'access_token') and ctx.access_token:
            token = ctx.access_token
            
            # FastMCP AccessToken has claims from upstream IdP
            if hasattr(token, 'claims'):
                claims = token.claims
                
                # Try login identifier claims in priority order
                # These represent what the user actually typed to login
                for claim in ['login', 'upn', 'preferred_username', 'email', 'sub']:
                    if claim in claims and claims[claim]:
                        user_id = claims[claim]
                        # DO NOT strip @domain - pass through as-is for certificate CN
                        logger.info(f"OAuth: Extracted login identifier '{user_id}' from claim '{claim}'")
                        return user_id
            
            # Try raw token if claims not available
            if hasattr(token, 'raw') or hasattr(token, 'token'):
                jwt_token = getattr(token, 'raw', None) or getattr(token, 'token', None)
                if jwt_token:
                    return _extract_login_identifier_from_jwt(jwt_token)
        
        # Method 2: Check for user in context state
        if hasattr(ctx, 'state') and hasattr(ctx.state, 'user'):
            return ctx.state.user
        
        # Method 3: Check request headers (fallback)
        if hasattr(ctx, 'request') and hasattr(ctx.request, 'headers'):
            headers = ctx.request.headers
            for header in ['x-user-id', 'x-authenticated-user']:
                if header in headers:
                    return headers[header]
        
        logger.debug("OAuth: No user identity found in context")
        return None
        
    except Exception as e:
        logger.error(f"OAuth: Error extracting user from context: {e}")
        return None


def _extract_login_identifier_from_jwt(jwt_token: str) -> Optional[str]:
    """
    Extract login identifier from JWT token payload.
    
    Returns the FULL login identifier (what user typed to login).
    Do NOT strip @domain - pass through as-is for certificate CN.
    """
    try:
        import base64
        import json
        
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode payload
        payload = parts[1]
        payload += '=' * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)
        
        # Try login identifier claims in priority order
        # These represent what the user actually typed to login
        for claim in ['login', 'upn', 'preferred_username', 'cognito:username', 'email', 'sub']:
            if claim in claims and claims[claim]:
                login_id = claims[claim]
                # DO NOT strip @domain - pass through as-is
                logger.info(f"OAuth: Extracted login identifier '{login_id}' from JWT claim '{claim}'")
                return login_id
        
        return None
        
    except Exception as e:
        logger.debug(f"OAuth: Error decoding JWT: {e}")
        return None


def extract_user_from_fastmcp_token(token) -> Optional[str]:
    """
    Extract user identity from FastMCP access token.
    
    Returns the FULL login identifier (pass-through for certificate CN).
    Do NOT strip the @domain part - SAP CERTRULE handles the mapping.
    """
    try:
        if hasattr(token, 'raw'):
            jwt_token = token.raw
        elif hasattr(token, 'token'):
            jwt_token = token.token
        else:
            jwt_token = str(token)
        
        # Use the new function that preserves full login identifier
        user_id = _extract_login_identifier_from_jwt(jwt_token)
        
        if user_id:
            logger.info(f"OAuth: Extracted login identifier: {user_id}")
            return user_id
        
        return None
        
    except Exception as e:
        logger.error(f"OAuth: Error extracting user: {e}")
        return None


def get_user_from_request() -> Optional[str]:
    """
    Get authenticated user's login identifier from current request.
    
    Returns the FULL login identifier (pass-through for certificate CN).
    """
    try:
        from fastmcp.server.dependencies import get_access_token
        
        token = get_access_token()
        if not token:
            return None
        
        return extract_user_from_fastmcp_token(token)
        
    except Exception as e:
        logger.debug(f"OAuth: Error getting user: {e}")
        return None


def is_fastmcp_oauth_available() -> bool:
    """Check if FastMCP OAuth is available and configured"""
    try:
        from fastmcp.server.auth import OAuthProxy
        
        auth_endpoint = os.getenv('OAUTH_AUTH_ENDPOINT')
        token_endpoint = os.getenv('OAUTH_TOKEN_ENDPOINT')
        client_id = os.getenv('OAUTH_CLIENT_ID')
        base_url = os.getenv('SERVER_BASE_URL')
        
        return all([auth_endpoint, token_endpoint, client_id, base_url])
        
    except ImportError:
        return False
