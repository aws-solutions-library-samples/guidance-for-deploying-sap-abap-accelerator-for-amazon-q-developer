"""
OAuth Callback Handler - Handles OAuth redirect after user authentication
"""

import logging
from typing import Optional
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse

logger = logging.getLogger(__name__)

# Create router for OAuth endpoints
oauth_router = APIRouter(prefix="/oauth", tags=["oauth"])


@oauth_router.get("/callback")
async def oauth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None
):
    """
    OAuth callback endpoint - receives authorization code from IdP.
    
    This endpoint is called by the IdP after user authenticates.
    Q Developer will be listening for this callback.
    
    Query parameters:
    - code: Authorization code (success case)
    - state: State parameter for CSRF protection
    - error: Error code (error case)
    - error_description: Human-readable error description
    """
    
    # Check for errors from IdP
    if error:
        logger.error(f"OAuth: Callback received error: {error} - {error_description}")
        return HTMLResponse(
            content=f"""
            <html>
                <head><title>Authentication Error</title></head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p><strong>Error:</strong> {error}</p>
                    <p><strong>Description:</strong> {error_description or 'No description provided'}</p>
                    <p>You can close this window and try again.</p>
                </body>
            </html>
            """,
            status_code=400
        )
    
    # Validate code is present
    if not code:
        logger.error("OAuth: Callback received without authorization code")
        raise HTTPException(
            status_code=400,
            detail="Missing authorization code"
        )
    
    logger.info(f"OAuth: Callback received with code (state={state})")
    
    # Import here to avoid circular dependency
    from .oauth_manager import oauth_manager
    from enterprise.middleware import enterprise_middleware
    
    # Exchange code for tokens
    token_response = await oauth_manager.exchange_code(code)
    
    if not token_response:
        logger.error("OAuth: Failed to exchange code for tokens")
        return HTMLResponse(
            content="""
            <html>
                <head><title>Authentication Error</title></head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Failed to exchange authorization code for tokens.</p>
                    <p>Please try again or contact support.</p>
                </body>
            </html>
            """,
            status_code=500
        )
    
    # Extract user identity from ID token
    id_token = token_response.get('id_token')
    if not id_token:
        logger.error("OAuth: No ID token in response")
        return HTMLResponse(
            content="""
            <html>
                <head><title>Authentication Error</title></head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>No ID token received from identity provider.</p>
                    <p>Please try again or contact support.</p>
                </body>
            </html>
            """,
            status_code=500
        )
    
    # Extract user from JWT
    user_id = enterprise_middleware.extract_user_identity_from_jwt(id_token)
    
    if not user_id or user_id == 'anonymous':
        logger.error("OAuth: Failed to extract user from ID token")
        return HTMLResponse(
            content="""
            <html>
                <head><title>Authentication Error</title></head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Could not extract user identity from token.</p>
                    <p>Please ensure your user profile has required attributes.</p>
                </body>
            </html>
            """,
            status_code=500
        )
    
    logger.info(f"OAuth: Successfully authenticated user: {user_id}")
    
    # Return success page with tokens
    # Q Developer will capture these tokens and use them for subsequent requests
    return HTMLResponse(
        content=f"""
        <html>
            <head>
                <title>Authentication Successful</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        max-width: 600px;
                        margin: 50px auto;
                        padding: 20px;
                        background-color: #f5f5f5;
                    }}
                    .success {{
                        background-color: #d4edda;
                        border: 1px solid #c3e6cb;
                        color: #155724;
                        padding: 20px;
                        border-radius: 5px;
                    }}
                    .token-info {{
                        background-color: #fff;
                        border: 1px solid #ddd;
                        padding: 15px;
                        margin-top: 20px;
                        border-radius: 5px;
                        font-family: monospace;
                        font-size: 12px;
                        word-break: break-all;
                    }}
                    h1 {{
                        color: #155724;
                    }}
                </style>
            </head>
            <body>
                <div class="success">
                    <h1>✓ Authentication Successful</h1>
                    <p><strong>User:</strong> {user_id}</p>
                    <p>You have been successfully authenticated.</p>
                    <p><strong>You can now close this window and return to Q Developer.</strong></p>
                </div>
                
                <div class="token-info">
                    <p><strong>Access Token:</strong></p>
                    <p>{token_response.get('access_token', 'N/A')[:50]}...</p>
                    <p><strong>Expires In:</strong> {token_response.get('expires_in', 'N/A')} seconds</p>
                </div>
                
                <script>
                    // Auto-close window after 3 seconds
                    setTimeout(function() {{
                        window.close();
                    }}, 3000);
                </script>
            </body>
        </html>
        """,
        status_code=200
    )


@oauth_router.get("/status")
async def oauth_status():
    """
    OAuth status endpoint - check if OAuth is configured.
    Useful for debugging.
    """
    from .oauth_manager import oauth_manager
    
    return {
        "oauth_enabled": oauth_manager.is_enabled(),
        "config": oauth_manager.get_config_summary()
    }
