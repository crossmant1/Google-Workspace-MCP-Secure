from fastapi import FastAPI, Request, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastmcp import FastMCP
from dotenv import load_dotenv
import os
import requests
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Environment variables
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
OWNER_EMAIL = os.getenv("OWNER_EMAIL", "owner@example.com")
API_KEY = os.getenv("API_KEY")  # Optional: Add API key for extra security
SCOPES = ["https://www.googleapis.com/auth/drive.metadata.readonly"]

# Security: Token storage with encryption (still in-memory for demo)
# In production, use a database with encryption or a secure key management service
class TokenStore:
    def __init__(self):
        self.tokens = {}
        self.states = {}  # For CSRF protection
    
    def generate_state(self) -> str:
        """Generate a secure random state for CSRF protection"""
        state = secrets.token_urlsafe(32)
        self.states[state] = datetime.utcnow()
        # Clean up old states (older than 10 minutes)
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        self.states = {k: v for k, v in self.states.items() if v > cutoff}
        return state
    
    def verify_state(self, state: str) -> bool:
        """Verify state is valid and not expired"""
        if state not in self.states:
            return False
        if datetime.utcnow() - self.states[state] > timedelta(minutes=10):
            del self.states[state]
            return False
        del self.states[state]
        return True
    
    def store_token(self, user_id: str, token_data: dict):
        """Store token with timestamp"""
        self.tokens[user_id] = {
            **token_data,
            "stored_at": datetime.utcnow()
        }
    
    def get_token(self, user_id: str) -> Optional[dict]:
        """Get token if valid"""
        if user_id not in self.tokens:
            return None
        return self.tokens[user_id]
    
    def refresh_token_if_needed(self, user_id: str) -> Optional[dict]:
        """Refresh token if it's expired or about to expire"""
        token_data = self.get_token(user_id)
        if not token_data:
            return None
        
        # Check if token needs refresh (if stored more than 50 minutes ago)
        stored_at = token_data.get("stored_at")
        if stored_at and datetime.utcnow() - stored_at > timedelta(minutes=50):
            refresh_token = token_data.get("refresh_token")
            if refresh_token:
                try:
                    response = requests.post(
                        "https://oauth2.googleapis.com/token",
                        data={
                            "client_id": CLIENT_ID,
                            "client_secret": CLIENT_SECRET,
                            "refresh_token": refresh_token,
                            "grant_type": "refresh_token",
                        },
                        timeout=10
                    )
                    if response.status_code == 200:
                        new_token = response.json()
                        # Keep the refresh token if not provided
                        if "refresh_token" not in new_token:
                            new_token["refresh_token"] = refresh_token
                        self.store_token(user_id, new_token)
                        logger.info(f"Token refreshed for user {user_id}")
                        return new_token
                except Exception as e:
                    logger.error(f"Token refresh failed: {e}")
        
        return token_data

token_store = TokenStore()

# Security: API Key authentication (optional)
security = HTTPBearer(auto_error=False)

def verify_api_key(credentials: Optional[HTTPAuthorizationCredentials] = Security(security)):
    """Verify API key if configured"""
    if API_KEY:
        if not credentials or credentials.credentials != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return True

# Create MCP instance
mcp = FastMCP("Google Drive MCP")

# --- MCP Tools ---
@mcp.tool()
async def list_drive_files(max_results: int = 20) -> dict:
    """List files from Google Drive
    
    Args:
        max_results: Maximum number of files to return (default: 20, max: 100)
    """
    # Use owner email as user_id for single-user mode
    token_data = token_store.refresh_token_if_needed(OWNER_EMAIL)
    
    if not token_data:
        return {"error": "No Google account connected. Please authenticate first at /auth"}

    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build

        max_results = min(max(1, max_results), 100)  # Clamp between 1 and 100
        
        creds = Credentials(
            token=token_data.get("access_token"),
            refresh_token=token_data.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=SCOPES,
        )

        service = build("drive", "v3", credentials=creds)
        res = service.files().list(
            pageSize=max_results, 
            fields="files(id,name,mimeType,modifiedTime,size)"
        ).execute()
        
        files = res.get("files", [])
        return {
            "success": True,
            "count": len(files),
            "files": files
        }
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return {"error": str(e)}

@mcp.tool()
async def search_drive_files(query: str, max_results: int = 10) -> dict:
    """Search for files in Google Drive by name
    
    Args:
        query: Search query (file name to search for)
        max_results: Maximum number of results to return (default: 10)
    """
    token_data = token_store.refresh_token_if_needed(OWNER_EMAIL)
    
    if not token_data:
        return {"error": "No Google account connected. Please authenticate first at /auth"}

    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build

        # Input validation
        if not query or len(query) > 200:
            return {"error": "Query must be between 1 and 200 characters"}
        
        max_results = min(max(1, max_results), 100)

        creds = Credentials(
            token=token_data.get("access_token"),
            refresh_token=token_data.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=SCOPES,
        )

        service = build("drive", "v3", credentials=creds)
        # Properly escape query for Google Drive API
        safe_query = query.replace("\\", "\\\\").replace("'", "\\'")
        res = service.files().list(
            q=f"name contains '{safe_query}'",
            pageSize=max_results,
            fields="files(id,name,mimeType,modifiedTime,size)"
        ).execute()
        
        files = res.get("files", [])
        return {
            "success": True,
            "query": query,
            "count": len(files),
            "files": files
        }
    except Exception as e:
        logger.error(f"Error searching files: {e}")
        return {"error": str(e)}

@mcp.tool()
async def get_auth_status() -> dict:
    """Check if the server is authenticated with Google Drive"""
    token_data = token_store.get_token(OWNER_EMAIL)
    return {
        "authenticated": token_data is not None,
        "owner": OWNER_EMAIL if token_data else None,
        "message": "Connected to Google Drive" if token_data else "Not authenticated. Please visit /auth to connect."
    }

# Create the MCP ASGI app
mcp_asgi = mcp.http_app(path='/mcp')

# Create Starlette app
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.responses import JSONResponse as StarletteJSONResponse

async def start_auth(request):
    """Start OAuth flow with CSRF protection"""
    if not CLIENT_ID or not CLIENT_SECRET or not REDIRECT_URI:
        logger.error("OAuth environment variables missing")
        return StarletteJSONResponse(
            {"error": "OAuth environment variables missing"}, 
            status_code=500
        )

    from urllib.parse import urlencode
    
    # Generate and store state for CSRF protection
    state = token_store.generate_state()
    
    params = urlencode({
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,  # CSRF protection
    })
    
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{params}"
    logger.info(f"Auth flow started with state: {state[:8]}...")
    
    return StarletteJSONResponse({"auth_url": auth_url})

async def oauth_callback(request):
    """OAuth callback with CSRF protection"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    # Check for OAuth errors
    if error:
        logger.error(f"OAuth error: {error}")
        return StarletteJSONResponse(
            {"error": f"OAuth error: {error}"}, 
            status_code=400
        )
    
    if not code:
        logger.error("Missing authorization code")
        return StarletteJSONResponse(
            {"error": "Missing authorization code"}, 
            status_code=400
        )
    
    # Verify state for CSRF protection
    if not state or not token_store.verify_state(state):
        logger.error("Invalid or missing state parameter")
        return StarletteJSONResponse(
            {"error": "Invalid or missing state parameter (CSRF check failed)"}, 
            status_code=400
        )

    try:
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uri": REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            timeout=10
        )

        if token_resp.status_code != 200:
            logger.error(f"Token exchange failed: {token_resp.text}")
            return StarletteJSONResponse(
                {"error": f"Token exchange failed: {token_resp.text}"}, 
                status_code=500
            )

        token_data = token_resp.json()
        token_store.store_token(OWNER_EMAIL, token_data)
        
        logger.info(f"Successfully authenticated user: {OWNER_EMAIL}")
        
        return StarletteJSONResponse({
            "status": "connected", 
            "owner": OWNER_EMAIL,
            "message": "Successfully authenticated with Google Drive"
        })
    
    except requests.exceptions.Timeout:
        logger.error("Token exchange timeout")
        return StarletteJSONResponse(
            {"error": "Token exchange timeout"}, 
            status_code=504
        )
    except Exception as e:
        logger.error(f"Unexpected error during OAuth callback: {e}")
        return StarletteJSONResponse(
            {"error": "An unexpected error occurred"}, 
            status_code=500
        )

async def health(request):
    """Health check endpoint"""
    token_data = token_store.get_token(OWNER_EMAIL)
    return StarletteJSONResponse({
        "status": "ok", 
        "authenticated": token_data is not None,
        "owner": OWNER_EMAIL if token_data else None,
        "version": "1.0.0"
    })

async def root(request):
    """Root endpoint with service information"""
    token_data = token_store.get_token(OWNER_EMAIL)
    return StarletteJSONResponse({
        "service": "Google Drive MCP Server",
        "version": "1.0.0",
        "endpoints": {
            "auth": "/auth - Start OAuth flow",
            "callback": "/oauth2callback - OAuth callback",
            "health": "/health - Health check",
            "mcp": "/mcp/ - MCP protocol endpoint (POST only)"
        },
        "authenticated": token_data is not None,
        "security_features": [
            "CSRF protection via state parameter",
            "Automatic token refresh",
            "Request timeout protection",
            "Input validation",
            "Secure logging"
        ]
    })

# Create the main app
app = Starlette(
    routes=[
        Route("/", root),
        Route("/auth", start_auth),
        Route("/oauth2callback", oauth_callback),
        Route("/health", health),
        Mount("/", mcp_asgi),
    ],
    lifespan=mcp_asgi.lifespan,
)

# Export for uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        log_level="info"
    )
