from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastmcp import FastMCP
from dotenv import load_dotenv
import os
import requests
import io

load_dotenv()

# Environment variables
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
OWNER_EMAIL = os.getenv("OWNER_EMAIL", "owner@example.com")
SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive.readonly"
]

# In-memory token storage for single user
stored_token = None

# Create MCP instance
mcp = FastMCP("Google Drive MCP")

# --- MCP Tools ---
@mcp.tool()
async def list_drive_files(max_results: int = 20) -> dict:
    """List files from Google Drive
    
    Args:
        max_results: Maximum number of files to return (default: 20, max: 100)
    """
    if not stored_token:
        return {"error": "No Google account connected. Please authenticate first at /auth"}

    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build

        max_results = min(max_results, 100)
        
        creds = Credentials(
            token=stored_token.get("access_token"),
            refresh_token=stored_token.get("refresh_token"),
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
        return {"error": str(e)}

@mcp.tool()
async def search_drive_files(query: str, max_results: int = 10) -> dict:
    """Search for files in Google Drive by name
    
    Args:
        query: Search query (file name to search for)
        max_results: Maximum number of results to return (default: 10)
    """
    if not stored_token:
        return {"error": "No Google account connected. Please authenticate first at /auth"}

    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build

        creds = Credentials(
            token=stored_token.get("access_token"),
            refresh_token=stored_token.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=SCOPES,
        )

        service = build("drive", "v3", credentials=creds)
        safe_query = query.replace("'", "\\'")
        res = service.files().list(
            q=f"name contains '{safe_query}'",
            pageSize=min(max_results, 100),
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
        return {"error": str(e)}

@mcp.tool()
async def read_file_content(file_id: str) -> dict:
    """Read the contents of a specific file from Google Drive
    
    Args:
        file_id: The Google Drive file ID to read
    
    Returns:
        Dictionary containing file metadata and content (for text files) or download info (for binary files)
    """
    if not stored_token:
        return {"error": "No Google account connected. Please authenticate first at /auth"}

    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseDownload

        creds = Credentials(
            token=stored_token.get("access_token"),
            refresh_token=stored_token.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=SCOPES,
        )

        service = build("drive", "v3", credentials=creds)
        
        # Get file metadata
        file_metadata = service.files().get(
            fileId=file_id,
            fields="id,name,mimeType,size,modifiedTime,webViewLink"
        ).execute()
        
        mime_type = file_metadata.get("mimeType", "")
        
        # Handle Google Workspace files (Docs, Sheets, Slides)
        if mime_type.startswith("application/vnd.google-apps"):
            export_formats = {
                "application/vnd.google-apps.document": "text/plain",
                "application/vnd.google-apps.spreadsheet": "text/csv",
                "application/vnd.google-apps.presentation": "text/plain",
            }
            
            if mime_type in export_formats:
                request = service.files().export_media(
                    fileId=file_id,
                    mimeType=export_formats[mime_type]
                )
                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request)
                
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                
                content = fh.getvalue().decode("utf-8", errors="replace")
                return {
                    "success": True,
                    "file_id": file_id,
                    "name": file_metadata["name"],
                    "mimeType": mime_type,
                    "exported_as": export_formats[mime_type],
                    "size": len(content),
                    "content": content
                }
            else:
                return {
                    "success": False,
                    "error": f"Google Workspace file type '{mime_type}' cannot be exported as text",
                    "file_id": file_id,
                    "name": file_metadata["name"],
                    "webViewLink": file_metadata.get("webViewLink")
                }
        
        # Handle regular files
        request = service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        
        done = False
        while not done:
            status, done = downloader.next_chunk()
        
        content_bytes = fh.getvalue()
        
        # Try to decode as text for common text formats
        text_mime_types = [
            "text/", "application/json", "application/xml",
            "application/javascript", "application/x-python"
        ]
        
        if any(mime_type.startswith(t) for t in text_mime_types):
            try:
                content = content_bytes.decode("utf-8")
                return {
                    "success": True,
                    "file_id": file_id,
                    "name": file_metadata["name"],
                    "mimeType": mime_type,
                    "size": len(content_bytes),
                    "content": content
                }
            except UnicodeDecodeError:
                pass
        
        # For binary files, return metadata only
        return {
            "success": True,
            "file_id": file_id,
            "name": file_metadata["name"],
            "mimeType": mime_type,
            "size": file_metadata.get("size"),
            "content": None,
            "message": "Binary file - content not displayed. Use webViewLink to access.",
            "webViewLink": file_metadata.get("webViewLink")
        }
        
    except Exception as e:
        return {"error": str(e), "file_id": file_id}

@mcp.tool()
async def get_auth_status() -> dict:
    """Check if the server is authenticated with Google Drive"""
    return {
        "authenticated": stored_token is not None,
        "owner": OWNER_EMAIL if stored_token else None,
        "message": "Connected to Google Drive" if stored_token else "Not authenticated. Please visit /auth to connect."
    }

# Create the MCP ASGI app - this creates a Starlette app with the MCP endpoint at /mcp/
mcp_asgi = mcp.http_app(path='/mcp')

# Create a Starlette app to combine everything
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.responses import JSONResponse as StarletteJSONResponse

# Define OAuth routes
async def start_auth(request):
    if not CLIENT_ID or not CLIENT_SECRET or not REDIRECT_URI:
        return StarletteJSONResponse({"error": "OAuth environment variables missing"}, status_code=500)

    from urllib.parse import urlencode
    params = urlencode({
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
    })
    return StarletteJSONResponse({"auth_url": f"https://accounts.google.com/o/oauth2/v2/auth?{params}"})

async def oauth_callback(request):
    global stored_token
    code = request.query_params.get("code")
    if not code:
        return StarletteJSONResponse({"error": "Missing code"}, status_code=400)

    token_resp = requests.post("https://oauth2.googleapis.com/token", data={
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    })

    if token_resp.status_code != 200:
        return StarletteJSONResponse({"error": f"Token exchange failed: {token_resp.text}"}, status_code=500)

    stored_token = token_resp.json()
    return StarletteJSONResponse({"status": "connected", "owner": OWNER_EMAIL})

async def health(request):
    return StarletteJSONResponse({
        "status": "ok", 
        "authenticated": stored_token is not None,
        "owner": OWNER_EMAIL
    })

async def root(request):
    return StarletteJSONResponse({
        "service": "Google Drive MCP Server",
        "endpoints": {
            "auth": "/auth - Start OAuth flow",
            "callback": "/oauth2callback - OAuth callback",
            "health": "/health - Health check",
            "mcp": "/mcp/ - MCP protocol endpoint (POST only)"
        },
        "authenticated": stored_token is not None
    })

# Create the main app using Starlette and mount everything
app = Starlette(
    routes=[
        Route("/", root),
        Route("/auth", start_auth),
        Route("/oauth2callback", oauth_callback),
        Route("/health", health),
        Mount("/", mcp_asgi),  # Mount MCP at root - it will handle /mcp/ path
    ],
    lifespan=mcp_asgi.lifespan,  # CRITICAL: Pass MCP's lifespan
)

# Export for uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
