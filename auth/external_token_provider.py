"""
External Token Provider for workspace-mcp

Enables integration with external OAuth services like IMF OAuth Proxy.
Bypasses workspace-mcp's built-in OAuth 2.1 flow by accepting pre-authenticated
bearer tokens.

This module provides a simple authentication provider that accepts Google OAuth 2.0
access tokens from external sources and creates credentials for Google API calls.
"""

import logging
from typing import List, Optional

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class ExternalTokenProvider:
    """
    Authentication provider using pre-authenticated bearer tokens.
    
    Designed for integration with external OAuth services (e.g., IMF OAuth Proxy).
    Accepts Google OAuth 2.0 access tokens and creates credentials for API calls.
    
    This provider is stateless and relies on the external OAuth service to handle
    token refresh. It does not store or manage tokens internally.
    
    Example:
        ```python
        # Initialize with external token
        provider = ExternalTokenProvider(
            access_token="ya29.a0ARrdaM...",
            validate=True
        )
        
        # Get credentials for Google API calls
        credentials = provider.get_credentials()
        
        # Use with Google API client
        from googleapiclient.discovery import build
        service = build('gmail', 'v1', credentials=credentials)
        messages = service.users().messages().list(userId='me').execute()
        ```
    
    Attributes:
        access_token: Google OAuth 2.0 access token
        scopes: List of OAuth 2.0 scope URLs (for documentation only)
        credentials: Google API Credentials object
        user_info: Cached user info dict from token validation
    """
    
    def __init__(
        self,
        access_token: str,
        scopes: Optional[List[str]] = None,
        validate: bool = True
    ):
        """
        Initialize with external access token.
        
        Args:
            access_token: Google OAuth 2.0 access token
            scopes: OAuth scopes (for documentation only, not validated)
            validate: Whether to validate token on initialization
            
        Raises:
            ValueError: If access_token is empty or invalid (when validate=True)
        """
        if not access_token:
            raise ValueError("access_token is required and cannot be empty")
        
        self.access_token = access_token
        self.scopes = scopes or self._get_default_scopes()
        self.credentials = self._build_credentials()
        self.user_info = None
        
        if validate:
            if not self.validate_token():
                raise ValueError(
                    "Invalid or expired bearer token. "
                    "Token validation failed with Google APIs."
                )
            logger.info(
                "✅ External bearer token validated successfully",
                extra={"user_email": self.user_info.get('email') if self.user_info else 'unknown'}
            )
    
    def _get_default_scopes(self) -> List[str]:
        """
        Get default scopes for Google Workspace.
        
        Returns:
            List of OAuth 2.0 scope URLs covering all Google Workspace services
        """
        return [
            # Gmail
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/gmail.labels',
            
            # Calendar
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/calendar.events',
            
            # Drive
            'https://www.googleapis.com/auth/drive',
            'https://www.googleapis.com/auth/drive.file',
            'https://www.googleapis.com/auth/drive.metadata',
            
            # Docs
            'https://www.googleapis.com/auth/documents',
            
            # Sheets
            'https://www.googleapis.com/auth/spreadsheets',
            
            # Slides
            'https://www.googleapis.com/auth/presentations',
            
            # Chat
            'https://www.googleapis.com/auth/chat.messages',
            'https://www.googleapis.com/auth/chat.spaces',
            
            # Forms
            'https://www.googleapis.com/auth/forms.body',
            'https://www.googleapis.com/auth/forms.responses.readonly',
            
            # Tasks
            'https://www.googleapis.com/auth/tasks',
            
            # Search
            'https://www.googleapis.com/auth/cse',
            
            # User Info
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'openid'
        ]
    
    def _build_credentials(self) -> Credentials:
        """
        Build Google API credentials from bearer token.
        
        Note: No refresh token since external service (OAuth Proxy) 
        handles token refresh.
        
        Returns:
            Google OAuth 2.0 Credentials object
        """
        from datetime import datetime, timedelta
        
        # Set expiry far in the future since external service handles refresh
        # This prevents Google auth library from trying to refresh the token
        expiry = datetime.utcnow() + timedelta(hours=24)
        
        return Credentials(
            token=self.access_token,
            refresh_token=None,  # External service handles refresh
            token_uri=None,
            client_id=None,
            client_secret=None,
            scopes=self.scopes,
            expiry=expiry  # Set expiry to prevent auto-refresh attempts
        )
    
    def get_credentials(self) -> Credentials:
        """
        Get credentials for Google API calls.
        
        Returns:
            Google OAuth 2.0 Credentials object ready for API use
        """
        return self.credentials
    
    def validate_token(self) -> bool:
        """
        Validate token works with Google APIs.
        
        Uses the tokeninfo endpoint which doesn't require People API to be enabled.
        This is more reliable for server-side OAuth integrations.
        
        Returns:
            True if token is valid and can make API calls, False otherwise
        """
        try:
            # Use tokeninfo endpoint (doesn't require People API)
            import requests
            response = requests.get(
                f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={self.access_token}",
                timeout=5
            )
            
            if response.status_code == 200:
                token_info = response.json()
                # Store basic user info from token validation
                self.user_info = {
                    'email': token_info.get('email', 'unknown'),
                    'id': token_info.get('sub', 'unknown')
                }
                
                logger.info(
                    "Bearer token validated successfully",
                    extra={
                        "user_email": self.user_info.get('email'),
                        "expires_in": token_info.get('expires_in'),
                        "scope_count": len(token_info.get('scope', '').split())
                    }
                )
                return True
            else:
                logger.error(
                    "Bearer token validation failed - HTTP error",
                    extra={
                        "status_code": response.status_code,
                        "error": response.text[:200]
                    }
                )
                return False
            
        except Exception as e:
            logger.error(
                "Bearer token validation failed",
                extra={
                    "error": str(e),
                    "error_type": type(e).__name__
                },
                exc_info=True
            )
            return False
    
    def get_user_info(self) -> dict:
        """
        Get user info for the authenticated token.
        
        Returns:
            User info dict with email, id, etc.
            
        Raises:
            Exception: If tokeninfo API call fails
        """
        if not self.user_info:
            # Use tokeninfo endpoint (doesn't require People API)
            import requests
            response = requests.get(
                f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={self.access_token}",
                timeout=5
            )
            
            if response.status_code == 200:
                token_info = response.json()
                self.user_info = {
                    'email': token_info.get('email', 'unknown'),
                    'id': token_info.get('sub', 'unknown')
                }
            else:
                raise Exception(f"Failed to get user info: HTTP {response.status_code}")
                
        return self.user_info
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        email = self.user_info.get('email') if self.user_info else 'unknown'
        return f"ExternalTokenProvider(user={email})"


# Convenience function for getting credentials from environment variable
def get_credentials_from_env(
    validate: bool = True
) -> Optional[Credentials]:
    """
    Get credentials from GOOGLE_BEARER_TOKEN environment variable.
    
    This is a convenience function for quickly creating credentials
    from an environment variable without explicitly creating an
    ExternalTokenProvider instance.
    
    Args:
        validate: Whether to validate the token (default: True)
        
    Returns:
        Credentials object if token is present and valid, None otherwise
        
    Example:
        ```python
        import os
        os.environ['GOOGLE_BEARER_TOKEN'] = 'ya29.a0ARrdaM...'
        
        credentials = get_credentials_from_env()
        if credentials:
            service = build('gmail', 'v1', credentials=credentials)
        ```
    """
    import os
    
    token = os.getenv('GOOGLE_BEARER_TOKEN')
    if not token:
        logger.warning("GOOGLE_BEARER_TOKEN environment variable not set")
        return None
    
    try:
        provider = ExternalTokenProvider(
            access_token=token,
            validate=validate
        )
        return provider.get_credentials()
    except ValueError as e:
        logger.error(f"Failed to create credentials from environment: {e}")
        return None

