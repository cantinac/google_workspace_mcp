"""
Unit tests for ExternalTokenProvider

Tests the bearer token authentication provider for integration with
external OAuth services like IMF OAuth Proxy.
"""

import os
import pytest
from unittest.mock import Mock, patch, MagicMock

# Import the module under test
from auth.external_token_provider import (
    ExternalTokenProvider,
    get_credentials_from_env
)


class TestExternalTokenProvider:
    """Test suite for ExternalTokenProvider class."""
    
    def test_init_with_valid_token(self):
        """Test initialization with a valid token (no validation)."""
        token = "ya29.test_token_12345"
        
        with patch.object(ExternalTokenProvider, 'validate_token', return_value=True):
            provider = ExternalTokenProvider(access_token=token, validate=True)
            
            assert provider.access_token == token
            assert provider.credentials.token == token
            assert provider.credentials.refresh_token is None
    
    def test_init_without_validation(self):
        """Test initialization without token validation."""
        token = "ya29.test_token_12345"
        provider = ExternalTokenProvider(access_token=token, validate=False)
        
        assert provider.access_token == token
        assert provider.credentials.token == token
    
    def test_init_empty_token_raises_error(self):
        """Test that empty token raises ValueError."""
        with pytest.raises(ValueError, match="access_token is required"):
            ExternalTokenProvider(access_token="", validate=False)
    
    def test_init_invalid_token_raises_error(self):
        """Test that invalid token raises ValueError when validated."""
        token = "ya29.invalid_token"
        
        with patch.object(ExternalTokenProvider, 'validate_token', return_value=False):
            with pytest.raises(ValueError, match="Invalid or expired bearer token"):
                ExternalTokenProvider(access_token=token, validate=True)
    
    def test_get_credentials_returns_credentials_object(self):
        """Test that get_credentials returns a Credentials object."""
        token = "ya29.test_token_12345"
        provider = ExternalTokenProvider(access_token=token, validate=False)
        
        credentials = provider.get_credentials()
        
        assert credentials is not None
        assert credentials.token == token
        assert credentials.refresh_token is None
    
    def test_validate_token_success(self):
        """Test successful token validation."""
        token = "ya29.valid_token_12345"
        response = Mock(status_code=200)
        response.json.return_value = {"email": "test@example.com", "sub": "123456"}

        with patch("requests.get", return_value=response):
            provider = ExternalTokenProvider(access_token=token, validate=False)
            result = provider.validate_token()

            assert result is True
            assert provider.user_info == {"email": "test@example.com", "id": "123456"}

    def test_validate_token_http_error(self):
        """Test token validation with HTTP error."""
        token = "ya29.expired_token"
        response = Mock(status_code=401, text='{"error": "invalid_token"}')

        with patch("requests.get", return_value=response):
            provider = ExternalTokenProvider(access_token=token, validate=False)
            result = provider.validate_token()

            assert result is False
            assert provider.user_info is None

    def test_validate_token_generic_exception(self):
        """Test token validation with generic exception."""
        token = "ya29.test_token"
        
        with patch('auth.external_token_provider.build') as mock_build:
            mock_service = Mock()
            mock_service.userinfo().get().execute.side_effect = Exception("Connection error")
            mock_build.return_value = mock_service
            
            provider = ExternalTokenProvider(access_token=token, validate=False)
            result = provider.validate_token()
            
            assert result is False
    
    def test_get_user_info_cached(self):
        """Test that get_user_info returns cached user info."""
        token = "ya29.test_token"
        mock_user_info = {"email": "test@example.com", "id": "123456"}
        
        provider = ExternalTokenProvider(access_token=token, validate=False)
        provider.user_info = mock_user_info
        
        result = provider.get_user_info()
        
        assert result == mock_user_info
    
    def test_get_user_info_fetch_on_demand(self):
        """Test that get_user_info fetches user info if not cached."""
        token = "ya29.test_token"
        response = Mock(status_code=200)
        response.json.return_value = {"email": "test@example.com", "sub": "123456"}

        with patch("requests.get", return_value=response):
            provider = ExternalTokenProvider(access_token=token, validate=False)
            result = provider.get_user_info()

            assert result == {"email": "test@example.com", "id": "123456"}
            assert provider.user_info == result

    def test_get_default_scopes_includes_all_services(self):
        """Test that default scopes include all Google Workspace services."""
        token = "ya29.test_token"
        provider = ExternalTokenProvider(access_token=token, validate=False)
        
        scopes = provider._get_default_scopes()
        
        # Check for key service scopes
        assert 'https://www.googleapis.com/auth/gmail.modify' in scopes
        assert 'https://www.googleapis.com/auth/calendar' in scopes
        assert 'https://www.googleapis.com/auth/drive' in scopes
        assert 'https://www.googleapis.com/auth/documents' in scopes
        assert 'https://www.googleapis.com/auth/spreadsheets' in scopes
        assert 'https://www.googleapis.com/auth/presentations' in scopes
        assert 'https://www.googleapis.com/auth/userinfo.email' in scopes
    
    def test_repr(self):
        """Test string representation."""
        token = "ya29.test_token"
        mock_user_info = {"email": "test@example.com"}
        
        provider = ExternalTokenProvider(access_token=token, validate=False)
        provider.user_info = mock_user_info
        
        repr_str = repr(provider)
        
        assert "ExternalTokenProvider" in repr_str
        assert "test@example.com" in repr_str


class TestGetCredentialsFromEnv:
    """Test suite for get_credentials_from_env convenience function."""
    
    def test_with_valid_env_token(self):
        """Test getting credentials from environment variable."""
        token = "ya29.env_token_12345"
        
        with patch.dict(os.environ, {'GOOGLE_BEARER_TOKEN': token}):
            with patch.object(ExternalTokenProvider, 'validate_token', return_value=True):
                credentials = get_credentials_from_env(validate=True)
                
                assert credentials is not None
                assert credentials.token == token
    
    def test_without_env_token(self):
        """Test that None is returned when environment variable is not set."""
        with patch.dict(os.environ, {}, clear=True):
            credentials = get_credentials_from_env(validate=False)
            
            assert credentials is None
    
    def test_with_invalid_env_token(self):
        """Test that None is returned when token validation fails."""
        token = "ya29.invalid_env_token"
        
        with patch.dict(os.environ, {'GOOGLE_BEARER_TOKEN': token}):
            with patch.object(ExternalTokenProvider, 'validate_token', return_value=False):
                credentials = get_credentials_from_env(validate=True)
                
                assert credentials is None
    
    def test_without_validation(self):
        """Test getting credentials without validation."""
        token = "ya29.env_token_no_validation"
        
        with patch.dict(os.environ, {'GOOGLE_BEARER_TOKEN': token}):
            credentials = get_credentials_from_env(validate=False)
            
            assert credentials is not None
            assert credentials.token == token


# Integration-style tests (can be run with actual tokens in development)
class TestExternalTokenProviderIntegration:
    """
    Integration tests for ExternalTokenProvider.
    
    These tests are skipped unless GOOGLE_BEARER_TOKEN_TEST is set with a real token.
    Use for manual testing with actual Google OAuth tokens.
    """
    
    @pytest.mark.skipif(
        'GOOGLE_BEARER_TOKEN_TEST' not in os.environ,
        reason="Requires GOOGLE_BEARER_TOKEN_TEST environment variable with real token"
    )
    def test_real_token_validation(self):
        """Test with a real Google OAuth token (manual test only)."""
        token = os.getenv('GOOGLE_BEARER_TOKEN_TEST')
        
        provider = ExternalTokenProvider(access_token=token, validate=True)
        
        assert provider.user_info is not None
        assert 'email' in provider.user_info
        assert provider.validate_token() is True
    
    @pytest.mark.skipif(
        'GOOGLE_BEARER_TOKEN_TEST' not in os.environ,
        reason="Requires GOOGLE_BEARER_TOKEN_TEST environment variable with real token"
    )
    def test_real_token_get_user_info(self):
        """Test getting user info with a real token (manual test only)."""
        token = os.getenv('GOOGLE_BEARER_TOKEN_TEST')
        
        provider = ExternalTokenProvider(access_token=token, validate=False)
        user_info = provider.get_user_info()
        
        assert user_info is not None
        assert 'email' in user_info
        assert '@' in user_info['email']


class TestBearerTokenUserEmail:
    """The bearer token's account stands in for the user_google_email argument."""

    @pytest.fixture(autouse=True)
    def _clean(self, monkeypatch):
        from auth import external_token_provider

        external_token_provider._bearer_email_cache.clear()
        monkeypatch.setenv("GOOGLE_BEARER_TOKEN", "ya29.test_token")
        yield
        external_token_provider._bearer_email_cache.clear()

    @staticmethod
    def _response(status, payload=None):
        response = Mock(status_code=status)
        response.json.return_value = payload or {}
        return response

    def test_mode_flag(self, monkeypatch):
        from auth.external_token_provider import is_bearer_token_mode

        monkeypatch.delenv("MCP_BEARER_TOKEN_MODE", raising=False)
        assert is_bearer_token_mode() is False
        monkeypatch.setenv("MCP_BEARER_TOKEN_MODE", "1")
        assert is_bearer_token_mode() is True

    def test_email_from_tokeninfo_is_cached(self):
        from auth.external_token_provider import get_bearer_token_user_email

        with patch("requests.post", return_value=self._response(200, {"email": "a@example.com"})) as post, \
                patch("requests.get") as get:
            assert get_bearer_token_user_email() == "a@example.com"
            assert get_bearer_token_user_email() == "a@example.com"
        assert post.call_count == 1
        assert get.call_count == 0

    def test_falls_back_to_gmail_then_drive(self):
        from auth.external_token_provider import get_bearer_token_user_email

        def get(url, **_):
            if "gmail" in url:
                return self._response(403)
            return self._response(200, {"user": {"emailAddress": "d@example.com"}})

        # tokeninfo answers but the token carries no email scope.
        with patch("requests.post", return_value=self._response(200, {"scope": "drive"})), \
                patch("requests.get", side_effect=get):
            assert get_bearer_token_user_email() == "d@example.com"

    def test_no_address_raises(self):
        from auth.external_token_provider import get_bearer_token_user_email

        with patch("requests.post", return_value=self._response(400)), \
                patch("requests.get", return_value=self._response(401)):
            with pytest.raises(ValueError, match="Could not determine"):
                get_bearer_token_user_email()

    def test_no_token_raises(self, monkeypatch):
        from auth.external_token_provider import get_bearer_token_user_email

        monkeypatch.delenv("GOOGLE_BEARER_TOKEN")
        with pytest.raises(ValueError, match="GOOGLE_BEARER_TOKEN"):
            get_bearer_token_user_email()

    def test_managed_email_comes_from_the_token(self, monkeypatch):
        from auth import service_decorator

        monkeypatch.setenv("MCP_BEARER_TOKEN_MODE", "1")
        monkeypatch.setattr(service_decorator, "get_bearer_token_user_email", lambda: "a@example.com")
        assert service_decorator._user_email_is_managed() is True
        assert service_decorator._extract_managed_user_email(None, None, "tool") == "a@example.com"
