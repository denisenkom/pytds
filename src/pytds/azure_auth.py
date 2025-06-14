"""
Azure AD authentication support for pytds.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from pytds.tds_base import AuthProtocol

logger = logging.getLogger(__name__)


class AzureTokenAuth(AuthProtocol):
    """Azure AD Token Authentication
    
    This class implements Azure AD token authentication for Azure SQL Database.
    It allows authentication using an access token obtained from Azure AD.
    
    :param token: Azure AD access token (JWT)
    :type token: str
    :param token_callback: Optional callable that returns a token string. 
                          If provided, will be called to get a fresh token when needed.
    :type token_callback: Callable[[], str], optional
    """
    
    def __init__(self, token: str = "", token_callback: Optional[Callable[[], str]] = None):
        if not token and not token_callback:
            raise ValueError("Either token or token_callback must be provided")
        self._token = token
        self._token_callback = token_callback
        self._token_used = False
    
    def _get_token(self) -> str:
        """Get the current token, calling the callback if needed"""
        if self._token_used and self._token_callback:
            self._token = self._token_callback()
            self._token_used = False
        return self._token
    
    def create_packet(self) -> bytes:
        """Create the initial authentication packet with the token"""
        token = self._get_token()
        if not token:
            raise ValueError("No token available for authentication")
        
        # The token is sent as a UTF-16LE encoded string with a 4-byte length prefix
        token_bytes = token.encode('utf-16le')
        packet = len(token_bytes).to_bytes(4, 'little') + token_bytes
        self._token_used = True  # Mark token as used for this authentication attempt
        return packet
    
    def handle_next(self, packet: bytes) -> bytes | None:
        """Handle server response - not expecting any further tokens"""
        # Azure SQL should not send any challenge after receiving the token
        if packet:
            logger.warning("Unexpected data received during Azure AD token authentication")
        return None
    
    def close(self) -> None:
        """Clean up any resources"""
        # Clear the token from memory when done
        self._token = ""
        self._token_used = True
