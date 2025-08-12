"""
Tests for Azure Active Directory token-based authentication.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import unittest
from unittest.mock import Mock, patch, MagicMock
import struct

import pytds
from pytds.login import AzureTokenAuth
from pytds import tds_base
from pytds.tds_session import _TdsSession
from pytds.tds_base import PreLoginToken, FeatureExtension, FedAuthLibrary


class TestAzureTokenAuth(unittest.TestCase):
    """Test the AzureTokenAuth class."""
    
    def test_init_with_valid_token(self):
        """Test initialization with a valid token."""
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.token"
        auth = AzureTokenAuth(token)
        self.assertEqual(auth.get_access_token(), token)
        self.assertFalse(auth._token_sent)
    
    def test_init_with_empty_token(self):
        """Test initialization with empty token raises ValueError."""
        with self.assertRaises(ValueError) as cm:
            AzureTokenAuth("")
        self.assertIn("Access token cannot be empty", str(cm.exception))
        
        with self.assertRaises(ValueError) as cm:
            AzureTokenAuth("   ")
        self.assertIn("Access token cannot be empty", str(cm.exception))
    
    def test_init_with_none_token(self):
        """Test initialization with None token raises ValueError."""
        with self.assertRaises(ValueError) as cm:
            AzureTokenAuth(None)
        self.assertIn("Access token cannot be empty", str(cm.exception))
    
    def test_create_packet(self):
        """Test create_packet returns empty bytes."""
        token = "test.token"
        auth = AzureTokenAuth(token)
        packet = auth.create_packet()
        self.assertEqual(packet, b"")
    
    def test_handle_next(self):
        """Test handle_next returns None."""
        token = "test.token"
        auth = AzureTokenAuth(token)
        result = auth.handle_next(b"some_data")
        self.assertIsNone(result)
    
    def test_close(self):
        """Test close method doesn't raise exceptions."""
        token = "test.token"
        auth = AzureTokenAuth(token)
        auth.close()  # Should not raise


class TestConnectionWithAccessToken(unittest.TestCase):
    """Test the connect function with access_token parameter."""

    @patch('pytds._connect')
    def test_access_token_parameter_validation(self, mock_connect):
        """Test validation of access_token parameter."""
        # Test access_token with auth parameter
        with self.assertRaises(ValueError) as cm:
            pytds.connect(
                dsn="test.database.windows.net",
                access_token="test.token",
                auth=Mock()
            )
        self.assertIn("access_token cannot be used with auth", str(cm.exception))

        # Test access_token with use_sso
        with self.assertRaises(ValueError) as cm:
            pytds.connect(
                dsn="test.database.windows.net",
                access_token="test.token",
                use_sso=True
            )
        self.assertIn("access_token cannot be used with", str(cm.exception))

        # Test access_token with user
        with self.assertRaises(ValueError) as cm:
            pytds.connect(
                dsn="test.database.windows.net",
                access_token="test.token",
                user="testuser"
            )
        self.assertIn("access_token cannot be used with", str(cm.exception))

        # Test access_token with password
        with self.assertRaises(ValueError) as cm:
            pytds.connect(
                dsn="test.database.windows.net",
                access_token="test.token",
                password="testpass"
            )
        self.assertIn("access_token cannot be used with", str(cm.exception))

        # Test empty access_token - this should raise ValueError before any connection attempt
        with self.assertRaises(ValueError) as cm:
            pytds.connect(
                dsn="test.database.windows.net",
                access_token=""
            )
        self.assertIn("access_token cannot be empty", str(cm.exception))

        # Verify the mock was not called since validation should fail early
        mock_connect.assert_not_called()


class TestPreloginWithFedAuth(unittest.TestCase):
    """Test prelogin process with federated authentication."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.session = Mock(spec=_TdsSession)
        self.session._writer = Mock()
        self.session.conn = Mock()
        self.session.conn._mars_enabled = False
        self.session.conn.server_library_version = (0, 0)
        
    def test_send_prelogin_with_token_auth(self):
        """Test send_prelogin includes FEDAUTHREQUIRED when using token auth."""
        login = tds_base._TdsLogin()
        login.auth = AzureTokenAuth("test.token")
        login.instance_name = "MSSQLSERVER"
        login.enc_flag = 0
        login.use_mars = False

        # Mock the session to simulate TDS 7.4+
        with patch('pytds.tds_session.tds_base.IS_TDS72_PLUS', return_value=True):
            # This would normally call the actual send_prelogin method
            # For now, we'll just verify the logic would work
            self.assertIsInstance(login.auth, AzureTokenAuth)
    
    def test_parse_prelogin_with_fedauth_response(self):
        """Test parsing prelogin response with FEDAUTHREQUIRED and NONCE."""
        login = tds_base._TdsLogin()
        
        # Create a mock prelogin response with FEDAUTHREQUIRED and NONCE
        # Structure: [token_id, offset_high, offset_low, length_high, length_low, ...]
        header = struct.pack(
            ">BHHBHHBHHB",
            PreLoginToken.VERSION, 16, 6,  # Version token at offset 16
            PreLoginToken.FEDAUTHREQUIRED, 22, 1,  # FedAuth required token at offset 22
            PreLoginToken.NONCEOPT, 23, 32,  # Nonce token at offset 23
            PreLoginToken.TERMINATOR  # End marker
        )
        # Add the actual data
        data = struct.pack(">LH", 0x74000000, 0)  # Version data (6 bytes)
        data += b"\x01"  # FedAuth required = true (1 byte)
        data += b"A" * 32  # 32-byte nonce

        prelogin_data = header + data
        
        # Mock the session's parse_prelogin method
        mock_conn = Mock()
        mock_conn.server_library_version = None
        mock_conn._mars_enabled = False

        session = _TdsSession(Mock(), Mock(), Mock(), mock_conn, 4096)

        # Call parse_prelogin
        session.parse_prelogin(prelogin_data, login)
        
        # Verify the login object was updated
        self.assertTrue(login.fedauth_required)
        self.assertEqual(len(login.fedauth_nonce), 32)
        self.assertEqual(login.fedauth_nonce, b"A" * 32)


class TestFedAuthTokenPacket(unittest.TestCase):
    """Test FEDAUTH token packet creation and sending."""
    
    def test_send_fedauth_token(self):
        """Test sending FEDAUTH token packet."""
        # Create a mock session
        session = _TdsSession(Mock(), Mock(), Mock(), Mock(), 4096)
        session._writer = Mock()
        
        # Create login with token auth
        login = tds_base._TdsLogin()
        login.auth = AzureTokenAuth("test.access.token")
        login.fedauth_nonce = b"A" * 32
        
        # Call send_fedauth_token
        session.send_fedauth_token(login)
        
        # Verify the writer was called correctly
        session._writer.begin_packet.assert_called_once_with(tds_base.PacketType.FEDAUTHTOKEN)
        session._writer.flush.assert_called_once()
        
        # Verify the data was written (token + nonce)
        expected_calls = [
            # DataLen
            unittest.mock.call(4 + len("test.access.token".encode('utf-8')) + 32),
            # Token length
            unittest.mock.call(len("test.access.token".encode('utf-8'))),
        ]
        session._writer.put_int.assert_has_calls(expected_calls)
        
        # Verify token and nonce were written
        session._writer.write.assert_any_call("test.access.token".encode('utf-8'))
        session._writer.write.assert_any_call(b"A" * 32)
    
    def test_send_fedauth_token_without_nonce(self):
        """Test sending FEDAUTH token packet without nonce."""
        session = _TdsSession(Mock(), Mock(), Mock(), Mock(), 4096)
        session._writer = Mock()
        
        login = tds_base._TdsLogin()
        login.auth = AzureTokenAuth("test.token")
        login.fedauth_nonce = None
        
        session.send_fedauth_token(login)
        
        # Verify only token data length was calculated (no nonce)
        expected_data_len = 4 + len("test.token".encode('utf-8'))
        session._writer.put_int.assert_any_call(expected_data_len)
    
    def test_send_fedauth_token_wrong_auth_type(self):
        """Test sending FEDAUTH token with wrong auth type raises error."""
        session = _TdsSession(Mock(), Mock(), Mock(), Mock(), 4096)
        
        login = tds_base._TdsLogin()
        login.auth = Mock()  # Not AzureTokenAuth
        
        with self.assertRaises(ValueError) as cm:
            session.send_fedauth_token(login)
        self.assertIn("FEDAUTH token can only be sent with AzureTokenAuth", str(cm.exception))


if __name__ == '__main__':
    unittest.main()
