import pytest
import pytds
from pytds.tds_base import TDS70, TDS71, TDS72, TDS73, TDS74


class TestAccessTokenValidation:
    """Tests for access_token parameter validation in connect()"""
    
    def test_empty_access_token_raises_error(self):
        """Test that empty access_token raises ValueError"""
        with pytest.raises(ValueError) as excinfo:
            pytds.connect(
                dsn="localhost",
                user="testuser",
                password="password",
                access_token="",  # Empty token should raise error
                disable_connect_retry=True,
            )
        assert str(excinfo.value) == "access_token cannot be an empty string"
    
    def test_access_token_requires_tds74_or_higher(self):
        """Test that access_token requires TDS 7.4 or higher"""
        # Test with TDS 7.0
        with pytest.raises(ValueError) as excinfo:
            pytds.connect(
                dsn="localhost",
                user="testuser",
                password="password",
                access_token="valid_token",
                tds_version=TDS70,
                disable_connect_retry=True,
            )
        assert str(excinfo.value) == "access_token requires TDS 7.4 or higher"
        
        # Test with TDS 7.1
        with pytest.raises(ValueError) as excinfo:
            pytds.connect(
                dsn="localhost",
                user="testuser",
                password="password",
                access_token="valid_token",
                tds_version=TDS71,
                disable_connect_retry=True,
            )
        assert str(excinfo.value) == "access_token requires TDS 7.4 or higher"
        
        # Test with TDS 7.2
        with pytest.raises(ValueError) as excinfo:
            pytds.connect(
                dsn="localhost",
                user="testuser",
                password="password",
                access_token="valid_token",
                tds_version=TDS72,
                disable_connect_retry=True,
            )
        assert str(excinfo.value) == "access_token requires TDS 7.4 or higher"
        
        # Test with TDS 7.3
        with pytest.raises(ValueError) as excinfo:
            pytds.connect(
                dsn="localhost",
                user="testuser",
                password="password",
                access_token="valid_token",
                tds_version=TDS73,
                disable_connect_retry=True,
            )
        assert str(excinfo.value) == "access_token requires TDS 7.4 or higher"
    
    def test_valid_access_token_with_tds74_does_not_raise(self):
        """Test that valid access_token with TDS 7.4 passes validation"""
        # This test verifies that the validation passes, but the connection
        # will fail later due to invalid server - we just want to ensure
        # the validation doesn't raise
        try:
            pytds.connect(
                dsn="localhost",
                user="testuser",
                password="password",
                access_token="valid_token",
                tds_version=TDS74,
                disable_connect_retry=True,
                login_timeout=0.1,  # Quick timeout since we expect connection to fail
            )
        except pytds.LoginError:
            # Expected - connection will fail, but validation should have passed
            pass
        except ValueError:
            # If we get ValueError, the validation failed when it shouldn't have
            pytest.fail("Validation raised ValueError when it should have passed")
