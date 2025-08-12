#!/usr/bin/env python3
"""
Manual integration test for Azure Active Directory token authentication.

This test requires:
1. An Azure SQL Database instance
2. A valid Azure AD access token
3. Proper network connectivity to Azure

Run this test manually with:
    python tests/manual_azure_token_test.py

Set environment variables:
    AZURE_SQL_SERVER=your-server.database.windows.net
    AZURE_SQL_DATABASE=your-database
    AZURE_ACCESS_TOKEN=your-access-token

Or use Azure CLI to get a token:
    az account get-access-token --resource https://database.windows.net/
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytds
import json
import subprocess


def get_token_from_cli():
    """Get access token using Azure CLI."""
    try:
        result = subprocess.run([
            'az', 'account', 'get-access-token', 
            '--resource', 'https://database.windows.net/'
        ], capture_output=True, text=True, check=True)
        
        token_info = json.loads(result.stdout)
        return token_info['accessToken']
    except subprocess.CalledProcessError as e:
        print(f"Azure CLI failed: {e}")
        print("Make sure you're logged in with 'az login'")
        return None
    except Exception as e:
        print(f"Error getting token from CLI: {e}")
        return None


def test_azure_token_connection():
    """Test connection to Azure SQL Database using token authentication."""
    
    # Get connection parameters from environment or use defaults
    server = os.getenv('AZURE_SQL_SERVER', 'your-server.database.windows.net')
    database = os.getenv('AZURE_SQL_DATABASE', 'your-database')
    access_token = os.getenv('AZURE_ACCESS_TOKEN')
    
    # If no token provided, try to get one from Azure CLI
    if not access_token:
        print("No AZURE_ACCESS_TOKEN environment variable found.")
        print("Attempting to get token from Azure CLI...")
        access_token = get_token_from_cli()
        
        if not access_token:
            print("Could not obtain access token.")
            print("Please set AZURE_ACCESS_TOKEN environment variable or login with 'az login'")
            return False
    
    print(f"Testing connection to: {server}")
    print(f"Database: {database}")
    print(f"Token length: {len(access_token)} characters")
    
    try:
        # Test the connection
        with pytds.connect(
            dsn=server,
            database=database,
            access_token=access_token,
            timeout=30
        ) as conn:
            print("✓ Connection successful!")
            
            with conn.cursor() as cur:
                # Test basic query
                cur.execute("SELECT CURRENT_USER, SYSTEM_USER, GETDATE()")
                result = cur.fetchone()
                print(f"✓ Query successful!")
                print(f"  Current User: {result[0]}")
                print(f"  System User: {result[1]}")
                print(f"  Current Time: {result[2]}")
                
                # Test another query to verify the connection is stable
                cur.execute("SELECT @@VERSION")
                version = cur.fetchone()[0]
                print(f"✓ Server version: {version[:100]}...")
                
        print("✓ Connection closed successfully!")
        return True
        
    except Exception as e:
        print(f"✗ Connection failed: {type(e).__name__}: {e}")
        return False


def test_validation_errors():
    """Test that validation errors are properly raised."""
    print("\nTesting validation errors:")
    
    test_cases = [
        ("Empty token", ""),
        ("Whitespace token", "   "),
        ("Token with user conflict", "valid-token", {"user": "testuser"}),
        ("Token with password conflict", "valid-token", {"password": "testpass"}),
        ("Token with auth conflict", "valid-token", {"auth": pytds.login.SspiAuth("test")}),
    ]
    
    for description, token, extra_params in [(tc[0], tc[1], tc[2] if len(tc) > 2 else {}) for tc in test_cases]:
        try:
            params = {
                'dsn': 'test-server.database.windows.net',
                'database': 'test-db',
                'access_token': token,
                **extra_params
            }
            
            # This should raise ValueError before attempting connection
            pytds.connect(**params)
            print(f"✗ {description}: No error raised (unexpected)")
            
        except ValueError as e:
            print(f"✓ {description}: {e}")
        except Exception as e:
            print(f"? {description}: Unexpected error: {type(e).__name__}: {e}")


def main():
    """Main test function."""
    print("Azure Active Directory Token Authentication Test")
    print("=" * 50)
    
    # Test validation first
    test_validation_errors()
    
    # Test actual connection if parameters are available
    print("\n" + "=" * 50)
    print("Integration Test")
    print("=" * 50)
    
    if len(sys.argv) > 1 and sys.argv[1] == '--skip-integration':
        print("Skipping integration test (--skip-integration flag provided)")
        return
    
    server = os.getenv('AZURE_SQL_SERVER')
    database = os.getenv('AZURE_SQL_DATABASE')
    token = os.getenv('AZURE_ACCESS_TOKEN')
    
    if not server or not database:
        print("Integration test requires environment variables:")
        print("  AZURE_SQL_SERVER=your-server.database.windows.net")
        print("  AZURE_SQL_DATABASE=your-database")
        print("  AZURE_ACCESS_TOKEN=your-token (optional, will try Azure CLI)")
        print("\nRun with --skip-integration to skip this test")
        return
    
    success = test_azure_token_connection()
    
    if success:
        print("\n🎉 All tests passed! Azure token authentication is working correctly.")
    else:
        print("\n❌ Integration test failed. Check your connection parameters and token.")


if __name__ == '__main__':
    main()
