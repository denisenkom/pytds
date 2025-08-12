#!/usr/bin/env python3
"""
Examples of using Azure Active Directory token-based authentication with pytds.

This module demonstrates various ways to authenticate to Azure SQL Database
using Azure AD access tokens instead of traditional username/password authentication.
"""

import pytds
import os
import sys


def example_with_hardcoded_token():
    """
    Example using a hardcoded access token.
    
    Note: This is for demonstration only. In production, never hardcode tokens
    in your source code. Use secure methods to obtain and store tokens.
    """
    print("Example 1: Using hardcoded access token")
    
    # This would be your actual access token from Azure AD
    access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."  # Placeholder token
    
    try:
        with pytds.connect(
            dsn='your-server.database.windows.net',
            database='your-database',
            access_token=access_token
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT CURRENT_USER, GETDATE()")
                result = cur.fetchone()
                print(f"Connected as: {result[0]} at {result[1]}")
    except Exception as e:
        print(f"Connection failed: {e}")


def example_with_azure_identity():
    """
    Example using Azure Identity library to obtain tokens automatically.
    
    This works with:
    - Managed Identity (when running in Azure)
    - Service Principal (with environment variables)
    - Azure CLI authentication
    - Visual Studio authentication
    - And more...
    
    Install: pip install azure-identity
    """
    print("Example 2: Using Azure Identity library")
    
    try:
        from azure.identity import DefaultAzureCredential
        
        # DefaultAzureCredential tries multiple authentication methods
        credential = DefaultAzureCredential()
        
        # Get token for Azure SQL Database
        token = credential.get_token("https://database.windows.net/.default")
        
        with pytds.connect(
            dsn='your-server.database.windows.net',
            database='your-database',
            access_token=token.token
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT CURRENT_USER, SYSTEM_USER")
                result = cur.fetchone()
                print(f"Connected as: {result[0]} (system user: {result[1]})")
                
    except ImportError:
        print("Azure Identity library not installed. Run: pip install azure-identity")
    except Exception as e:
        print(f"Connection failed: {e}")


def example_with_service_principal():
    """
    Example using Service Principal authentication.
    
    Set these environment variables:
    - AZURE_CLIENT_ID: Your service principal's client ID
    - AZURE_CLIENT_SECRET: Your service principal's client secret  
    - AZURE_TENANT_ID: Your Azure AD tenant ID
    """
    print("Example 3: Using Service Principal")
    
    try:
        from azure.identity import ClientSecretCredential
        
        client_id = os.getenv('AZURE_CLIENT_ID')
        client_secret = os.getenv('AZURE_CLIENT_SECRET')
        tenant_id = os.getenv('AZURE_TENANT_ID')
        
        if not all([client_id, client_secret, tenant_id]):
            print("Missing environment variables: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID")
            return
        
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        token = credential.get_token("https://database.windows.net/.default")
        
        with pytds.connect(
            dsn='your-server.database.windows.net',
            database='your-database',
            access_token=token.token
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT CURRENT_USER")
                result = cur.fetchone()
                print(f"Connected as service principal: {result[0]}")
                
    except ImportError:
        print("Azure Identity library not installed. Run: pip install azure-identity")
    except Exception as e:
        print(f"Connection failed: {e}")


def example_with_managed_identity():
    """
    Example using Managed Identity (for applications running in Azure).
    
    This works automatically when your application is running in:
    - Azure Virtual Machines
    - Azure App Service
    - Azure Functions
    - Azure Container Instances
    - Azure Kubernetes Service
    """
    print("Example 4: Using Managed Identity")
    
    try:
        from azure.identity import ManagedIdentityCredential
        
        # Use system-assigned managed identity
        credential = ManagedIdentityCredential()
        
        # Or use user-assigned managed identity
        # credential = ManagedIdentityCredential(client_id="your-user-assigned-identity-client-id")
        
        token = credential.get_token("https://database.windows.net/.default")
        
        with pytds.connect(
            dsn='your-server.database.windows.net',
            database='your-database',
            access_token=token.token
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT CURRENT_USER")
                result = cur.fetchone()
                print(f"Connected using managed identity: {result[0]}")
                
    except ImportError:
        print("Azure Identity library not installed. Run: pip install azure-identity")
    except Exception as e:
        print(f"Connection failed: {e}")


def example_with_azure_cli():
    """
    Example using Azure CLI to get access token.
    
    Prerequisites:
    1. Install Azure CLI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
    2. Login: az login
    3. Get token: az account get-access-token --resource https://database.windows.net/
    """
    print("Example 5: Using Azure CLI token")
    
    import subprocess
    import json
    
    try:
        # Get token using Azure CLI
        result = subprocess.run([
            'az', 'account', 'get-access-token', 
            '--resource', 'https://database.windows.net/'
        ], capture_output=True, text=True, check=True)
        
        token_info = json.loads(result.stdout)
        access_token = token_info['accessToken']
        
        with pytds.connect(
            dsn='your-server.database.windows.net',
            database='your-database',
            access_token=access_token
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT CURRENT_USER")
                result = cur.fetchone()
                print(f"Connected using Azure CLI token: {result[0]}")
                
    except subprocess.CalledProcessError as e:
        print(f"Azure CLI command failed: {e}")
        print("Make sure you're logged in with 'az login'")
    except Exception as e:
        print(f"Connection failed: {e}")


def example_error_handling():
    """
    Example showing proper error handling for token authentication.
    """
    print("Example 6: Error handling")
    
    # Test various error conditions
    test_cases = [
        ("Empty token", ""),
        ("None token", None),
        ("Token with auth conflict", "valid-token"),
    ]
    
    for description, token in test_cases:
        print(f"\nTesting: {description}")
        try:
            if description == "Token with auth conflict":
                # This should raise ValueError
                pytds.connect(
                    dsn='test-server.database.windows.net',
                    database='test-db',
                    access_token=token,
                    user='testuser'  # This conflicts with access_token
                )
            else:
                pytds.connect(
                    dsn='test-server.database.windows.net',
                    database='test-db',
                    access_token=token
                )
        except ValueError as e:
            print(f"  ✓ Validation error (expected): {e}")
        except Exception as e:
            print(f"  ✓ Other error: {type(e).__name__}: {e}")


if __name__ == '__main__':
    print("Azure Active Directory Token Authentication Examples")
    print("=" * 55)
    
    # Update these with your actual Azure SQL Database details
    print("\nNOTE: Update the connection details in each example with your actual:")
    print("- Server name (your-server.database.windows.net)")
    print("- Database name")
    print("- Ensure your Azure AD user/service principal has access to the database")
    print()
    
    examples = [
        example_with_hardcoded_token,
        example_with_azure_identity,
        example_with_service_principal,
        example_with_managed_identity,
        example_with_azure_cli,
        example_error_handling,
    ]
    
    for i, example_func in enumerate(examples, 1):
        print(f"\n{'-' * 50}")
        try:
            example_func()
        except Exception as e:
            print(f"Example {i} failed: {e}")
        print()
