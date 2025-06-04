#!/usr/bin/env python
"""
Example of using Azure AD authentication with pytds

This example demonstrates how to connect to Azure SQL Database using 
Azure Active Directory authentication tokens.

Prerequisites:
- Install required packages: pip install azure-identity msal pytds
- Configure Azure AD authentication for your Azure SQL Database
- Update the connection parameters below with your actual values
"""

import os
import struct
import pytds
from typing import Optional


def get_token_with_azure_identity(tenant_id: str, client_id: str, client_secret: Optional[str] = None) -> str:
    """
    Get an access token using Azure Identity library.
    
    This method supports multiple authentication flows:
    - Service Principal (when client_secret is provided)
    - Managed Identity (when running in Azure)
    - Azure CLI (for local development)
    
    Args:
        tenant_id: Azure AD tenant ID
        client_id: Application (client) ID
        client_secret: Client secret (optional, for service principal auth)
    
    Returns:
        Access token as string
    """
    from azure.identity import (
        ClientSecretCredential,
        DefaultAzureCredential,
        ManagedIdentityCredential,
        AzureCliCredential,
        ChainedTokenCredential
    )
    
    # The scope for Azure SQL Database
    scope = "https://database.windows.net//.default"
    
    if client_secret:
        # Use service principal authentication
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
    else:
        # Try multiple authentication methods in order
        credential = ChainedTokenCredential(
            ManagedIdentityCredential(client_id=client_id),  # For Azure-hosted apps
            AzureCliCredential(),  # For local development
            DefaultAzureCredential()  # Fallback
        )
    
    # Get the token
    token = credential.get_token(scope)
    return token.token


def get_token_with_msal(tenant_id: str, client_id: str, client_secret: Optional[str] = None) -> str:
    """
    Get an access token using MSAL (Microsoft Authentication Library).
    
    Args:
        tenant_id: Azure AD tenant ID
        client_id: Application (client) ID
        client_secret: Client secret (optional, for service principal auth)
    
    Returns:
        Access token as string
    """
    import msal
    
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scope = ["https://database.windows.net//.default"]
    
    if client_secret:
        # Create a confidential client for service principal auth
        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority
        )
        # Acquire token for the application itself (client credentials flow)
        result = app.acquire_token_for_client(scopes=scope)
    else:
        # Create a public client for interactive auth
        app = msal.PublicClientApplication(
            client_id=client_id,
            authority=authority
        )
        # Try to get token from cache first
        accounts = app.get_accounts()
        if accounts:
            result = app.acquire_token_silent(scope, account=accounts[0])
        else:
            # Fall back to interactive authentication
            result = app.acquire_token_interactive(scopes=scope)
    
    if "access_token" in result:
        return result["access_token"]
    else:
        raise Exception(f"Failed to acquire token: {result.get('error_description', 'Unknown error')}")


def generate_nonce() -> bytes:
    """
    Generate a 32-byte nonce for enhanced security.
    
    The nonce adds an extra layer of security to prevent replay attacks.
    
    Returns:
        32 random bytes
    """
    import secrets
    return secrets.token_bytes(32)


def example_service_principal_auth():
    """Example using service principal authentication"""
    print("=== Service Principal Authentication Example ===")
    
    # Configuration - replace with your actual values
    server = "your-server.database.windows.net"
    database = "your-database"
    tenant_id = "your-tenant-id"
    client_id = "your-client-id"
    client_secret = "your-client-secret"  # Store securely, don't hardcode!
    
    try:
        # Get the access token
        print("Acquiring access token...")
        access_token = get_token_with_azure_identity(tenant_id, client_id, client_secret)
        print("Token acquired successfully")
        
        # Optional: Generate a nonce for additional security
        nonce = generate_nonce()
        
        # Connect to the database
        print(f"Connecting to {server}/{database}...")
        with pytds.connect(
            dsn=server,
            database=database,
            access_token=access_token,
            nonce=nonce,
            autocommit=True
        ) as conn:
            print("Connected successfully!")
            
            # Execute a simple query
            with conn.cursor() as cursor:
                cursor.execute("SELECT @@VERSION")
                row = cursor.fetchone()
                print(f"SQL Server version: {row[0][:50]}...")
                
                # Example: Query some data
                cursor.execute("SELECT SYSTEM_USER AS [User], DB_NAME() AS [Database]")
                row = cursor.fetchone()
                print(f"Connected as: {row[0]}")
                print(f"Database: {row[1]}")
    
    except Exception as e:
        print(f"Error: {e}")


def example_managed_identity_auth():
    """Example using Managed Identity authentication (for Azure-hosted apps)"""
    print("\n=== Managed Identity Authentication Example ===")
    
    # Configuration
    server = "your-server.database.windows.net"
    database = "your-database"
    
    # For system-assigned managed identity, you don't need client_id
    # For user-assigned managed identity, provide the client_id
    client_id = None  # or "your-managed-identity-client-id"
    
    try:
        # Get the access token
        print("Acquiring access token using Managed Identity...")
        credential = ManagedIdentityCredential(client_id=client_id) if client_id else ManagedIdentityCredential()
        token = credential.get_token("https://database.windows.net//.default")
        access_token = token.token
        print("Token acquired successfully")
        
        # Connect to the database
        print(f"Connecting to {server}/{database}...")
        with pytds.connect(
            dsn=server,
            database=database,
            access_token=access_token,
            autocommit=True
        ) as conn:
            print("Connected successfully!")
            
            with conn.cursor() as cursor:
                cursor.execute("SELECT SYSTEM_USER")
                user = cursor.fetchone()[0]
                print(f"Connected as: {user}")
    
    except Exception as e:
        print(f"Error: {e}")


def example_interactive_auth():
    """Example using interactive authentication (for development)"""
    print("\n=== Interactive Authentication Example ===")
    
    # Configuration
    server = "your-server.database.windows.net"
    database = "your-database"
    tenant_id = "your-tenant-id"
    client_id = "your-client-id"  # Your app registration client ID
    
    try:
        # Get the access token interactively
        print("Acquiring access token interactively...")
        access_token = get_token_with_msal(tenant_id, client_id)
        print("Token acquired successfully")
        
        # Connect to the database
        print(f"Connecting to {server}/{database}...")
        with pytds.connect(
            dsn=server,
            database=database,
            access_token=access_token,
            autocommit=True
        ) as conn:
            print("Connected successfully!")
            
            with conn.cursor() as cursor:
                cursor.execute("SELECT SYSTEM_USER")
                user = cursor.fetchone()[0]
                print(f"Connected as: {user}")
    
    except Exception as e:
        print(f"Error: {e}")


def main():
    """Run the examples"""
    print("Azure AD Authentication Examples for pytds")
    print("=" * 50)
    
    # Check if running in Azure (has managed identity)
    if os.environ.get("AZURE_CLIENT_ID") or os.environ.get("MSI_ENDPOINT"):
        example_managed_identity_auth()
    else:
        # For local development, you can use either:
        # 1. Service principal (if you have credentials)
        # 2. Interactive auth (browser-based login)
        
        # Uncomment the example you want to run:
        example_service_principal_auth()
        # example_interactive_auth()


if __name__ == "__main__":
    # Import at module level for the managed identity example
    from azure.identity import ManagedIdentityCredential
    
    main()
