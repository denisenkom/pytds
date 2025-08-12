pytds
=====

.. image:: https://secure.travis-ci.org/denisenkom/pytds.png?branch=master
   :target: https://travis-ci.org/denisenkom/pytds

.. image:: https://ci.appveyor.com/api/projects/status/a5h4y29063crqtet?svg=true
   :target: https://ci.appveyor.com/project/denisenkom/pytds

.. image:: http://img.shields.io/pypi/v/python-tds.svg
   :target: https://pypi.python.org/pypi/python-tds/

.. image:: https://codecov.io/gh/denisenkom/pytds/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/denisenkom/pytds


`Python DBAPI`_ driver for MSSQL using pure Python TDS (Tabular Data Stream) protocol implementation.
Doesn't depend on ADO or FreeTDS.  Can be used on any platform, including Linux, MacOS, Windows.

It can be used with https://pypi.python.org/pypi/django-sqlserver as a Django database backend.

Features
--------

* Fully supports new MSSQL 2008 date types: datetime2, date, time, datetimeoffset
* MARS
* Bulk insert
* Table-valued parameters
* TLS connection encryption
* Kerberos support on non-Windows platforms (requires kerberos package)
* Azure Active Directory token-based authentication for Azure SQL Database

Installation
------------

To install run this command:

.. code-block:: bash

    $ pip install python-tds

If you want to use TLS you should also install pyOpenSSL package:

.. code-block:: bash

   $ pip install pyOpenSSL

For a better performance install bitarray package too:

.. code-block:: bash

    $ pip install bitarray

To use Kerberos on non-Windows platforms (experimental) install kerberos package:

.. code-block:: bash

    $ pip install kerberos

Documentation
-------------
Documentation is available at https://python-tds.readthedocs.io/en/latest/.

Example
-------

To connect to database do

.. code-block:: python

    import pytds
    with pytds.connect('server', 'database', 'user', 'password') as conn:
        with conn.cursor() as cur:
            cur.execute("select 1")
            cur.fetchall()


To enable TLS you should also provide cafile parameter which should be a file name containing trusted CAs in PEM format.

Azure Active Directory Authentication
--------------------------------------

To connect to Azure SQL Database using Azure Active Directory token-based authentication:

.. code-block:: python

    import pytds

    # Using an access token obtained from Azure AD
    access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."  # Your Azure AD access token

    with pytds.connect(
        dsn='your-server.database.windows.net',
        database='your-database',
        access_token=access_token
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchall()

The access token can be obtained using various methods:

* Azure Managed Identity (for applications running in Azure)
* Service Principal authentication
* Interactive authentication flows
* Azure CLI (`az account get-access-token --resource https://database.windows.net/`)

Example using Azure Identity library to get a token:

.. code-block:: python

    from azure.identity import DefaultAzureCredential
    import pytds

    # Get token using Azure Identity (works with managed identity, service principal, etc.)
    credential = DefaultAzureCredential()
    token = credential.get_token("https://database.windows.net/.default")

    with pytds.connect(
        dsn='your-server.database.windows.net',
        database='your-database',
        access_token=token.token
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT CURRENT_USER")
            print(cur.fetchone())

For detailed documentation of connection parameters see: `pytds.connect`_


.. _Python DBAPI: http://legacy.python.org/dev/peps/pep-0249/
.. _pytds.connect: https://python-tds.readthedocs.io/en/latest/pytds.html#pytds.connect
