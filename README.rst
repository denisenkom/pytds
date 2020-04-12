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

For detailed documentation of connection parameters see: `pytds.connect`_


.. _Python DBAPI: http://legacy.python.org/dev/peps/pep-0249/
.. _pytds.connect: https://python-tds.readthedocs.io/en/latest/pytds.html#pytds.connect
