pytds
=====

.. image:: https://secure.travis-ci.org/denisenkom/pytds.png?branch=master
   :target: https://travis-ci.org/denisenkom/pytds

.. image:: http://img.shields.io/pypi/dm/python-tds.svg
   :target: https://pypi.python.org/pypi/python-tds/

.. image:: http://img.shields.io/pypi/v/python-tds.svg
   :target: https://pypi.python.org/pypi/python-tds/


`Python DBAPI`_ driver for MSSQL using pure Python TDS (Tabular Data Stream) protocol implementation.
Doesn't depend on ADO or FreeTDS.  Can be used on any platform, including Linux, MacOS, Windows.

It can be used with https://pypi.python.org/pypi/django-sqlserver as a Django database backend.

Features
--------

* Fully supports new MSSQL 2008 date types: datetime2, date, time, datetimeoffset
* MARS

Missing Features
----------------

* SSL encryption

Installation
------------

To install run this command:

.. code-block:: bash

    $ pip install python-tds

For a better performance install bitarray package too:

.. code-block:: bash

    $ pip install bitarray

Documentation
-------------
Documentation is available at http://python-tds.readthedocs.org/en/latest/.

Example
-------

To connect to database do

.. code-block:: python

    import pytds
    with pytds.connect('server', 'database', 'user', 'password') as conn:
        with conn.cursor() as cur:
            cur.execute("select 1")
            cur.fetchall()


.. _Python DBAPI: http://legacy.python.org/dev/peps/pep-0249/
