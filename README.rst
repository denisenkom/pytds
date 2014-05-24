pytds
=====

.. image:: https://secure.travis-ci.org/denisenkom/pytds.png?branch=master
   :target: https://travis-ci.org/denisenkom/pytds


`Python DBAPI`_ driver for MSSQL using pure Python TDS (Tabular Data Stream) protocol implementation

It can be used with https://bitbucket.org/denisenkom/django-pytds as a django database backend.

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