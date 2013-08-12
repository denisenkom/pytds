pytds
=====

![Build Status](https://secure.travis-ci.org/denisenkom/pytds.png?branch=master)
   

Python DBAPI driver for MSSQL using pure Python TDS (Tabular Data Stream) protocol implementation

It can be used with https://bitbucket.org/denisenkom/django-pytds as a django database backend.

Install
-------

To install run this command:

    pip install python-tds

To connect to database do
    
    import pytds
    conn = pytds.connect('server', 'database', 'user', 'password')
