`pytds.extensions` -- Extensions to the DB API
==============================================

.. module:: pytds.extensions

.. _isolation-level-constants:

Isolation level constants
-------------------------

.. data:: ISOLATION_LEVEL_READ_UNCOMMITTED

    Transaction can read uncommitted data


.. data:: ISOLATION_LEVEL_READ_COMMITTED

    Transaction can read only committed data, will block on attempt
    to read modified uncommitted data


.. data:: ISOLATION_LEVEL_REPEATABLE_READ

    Transaction will place lock on read records, other transactions
    will block trying to modify such records


.. data:: ISOLATION_LEVEL_SERIALIZABLE

    Transaction will lock tables to prevent other transactions
    from inserting new data that would match selected recordsets


.. data:: ISOLATION_LEVEL_SNAPSHOT

    Allows non-blocking consistent reads on a snapshot for transaction without
    blocking other transactions changes

