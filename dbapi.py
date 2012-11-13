class Connection(object):
    def cursor(self, as_dict=None):
        """
        Return cursor object that can be used to make queries and fetch
        results from the database.
        """
        if as_dict is None:
            as_dict = self.as_dict
        return Cursor(self, as_dict)

##################
## Cursor class ##
##################
class Cursor(object):
    """
    This class represents a database cursor, which is used to issue queries
    and fetch results from a database connection.
    """
    @property
    def _source(self):
        if self.conn == None:
            raise InterfaceError('Cursor is closed.')
        return self.conn

    def __init__(self, conn, as_dict):
        self.conn = conn
        self.description = None
        self._batchsize = 1
        self._rownumber = 0
        self._returnvalue = None
        self.as_dict = as_dict

    def execute(self, operation, params=()):
        self.description = None
        self._rownumber = 0

        try:
            if not params:
                self._source._conn.execute_query(operation)
            else:
                self._source._conn.execute_query(operation, params)
            self.description = self._source._conn.get_header()
            self._rownumber = self._source._conn.rows_affected

        except _mssql.MSSQLDatabaseException, e:
            if e.number in prog_errors:
                raise ProgrammingError, e[0]
            if e.number in integrity_errors:
                raise IntegrityError, e[0]
            raise OperationalError, e[0]
        except _mssql.MSSQLDriverException, e:
            raise InterfaceError, e[0]


def connect(host, database, login, password, **kwargs):
    import login
    conn = Connection()
    conn._tds = login.tds_connect(host, database, login, password, **kwargs)
