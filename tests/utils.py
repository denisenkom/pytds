import sys
import unittest
import pytds
import settings


if sys.version_info.major < 3:
    # patch unittest.TestCase for Python 2.7
    unittest.TestCase.assertRaisesRegex = unittest.TestCase.assertRaisesRegexp


class MockSock(object):
    def __init__(self, input_packets=()):
        self.set_input(input_packets)
        self._out_packets = []
        self._closed = False

    def recv(self, size):
        if not self.is_open():
            raise Exception('Connection closed')
        if self._curr_packet >= len(self._packets):
            return b''
        if self._packet_pos >= len(self._packets[self._curr_packet]):
            self._curr_packet += 1
            self._packet_pos = 0
        if self._curr_packet >= len(self._packets):
            return b''
        res = self._packets[self._curr_packet][self._packet_pos:self._packet_pos+size]
        self._packet_pos += len(res)
        return res

    def recv_into(self, buffer, size=0):
        if not self.is_open():
            raise Exception('Connection closed')
        if size == 0:
            size = len(buffer)
        res = self.recv(size)
        buffer[0:len(res)] = res
        return len(res)

    def send(self, buf, flags=0):
        if not self.is_open():
            raise Exception('Connection closed')
        self._out_packets.append(buf)
        return len(buf)

    def sendall(self, buf, flags=0):
        if not self.is_open():
            raise Exception('Connection closed')
        self._out_packets.append(buf)

    def setsockopt(self, *args):
        pass

    def close(self):
        self._closed = True

    def is_open(self):
        return not self._closed

    def consume_output(self):
        """
        Retrieve data from output queue and then clear output queue
        @return: bytes
        """
        res = self._out_packets
        self._out_packets = []
        return b''.join(res)

    def set_input(self, packets):
        """
        Resets input queue
        @param packets: List of input packets
        """
        self._packets = packets
        self._curr_packet = 0
        self._packet_pos = 0


def does_database_exist(connection: pytds.Connection, name: str):
    with connection.cursor() as cursor:
        db_id = cursor.execute_scalar("select db_id(%s)", (name,))
    return db_id is not None


def does_schema_exist(connection: pytds.Connection, name: str, database: str) -> bool:
    with connection.cursor() as cursor:
        val = cursor.execute_scalar(
            f"""
            select count(*) from {database}.information_schema.schemata
            where schema_name = cast(%s as nvarchar(max))
            """, (name,))
    return val > 0


def does_stored_proc_exist(connection: pytds.Connection, name: str, database: str, schema: str = "dbo") -> bool:
    with connection.cursor() as cursor:
        val = cursor.execute_scalar(
            f"""
            select count(*) from {database}.information_schema.routines
            where routine_schema = cast(%s as nvarchar(max)) and routine_name = cast(%s as nvarchar(max))
            """, (schema, name))
    return val > 0


def does_table_exist(connection: pytds.Connection, name: str, database: str, schema: str = "dbo") -> bool:
    with connection.cursor() as cursor:
        val = cursor.execute_scalar(
            f"""
            select count(*) from {database}.information_schema.tables
            where table_schema = cast(%s as nvarchar(max)) and table_name = cast(%s as nvarchar(max))
            """, (schema, name))
    return val > 0


def does_user_defined_type_exist(connection: pytds.Connection, name: str) -> bool:
    with connection.cursor() as cursor:
        val = cursor.execute_scalar("select type_id(%s)", (name,))
        return val is not None



def create_test_database(connection: pytds.Connection):
    with connection.cursor() as cur:
        if not does_database_exist(connection=connection, name=settings.DATABASE):
            cur.execute(f'create database [{settings.DATABASE}]')
        cur.execute(f"use [{settings.DATABASE}]")
        if not does_schema_exist(connection=connection, name="myschema", database=settings.DATABASE):
            cur.execute('create schema myschema')
        if not does_table_exist(connection=connection, name="bulk_insert_table", schema="myschema", database=settings.DATABASE):
            cur.execute('create table myschema.bulk_insert_table(num int, data varchar(100))')
        if not does_stored_proc_exist(connection=connection, name="testproc", database=settings.DATABASE):
            cur.execute('''
            create procedure testproc (@param int, @add int = 2, @outparam int output)
            as
            begin
                set nocount on
                --select @param
                set @outparam = @param + @add
                return @outparam
            end
            ''')
        # Stored procedure which does not have RETURN statement
        if not does_stored_proc_exist(connection=connection, name="test_proc_no_return", database=settings.DATABASE):
            cur.execute('''
            create procedure test_proc_no_return(@param int)
            as
            begin
                select @param
            end
            ''')
        if not does_user_defined_type_exist(connection=connection, name="dbo.CategoryTableType"):
            cur.execute('CREATE TYPE dbo.CategoryTableType AS TABLE ( CategoryID int, CategoryName nvarchar(50) )')
