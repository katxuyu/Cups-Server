import mysql.connector
from mysql.connector import Error
from . import helper 


import logging
logger = logging.getLogger(__name__)

def connect(host, database, user, password, port, ssl_ca, ssl_disabled=False):
    try:
        conn = mysql.connector.connect(
            host=host,
            database=database,
            user=user,
            password=password,
            port=port,
            ssl_ca=ssl_ca,
            ssl_disabled=ssl_disabled
        )
 
        return conn
    except(Exception, Error) as err:
        log = "ERROR - " + str(err)
        return log

"""
    ----Format----
    table: "table1"
    elements: "(float_elem2, int_elem2, string_elem3)"
    values: "(3.14, 1234, 'string_value3')"
"""
def insert(conn, table, elements, values):
    # creating a cursor to perform a sql operation

    cursor = conn.cursor()
    # sql query
    query = "INSERT INTO " + table + " " + elements + "  VALUES "+ values +";"
    try:
        # execute the command
        cursor.execute(query)
        # commit the changes
        conn.commit()
        return '{} records inserted'.format(cursor.rowcount)
    except(Exception, Error) as error:
        return "ERROR - " + str(error)
    finally:
        cursor.close()
        return '\nConnection closed'



"""
    ----Format----
    elements: "elem1, elem2, elem3" or "*"
    table: "table1"
"""
def fetch(conn, elements, table):
    # creating a cursor to perform a sql operation
    cursor = conn.cursor()
    # sql query
    query = "SELECT " + elements + " FROM " + table +";"
    try:
        # execute the command
        cursor.execute(query)
        records = cursor.fetchall()
        
        return records
    except(Exception, Error) as error:
        return "ERROR - " + str(error)
    finally:
        cursor.close()
        return '\nConnection closed'


"""
    ----Format----
    elements: "elem1, elem2, elem3" or "*"
    table: "table1"
    condition: "elem1 != 'Something' or elem2 == 1.23"
"""
def fetch(conn, elements, table, condition):
    # creating a cursor to perform a sql operation
    cursor = conn.cursor()
    # sql query
    query = "SELECT " + elements + " FROM " + table +" WHERE "+ condition+";"
    try:
        # execute the command
        cursor.execute(query)
        records = cursor.fetchall()
        
        return records
    except(Exception, Error) as error:
        return "ERROR - " + str(error)
    finally:
        cursor.close()
        return records


"""
    ----Format----
    table: "table1"
    set: elem3 = 123.4, elem4 = 'Something'
    condition: "elem1 != 'Something' or elem2 == 1.23"
"""
def update(conn, table, set, condition):
    # creating a cursor to perform a sql operation
    cursor = conn.cursor()
    # sql query
    query = "UPDATE " + table + " SET " + set + " WHERE " + condition + ";"
    try:
        cursor.execute(query)
        # commit the changes
        conn.commit()
        return "Update Successful"
    except(Exception, Error) as error:
        return "ERROR - " + str(error)
    finally:
        cursor.close()
        return '\nConnection closed'

"""
    ----Format----
    table: "table1"
    set: elem3 = 123.4, elem4 = 'Something'
    router_id: '8002:9cff:fe08:7c18'
"""
def update_router(conn, table, set, router_id):
    # creating a cursor to perform a sql operation
    cursor = conn.cursor()
    # sql query
    query = "UPDATE " + table + " SET " + set + " WHERE router_name = '"+ router_id +"';"
    try:
        record = helper.get_by_id(cursor, router_id)
        if record is None:
            return('Router id = {} not found'.format(router_id))
        else:
            # execute the command
            cursor.execute(query)
            # commit the changes
            conn.commit()
            return 'Router id = {} updated successfully'.format(router_id)
    except(Exception, Error) as error:
        return "ERROR - " + str(error)
    finally:
        cursor.close()
        return '\nConnection closed'


def query(conn, query):
    # creating a cursor to perform a sql operation

    cursor = conn.cursor()
    # sql query
    
    try:
        # execute the command
        cursor.execute(query)
        # commit the changes
        conn.commit()
        return '{} records inserted'.format(cursor.rowcount)
    except(Exception, Error) as error:
        return "ERROR - " + str(error)
    finally:
        cursor.close()
        return '\nConnection closed'