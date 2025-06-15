

import mysql.connector
from mysql.connector import Error
from flask import current_app
import logging

def get_database_connection():
    """Create and return a database connection"""
    try:
        connection = mysql.connector.connect(
            host=current_app.config.get('DB_HOST', 'localhost'),
            database=current_app.config.get('DB_NAME'),
            user=current_app.config.get('DB_USER'),
            password=current_app.config.get('DB_PASSWORD'),
            port=current_app.config.get('DB_PORT', 3306),
            autocommit=True
        )
        return connection
    except Error as e:
        logging.error(f"Error connecting to MySQL: {e}")
        return None

def call_stored_procedure(procedure_name, parameters=None):
    """
    Call a MySQL stored procedure with optional parameters
    
    Args:
        procedure_name (str): Name of the stored procedure
        parameters (list): List of parameters to pass to the procedure
    
    Returns:
        list: Results from the stored procedure or empty list if error
    """
    connection = None
    cursor = None
    results = []
    
    try:
        connection = get_database_connection()
        if connection is None:
            return results
        
        cursor = connection.cursor(dictionary=True)
        
        if parameters:
            cursor.callproc(procedure_name, parameters)
        else:
            cursor.callproc(procedure_name)
        
        # Fetch results from all result sets
        for result in cursor.stored_results():
            results.extend(result.fetchall())
        
        return results
        
    except Error as e:
        logging.error(f"Error calling stored procedure {procedure_name}: {e}")
        return results
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

def execute_query(query, parameters=None, fetch=True):
    """
    Execute a SQL query with optional parameters
    
    Args:
        query (str): SQL query to execute
        parameters (tuple): Parameters for the query
        fetch (bool): Whether to fetch results
    
    Returns:
        list: Query results or empty list
    """
    connection = None
    cursor = None
    results = []
    
    try:
        connection = get_database_connection()
        if connection is None:
            return results
        
        cursor = connection.cursor(dictionary=True)
        
        if parameters:
            cursor.execute(query, parameters)
        else:
            cursor.execute(query)
        
        if fetch:
            results = cursor.fetchall()
        
        connection.commit()
        return results
        
    except Error as e:
        logging.error(f"Error executing query: {e}")
        if connection:
            connection.rollback()
        return results
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# Alternative implementation if you're using PyMySQL instead of mysql-connector-python
def call_stored_procedure_pymysql(procedure_name, parameters=None):
    """
    Alternative implementation using PyMySQL
    """
    import pymysql
    
    connection = None
    cursor = None
    results = []
    
    try:
        connection = pymysql.connect(
            host=current_app.config.get('DB_HOST', 'localhost'),
            user=current_app.config.get('DB_USER'),
            password=current_app.config.get('DB_PASSWORD'),
            database=current_app.config.get('DB_NAME'),
            port=current_app.config.get('DB_PORT', 3306),
            cursorclass=pymysql.cursors.DictCursor
        )
        
        cursor = connection.cursor()
        
        if parameters:
            cursor.callproc(procedure_name, parameters)
        else:
            cursor.callproc(procedure_name)
        
        results = cursor.fetchall()
        connection.commit()
        
        return results
        
    except Exception as e:
        logging.error(f"Error calling stored procedure {procedure_name}: {e}")
        return results
        
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# Example usage functions for your specific use cases
def search_risks(search_term=None):
    """Search risks with optional search term"""
    if search_term:
        # If you have a stored procedure for searching
        return call_stored_procedure('search_risks', [f'%{search_term}%'])
    else:
        # If you want to use a direct query instead
        query = "SELECT risk_id, risk_name, risk_level FROM risks ORDER BY risk_id"
        return execute_query(query)

def search_threats(search_term=None):
    """Search threats with optional search term"""
    if search_term:
        query = """
        SELECT threat_id, threat_type, description, date_detected, risk_id, malware_id 
        FROM threats 
        WHERE threat_id LIKE %s OR threat_type LIKE %s OR description LIKE %s
        ORDER BY threat_id
        """
        search_pattern = f'%{search_term}%'
        return execute_query(query, (search_pattern, search_pattern, search_pattern))
    else:
        query = """
        SELECT threat_id, threat_type, description, date_detected, risk_id, malware_id 
        FROM threats 
        ORDER BY threat_id
        """
        return execute_query(query)

def insert_risk(risk_name, risk_level, risk_id=None):
    """Insert a new risk"""
    if risk_id:
        query = "INSERT INTO risks (risk_id, risk_name, risk_level) VALUES (%s, %s, %s)"
        return execute_query(query, (risk_id, risk_name, risk_level), fetch=False)
    else:
        query = "INSERT INTO risks (risk_name, risk_level) VALUES (%s, %s)"
        return execute_query(query, (risk_name, risk_level), fetch=False)

def update_risk(risk_id, risk_name, risk_level):
    """Update an existing risk"""
    query = "UPDATE risks SET risk_name = %s, risk_level = %s WHERE risk_id = %s"
    return execute_query(query, (risk_name, risk_level, risk_id), fetch=False)

def delete_risk(risk_id):
    """Delete a risk"""
    query = "DELETE FROM risks WHERE risk_id = %s"
    return execute_query(query, (risk_id,), fetch=False)

from flask import abort
from functools import wraps
from flask_login import current_user

def roles_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_anonymous or current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return wrapper
