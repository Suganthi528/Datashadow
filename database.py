import mysql.connector
from config import DB_CONFIG

def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        print("Database Connected Successfully!")
        return conn
    except mysql.connector.Error as err:
        print("Database Connection Failed:", err)
        return None