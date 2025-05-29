from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy import inspect
import psycopg2
import pymysql
import pyodbc

def create_database(database_url: str):
    url = make_url(database_url)
    db_name = url.database

    if url.drivername.startswith("postgresql"):
        _create_postgres_db(url, db_name)
    elif url.drivername.startswith("mysql"):
        _create_mysql_db(url, db_name)
    elif url.drivername.startswith("mssql"):
        _create_sqlserver_db(url, db_name)
    elif url.drivername.startswith("sqlite"):
        # SQLite does not require explicit database creation
        pass
    else:
        raise ValueError("Unsupported database dialect")
    
    from .models import Base, engine

    inspector = inspect(engine)
    tables_needed = Base.metadata.tables.keys()
    existing_tables = inspector.get_table_names()

    if not all(table in existing_tables for table in tables_needed):
        Base.metadata.create_all(bind=engine)

def _create_postgres_db(url, db_name):
    conn = psycopg2.connect(
        host=url.host,
        user=url.username,
        password=url.password,
        port=url.port or 5432,
        dbname="postgres"
    )
    conn.set_isolation_level(0)
    cursor = conn.cursor()
    cursor.execute(f"CREATE DATABASE {db_name}")
    cursor.close()
    conn.close()

def _create_mysql_db(url, db_name):
    conn = pymysql.connect(
        host=url.host,
        user=url.username,
        password=url.password,
        port=url.port or 3306
    )
    cursor = conn.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
    conn.commit()
    cursor.close()
    conn.close()

def _create_sqlserver_db(url, db_name):
    conn_str = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={url.host},{url.port or 1433};"
        f"UID={url.username};PWD={url.password};"
        f"DATABASE=master"
    )
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute(f"IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = '{db_name}') "
                   f"BEGIN CREATE DATABASE [{db_name}] END")
    conn.commit()
    cursor.close()
    conn.close()

if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    load_dotenv()

    db_url = os.getenv("LOG_CENTER_DB_URL")
    try:
        create_database(db_url)
        print("Database created successfully (or already exists).")
    except OperationalError as e:
        print("Error creating database:", e)
    except Exception as e:
        print("Unexpected error:", e)
