"""
Apply SQL migrations from the migrations/ folder to the database configured in app.py.
This script reads the SQLAlchemy URI from app.config and executes each .sql file in filename order.
Run with the virtualenv Python.

Note: This will modify your local database. Proceed only if you want to add the column.
"""
import os
from app import app
from sqlalchemy.engine import make_url
import mysql.connector


def get_db_params():
    uri = app.config.get('SQLALCHEMY_DATABASE_URI')
    if not uri:
        raise RuntimeError('SQLALCHEMY_DATABASE_URI not set in app.config')
    url = make_url(uri)
    return {
        'host': url.host or 'localhost',
        'port': url.port or 3306,
        'user': url.username or 'root',
        'password': url.password or '',
        'database': url.database,
    }


def apply_sql_file(conn, path):
    with open(path, 'r', encoding='utf-8') as f:
        sql = f.read()
    # mysql-connector does not support multiple statements by default; split on ';'
    cursor = conn.cursor()
    for stmt in [s.strip() for s in sql.split(';') if s.strip()]:
        cursor.execute(stmt)
    conn.commit()
    cursor.close()


def main():
    migrations_dir = os.path.join(os.path.dirname(__file__), '..', 'migrations')
    migrations_dir = os.path.normpath(migrations_dir)
    files = sorted([f for f in os.listdir(migrations_dir) if f.endswith('.sql')])
    if not files:
        print('No migrations found.')
        return

    params = get_db_params()
    print('Connecting to DB:', params['database'], 'at', params['host'])
    conn = mysql.connector.connect(host=params['host'], port=params['port'], user=params['user'], password=params['password'], database=params['database'])
    try:
        for fname in files:
            path = os.path.join(migrations_dir, fname)
            print('Applying', fname)
            apply_sql_file(conn, path)
        print('Migrations applied.')
    finally:
        conn.close()


if __name__ == '__main__':
    main()
