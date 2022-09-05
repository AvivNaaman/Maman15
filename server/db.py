import sqlite3
import logging


class Database:
    DB_FILE_NAME = "server.db"

    # SQL Scripts for table creation.
    CREATE_USERS_SQL = """
    CREATE TABLE IF NOT EXISTS clients (
    ID blob PRIMARY KEY,
    Name text,
    PublicKey blob,
    LastSeen integer,
    AESKey blob
);
    """
    CREATE_FILES_SQL = """ 
CREATE TABLE IF NOT EXISTS files (
    ID blob PRIMARY KEY,
    FileName text,
    PathName text,
    Verified integer
);
    """

    def __init__(self):
        self.sqlite_conn = self.connect()

        self.load_data()

    def connect(self) -> sqlite3.Connection:
        logging.info("Connecting to database, and creating tables if don't exist.")
        conn = sqlite3.connect(self.DB_FILE_NAME)
        c = conn.cursor()
        c.execute(self.CREATE_USERS_SQL)
        c.execute(self.CREATE_FILES_SQL)
        conn.commit()
        return conn

    def load_data(self):
        pass

    def add_file(self):
        pass

    def verify_file(self):
        pass

    def register_user(self, user_id, name):
        pass

    def save_keys(self, public_key: bytes, aes_key: bytes):
        pass

    def __login_user(self):
        pass
