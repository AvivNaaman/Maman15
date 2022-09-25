import sqlite3
import logging
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


@dataclass
class User:
    id: uuid.UUID
    name: str
    public_key: Optional[bytes] = None
    last_seen: float = time.time()
    aes_key: Optional[bytes] = None


@dataclass
class File:
    id: uuid.UUID
    file_name: str
    path_name: str
    verified: bool = False

# TODO: Do I Need to use SQLite for data, but not RAM for the same data?


class Database:
    """
    This class handles all the database operations.
    """
    LOCAL_DB_FILE_NAME = "server.db"

    # SQL Scripts for table creation.
    CREATE_USERS_SQL = """
    CREATE TABLE IF NOT EXISTS clients (
    ID blob PRIMARY KEY,
    Name text,
    PublicKey blob,
    LastSeen REAL,
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
        self.sqlite_conn = self.__connect_sqlite()
        self.__ensure_tables_exist()

        self.users: Dict[uuid.UUID, User] = {}
        self.files: Dict[uuid.UUID, File] = {}

        self.__load_data()

    def __connect_sqlite(self):
        logging.info("Connecting to database, and creating tables if don't exist.")
        conn = sqlite3.connect(self.LOCAL_DB_FILE_NAME)
        return conn

    def __ensure_tables_exist(self):
        cursor = self.sqlite_conn.cursor()
        cursor.execute(self.CREATE_USERS_SQL)
        cursor.execute(self.CREATE_FILES_SQL)
        self.sqlite_conn.commit()

    def __load_data(self):
        cursor = self.sqlite_conn.cursor()
        all_files = cursor.execute("SELECT * FROM files").fetchall()
        all_users = cursor.execute("SELECT * FROM clients").fetchall()

        for file_row in all_files:
            file_id = uuid.UUID(bytes=file_row[0])
            self.files[file_id] = File(file_id, *file_row[1:])

        for client_row in all_users:
            client_id = uuid.UUID(bytes=client_row[0])
            self.users[client_id] = User(client_id, *client_row[1:])

    def add_file(self, user_id: uuid, file_name: str, file_path: Path):
        file_entry = File(user_id, file_name, str(file_path.absolute()))

        cursor = self.sqlite_conn.cursor()
        cursor.execute("INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
                       [user_id, file_entry.file_name, file_entry.path_name, file_entry.verified])
        self.sqlite_conn.commit()

    def verify_file(self, user_id: uuid):
        self.files[user_id].verified = True
        cursor = self.sqlite_conn.cursor()
        cursor.execute("UPDATE files SET Verified=1 WHERE ID=?", [user_id])
        self.sqlite_conn.commit()

    def register_user(self, name: str):
        """ Registers a new client by name, and returns the new client ID. """
        new_id = uuid.uuid4()
        new_user = User(new_id, name)

        cursor = self.sqlite_conn.cursor()
        cursor.execute("INSERT INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)",
                       [new_user.id.bytes, new_user.name, new_user.last_seen])
        self.sqlite_conn.commit()

        self.users[new_id] = new_user

        return new_id

    def save_keys(self, user_id: uuid, public_key: bytes, aes_key: bytes):
        # TODO: Handle KeyError?
        user_to_update = self.users[user_id]
        # TODO: Prevent updating key of an existing user. Return Error.
        user_to_update.public_key = public_key
        user_to_update.aes_key = aes_key

        cursor = self.sqlite_conn.cursor()
        cursor.execute("UPDATE clients SET PublicKey=?, AESKey=? WHERE ID=?",
                       [public_key, aes_key, user_to_update.id.bytes])
        self.sqlite_conn.commit()

    def get_aes_for_user(self, user_id: uuid) -> bytes:
        return self.users[user_id].public_key

    def __login_user(self):
        pass
