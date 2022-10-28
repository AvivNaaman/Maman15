import sqlite3
import logging
from threading import Lock
import time
from uuid import UUID, uuid4
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


@dataclass
class User:
    id: UUID
    name: str
    public_key: Optional[bytes] = None
    last_seen: float = time.time()
    aes_key: Optional[bytes] = None


@dataclass
class File:
    id: UUID
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
        self.logger = logging.getLogger("Server.DataAccess")

        self.sqlite_conn = self.__connect_sqlite()
        self.__ensure_tables_exist()

        self.users: Dict[UUID, User] = {}
        self.files: Dict[UUID, File] = {}

        # Thread saftey is important - This is a shared object!
        self.lock = Lock()

        self.__load_data()

    def __connect_sqlite(self) -> sqlite3.Connection:
        self.logger.info("Connecting to local SQLite database.")

        # in modern python, you can use SQLite connection via different thread.
        # in addition, everything's 100% thread-safe - so that's okay.
        conn = sqlite3.connect(self.LOCAL_DB_FILE_NAME, check_same_thread=False)
        return conn

    def __ensure_tables_exist(self):
        self.logger.info("Making sure all tables exist.")
        cursor = self.sqlite_conn.cursor()
        cursor.execute(self.CREATE_USERS_SQL)
        cursor.execute(self.CREATE_FILES_SQL)
        cursor.close()
        self.sqlite_conn.commit()

    def __load_data(self):
        """ This method loads all the persistant SQLite3 DB data into the memory. TODO: Is this required? """
        cursor = self.sqlite_conn.cursor()
        all_files = cursor.execute("SELECT * FROM files").fetchall()
        all_users = cursor.execute("SELECT * FROM clients").fetchall()

        for file_row in all_files:
            file_id = UUID(bytes=file_row[0])
            self.files[file_id] = File(file_id, *file_row[1:])

        for client_row in all_users:
            client_id = UUID(bytes=client_row[0])
            self.users[client_id] = User(client_id, *client_row[1:])

    def add_file(self, user_id: UUID, file_name: str, file_path: str):
        """ Inserts the information of a new file to the database. """
        file_entry = File(user_id, file_name, str(Path(file_path).absolute()))
        self.logger.debug(f"Storing file {file_path} information of {user_id}.")
        with self.lock:
            self.files[user_id] = file_entry

            cursor = self.sqlite_conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
                        [user_id.bytes, file_entry.file_name, file_entry.path_name, file_entry.verified])
            cursor.close()
            self.sqlite_conn.commit()

    def verify_file(self, user_id: UUID):
        """ Flags the file as verified in the database. """
        self.logger.debug(f"Updating file of user {user_id} as verified.")
        with self.lock:
            self.files[user_id].verified = True
            cursor = self.sqlite_conn.cursor()
            cursor.execute("UPDATE files SET Verified=1 WHERE ID=?", [user_id.bytes])
            cursor.close()
            self.sqlite_conn.commit()

    def register_user(self, name: str):
        """ Registers a new client by name to the database, and returns the new client ID. """

        new_id = uuid4()
        new_user = User(new_id, name)

        self.logger.debug(f"Adding new user {name} with ID {new_id}.")

        with self.lock:
            self.users[new_id] = new_user

            cursor = self.sqlite_conn.cursor()
            cursor.execute("INSERT INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)",
                        [new_user.id.bytes, new_user.name, new_user.last_seen])
            cursor.close()
            self.sqlite_conn.commit()
        return new_id

    def save_keys(self, user_id: UUID, public_key: bytes, aes_key: bytes):
        self.logger.debug(f"Begin saving keys for user #{user_id}")
        with self.lock:
            user_to_update = self.users[user_id]
            
            user_to_update.public_key = public_key
            user_to_update.aes_key = aes_key


            cursor = self.sqlite_conn.cursor()
            cursor.execute("UPDATE clients SET PublicKey=?, AESKey=? WHERE ID=?",
                        [public_key, aes_key, user_to_update.id.bytes])
            cursor.close()
            self.sqlite_conn.commit()

    def get_aes_for_user(self, user_id: UUID) -> Optional[bytes]:
        return self.users[user_id].aes_key

    def remove_file(self, user_id: UUID):
        with self.lock:
            self.files.pop(user_id)
            cursor = self.sqlite_conn.cursor()
            cursor.execute("DELETE from files WHERE ID=?",
                        [user_id.bytes])
            cursor.close()
            self.sqlite_conn.commit()

    def set_last_seen(self, user_id: UUID) -> None:
        """ Updates the last seen of a user to current time. """
        with self.lock:
            self.users[user_id].last_seen = time.time()
            cursor = self.sqlite_conn.cursor()
            cursor.execute("UPDATE clients SET LastSeen=? WHERE ID=?",
                        [time.time(), user_id.bytes])
            cursor.close()
            self.sqlite_conn.commit()

    def user_exists(self, user_name) -> bool:
        """ Returns whether user name already taken in database """
        with self.lock:
            cursor = self.sqlite_conn.cursor()
            matches = cursor.execute("SELECT * FROM clients WHERE Name=?", [user_name]).fetchall()
            cursor.close()
        return len(matches) > 0

    def close(self):
        self.sqlite_conn.close()