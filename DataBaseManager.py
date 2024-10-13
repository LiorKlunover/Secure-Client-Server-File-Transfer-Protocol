import sqlite3
import threading
import uuid
from datetime import datetime
from typing import Optional, Tuple, Union

class DataBaseManager:
    """
       A thread-safe SQLite database manager for handling client and file information.

       This class provides methods to manage client registrations, file tracking,
       and associated cryptographic keys in a SQLite database.

       Attributes:
           db_path (str): Path to the SQLite database file
           shared_lock (threading.Lock): Class-level lock for thread safety
       """

    shared_lock = threading.Lock()


    def __init__(self, db_path: str = 'defensive.db'):
        """
        Initialize the DatabaseManager.

        Args:
            db_path (str): Path to the SQLite database file
        """
        self.db_path = db_path
        self._create_tables()

    def _create_connection(self) -> sqlite3.Connection:
        """
        Create a new SQLite connection for thread-safe operation.

        Returns:
            sqlite3.Connection: A new database connection
        """
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _create_tables(self) -> None:
        """Create the necessary database tables if they don't exist."""
        with self._create_connection() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS clients (
                    client_id BLOB PRIMARY KEY,
                    client_name TEXT NOT NULL UNIQUE,
                    public_key TEXT NOT NULL DEFAULT '',
                    last_seen TEXT NOT NULL,
                    aes_key TEXT NOT NULL DEFAULT ''
                );
                
                CREATE TABLE IF NOT EXISTS files (
                    client_id BLOB,
                    file_name TEXT NOT NULL,
                    path_name TEXT NOT NULL,
                    verified BOOLEAN NOT NULL,
                    PRIMARY KEY (client_id, file_name),
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                );
            ''')

    def add_client(self, client_name: str) -> Optional[bytes]:
        """
        Add a new client to the database.

        Args:
            client_name (str): Name of the client to add

        Returns:
            Optional[bytes]: The client_id if successful, None otherwise
        """
        with self.shared_lock:
            try:
                with self._create_connection() as conn:
                    if self._check_client_name_exists(client_name, conn):
                        print("Client name already exists")
                        return None

                    client_id = uuid.uuid4().bytes
                    last_seen = datetime.now().isoformat()

                    conn.execute('''
                               INSERT INTO clients (client_id, client_name, public_key, last_seen, aes_key)
                               VALUES (?, ?, ?, ?, ?)
                           ''', (client_id, client_name, '', last_seen, ''))

                    return client_id
            except sqlite3.Error as e:
                print(f"Database error occurred: {e}")
                return None

    def add_file(self, client_id: bytes, file_name: str, path_name: str, verified: bool) -> bool:
        """
        Add a file entry for a client.

        Args:
            client_id (bytes): 16-byte client identifier
            file_name (str): Name of the file (max 32 chars)
            path_name (str): Path of the file (max 32 chars)
            verified (bool): Verification status of the file

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ValueError: If input parameters don't meet requirements
        """
        self.validate_file_params(client_id, file_name, path_name)

        with self.shared_lock:
            try:
                with self._create_connection() as conn:
                    if not self._client_exists(client_id, conn):
                        return False
                    if self._check_file_exists(client_id, file_name, conn):
                        print("File already exists")
                        return True
                    conn.execute('''
                         INSERT INTO files (client_id, file_name, path_name, verified)
                         VALUES (?, ?, ?, ?)
                     ''', (client_id, file_name, path_name, verified))
                    return True
            except sqlite3.IntegrityError:

                return False
            except sqlite3.Error as e:
                print(f"Database error occurred: {e}")
                return False


    def validate_file_params(self, client_id: bytes, file_name: str, path_name: str) -> None:
        """Validate parameters for file operations."""
        if not isinstance(client_id, bytes) or len(client_id) != 16:
            raise ValueError("client_id must be exactly 16 bytes")
        if not isinstance(file_name, str) or len(file_name) > 32:
            raise ValueError("file_name must be ≤ 32 characters")
        if not isinstance(path_name, str) or len(path_name) > 32:
            raise ValueError("path_name must be ≤ 32 characters")

    @staticmethod
    def _check_file_exists(client_id, file_name,conn) -> bool:
        try:
            cursor = conn.execute('''
                           SELECT COUNT(*) FROM files WHERE client_id = ? AND file_name = ?
                       ''', (client_id, file_name))
            result = cursor.fetchone()[0] > 0
            return result
        except sqlite3.Error as e:
            print(e)
            return False
    def update_file_verified(self, client_id, file_name, verified) -> None:
        with DataBaseManager.shared_lock:
            try:
                conn = self._create_connection()
                conn.execute('''
                    UPDATE files SET verified = ? WHERE client_id = ? AND file_name = ?
                ''', (verified, client_id, file_name))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(e)

    def add_public_key(self, client_id, public_key) -> None:
        with DataBaseManager.shared_lock:
            try:
                conn = self._create_connection()
                conn.execute('''
                    UPDATE clients SET public_key = ? WHERE client_id = ?
                ''', (public_key, client_id))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(e)
    def add_aes_key(self, client_id, aes_key) -> None:
        with DataBaseManager.shared_lock:
            try:
                conn = self._create_connection()
                conn.execute('''
                    UPDATE clients SET aes_key = ? WHERE client_id = ?
                ''', (aes_key, client_id))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(e)

    def get_client(self, client_id) -> Optional[Tuple[str, str, str, str]]:
        with DataBaseManager.shared_lock:
            try:
                conn = self._create_connection()
                cursor = conn.execute('''
                    SELECT client_name, public_key, last_seen, aes_key FROM clients WHERE client_id = ?
                ''', (client_id,))
                result = cursor.fetchone()
                conn.close()
                return result
            except sqlite3.Error as e:
                print(e)
                return None

    def get_client_id(self, client_name) -> Optional[bytes]:
        with DataBaseManager.shared_lock:
            try:
                conn = self._create_connection()
                cursor = conn.execute('''
                    SELECT client_id FROM clients WHERE client_name = ?
                ''', (client_name,))
                result = cursor.fetchone()
                conn.close()
                return result[0]
            except sqlite3.Error as e:
                print(e)
                return None
    def check_client_name_exists(self, client_name, conn) -> bool:
        try:
            cursor = conn.execute('''
                           SELECT COUNT(*) FROM clients WHERE client_name = ?
                       ''', (client_name,))
            return cursor.fetchone()[0] > 0
        except sqlite3.Error as e:
            print(e)
            return False

    def get_aes_key(self, client_id) -> Optional[str]:
        with DataBaseManager.shared_lock:
            try:
                conn = self._create_connection()
                cursor = conn.execute('''
                    SELECT aes_key FROM clients WHERE client_id = ?
                ''', (client_id,))
                result = cursor.fetchone()
                conn.close()
                return result[0]
            except sqlite3.Error as e:
                print(e)
                return None

    def update_last_seen(self, client_id) -> None:
        with DataBaseManager.shared_lock:
            try:
                conn = self._create_connection()
                last_seen = datetime.now().isoformat()
                conn.execute('''
                    UPDATE clients SET last_seen = ? WHERE client_id = ?
                ''', (last_seen, client_id))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(e)

    def _client_exists(self, client_id: bytes, conn: sqlite3.Connection) -> bool:
        """Check if a client ID exists in the database."""
        cursor = conn.execute('SELECT 1 FROM clients WHERE client_id = ?', (client_id,))
        return cursor.fetchone() is not None
    def _check_client_name_exists(self, client_name: str, conn: sqlite3.Connection) -> bool:
        """Check if a client name already exists in the database."""
        cursor = conn.execute('SELECT 1 FROM clients WHERE client_name = ?', (client_name,))
        return cursor.fetchone() is not None

    def close(self):
        pass  # Each thread creates and closes its own connection, so no global connection to close.


