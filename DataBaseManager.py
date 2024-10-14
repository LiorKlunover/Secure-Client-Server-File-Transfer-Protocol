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
        with self.shared_lock:  # Ensure thread-safe access to the database
            try:
                with self._create_connection() as conn:  # Create a new database connection
                    if self._check_client_name_exists(client_name, conn):  # Check if the client name already exists
                        print("Client name already exists")  # Print a message if the client name exists
                        return None  # Return None if the client name exists

                    client_id = uuid.uuid4().bytes  # Generate a new UUID for the client ID
                    last_seen = datetime.now().isoformat()  # Get the current timestamp for last seen

                    # Insert the new client into the database
                    conn.execute('''
                        INSERT INTO clients (client_id, client_name, public_key, last_seen, aes_key)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (client_id, client_name, '', last_seen, ''))

                    return client_id  # Return the client ID if successful
            except sqlite3.Error as e:  # Handle any SQLite errors
                print(f"Database error occurred: {e}")  # Print the error message
                return None  # Return None if an error occurs

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
        self.validate_file_params(client_id, file_name, path_name)  # Validate the input parameters

        with self.shared_lock:  # Ensure thread-safe access to the database
            try:
                with self._create_connection() as conn:  # Create a new database connection
                    if not self._client_exists(client_id, conn):  # Check if the client exists in the database
                        return False  # Return False if the client does not exist
                    if self._check_file_exists(client_id, file_name, conn):  # Check if the file already exists for the client
                        print("File already exists")  # Print a message indicating the file already exists
                        return True  # Return True since the file already exists
                    # Insert the new file entry into the database
                    conn.execute('''
                        INSERT INTO files (client_id, file_name, path_name, verified)
                        VALUES (?, ?, ?, ?)
                    ''', (client_id, file_name, path_name, verified))
                    return True  # Return True if the file entry was successfully added
            except sqlite3.IntegrityError:
                return False  # Return False if there is an integrity error
            except sqlite3.Error as e:
                print(f"Database error occurred: {e}")  # Print the error message
                return False  # Return False if a database error occurs


    def validate_file_params(self, client_id: bytes, file_name: str, path_name: str) -> None:
        """Validate parameters for file operations."""
        # Check if client_id is a bytes object and exactly 16 bytes long
        if not isinstance(client_id, bytes) or len(client_id) != 16:
            raise ValueError("client_id must be exactly 16 bytes")

        # Check if file_name is a string and its length is ≤ 32 characters
        if not isinstance(file_name, str) or len(file_name) > 32:
            raise ValueError("file_name must be ≤ 32 characters")

        # Check if path_name is a string and its length is ≤ 32 characters
        if not isinstance(path_name, str) or len(path_name) > 32:
            raise ValueError("path_name must be ≤ 32 characters")

    @staticmethod
    def _check_file_exists(client_id, file_name, conn) -> bool:
        try:
            # Execute SQL query to count the number of files with the given client_id and file_name
            cursor = conn.execute('''
                SELECT COUNT(*) FROM files WHERE client_id = ? AND file_name = ?
            ''', (client_id, file_name))

            # Fetch the result and check if the count is greater than 0
            result = cursor.fetchone()[0] > 0
            return result  # Return True if the file exists, otherwise False
        except sqlite3.Error as e:
            print(e)  # Print the error message if an SQLite error occurs
            return False  # Return False if an error occurs

    def update_file_verified(self, client_id, file_name, verified) -> None:
        # Acquire the shared lock to ensure thread-safe access to the database
        with DataBaseManager.shared_lock:
            try:
                # Create a new database connection
                conn = self._create_connection()
                # Execute the SQL query to update the 'verified' status of the file
                conn.execute('''
                    UPDATE files SET verified = ? WHERE client_id = ? AND file_name = ?
                ''', (verified, client_id, file_name))
                # Commit the transaction to save changes
                conn.commit()
                # Close the database connection
                conn.close()
            except sqlite3.Error as e:
                # Print the error message if an SQLite error occurs
                print(e)

    def add_public_key(self, client_id, public_key) -> None:
        # Acquire the shared lock to ensure thread-safe access to the database
        with DataBaseManager.shared_lock:
            try:
                # Create a new database connection
                conn = self._create_connection()
                # Execute the SQL query to update the public key for the given client_id
                conn.execute('''
                    UPDATE clients SET public_key = ? WHERE client_id = ?
                ''', (public_key, client_id))
                # Commit the transaction to save changes
                conn.commit()
                # Close the database connection
                conn.close()
            except sqlite3.Error as e:
                # Print the error message if an SQLite error occurs
                print(e)

    def add_aes_key(self, client_id, aes_key) -> None:
        # Acquire the shared lock to ensure thread-safe access to the database
        with DataBaseManager.shared_lock:
            try:
                # Create a new database connection
                conn = self._create_connection()
                # Execute the SQL query to update the AES key for the given client_id
                conn.execute('''
                    UPDATE clients SET aes_key = ? WHERE client_id = ?
                ''', (aes_key, client_id))
                # Commit the transaction to save changes
                conn.commit()
                # Close the database connection
                conn.close()
            except sqlite3.Error as e:
                # Print the error message if an SQLite error occurs
                print(e)

    def get_client(self, client_id) -> Optional[Tuple[str, str, str, str]]:
        # Acquire the shared lock to ensure thread-safe access to the database
        with DataBaseManager.shared_lock:
            try:
                # Create a new database connection
                conn = self._create_connection()
                # Execute the SQL query to retrieve client information based on client_id
                cursor = conn.execute('''
                    SELECT client_name, public_key, last_seen, aes_key FROM clients WHERE client_id = ?
                ''', (client_id,))
                # Fetch the first result from the query
                result = cursor.fetchone()
                # Close the database connection
                conn.close()
                # Return the result (client_name, public_key, last_seen, aes_key) or None if no result is found
                return result
            except sqlite3.Error as e:
                # Print the error message if an SQLite error occurs
                print(e)
                return None

    def get_client_id(self, client_name) -> Optional[bytes]:
        # Acquire the shared lock to ensure thread-safe access to the database
        with DataBaseManager.shared_lock:
            try:
                # Create a new database connection
                conn = self._create_connection()
                # Execute the SQL query to retrieve the client_id based on client_name
                cursor = conn.execute('''
                    SELECT client_id FROM clients WHERE client_name = ?
                ''', (client_name,))
                # Fetch the first result from the query
                result = cursor.fetchone()
                # Close the database connection
                conn.close()
                # Return the client_id or None if no result is found
                return result[0]
            except sqlite3.Error as e:
                # Print the error message if an SQLite error occurs
                print(e)
                return None

    def update_last_seen(self, client_id) -> None:
        # Acquire the shared lock to ensure thread-safe access to the database
        with DataBaseManager.shared_lock:
            try:
                # Create a new database connection
                conn = self._create_connection()
                # Get the current timestamp in ISO format
                last_seen = datetime.now().isoformat()
                # Execute the SQL query to update the last_seen timestamp for the given client_id
                conn.execute('''
                    UPDATE clients SET last_seen = ? WHERE client_id = ?
                ''', (last_seen, client_id))
                # Commit the transaction to save changes
                conn.commit()
                # Close the database connection
                conn.close()
            except sqlite3.Error as e:
                # Print the error message if an SQLite error occurs
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


