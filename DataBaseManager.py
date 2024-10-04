
import sqlite3
import threading
import uuid
import datetime

class DataBaseManager:
    shared_lock = threading.Lock()  # Shared lock across all instances

    def __init__(self):
        self.db_path = 'defensive.db'
        self.create_tables()

    def create_connection(self):
        """Create a new SQLite connection for each thread."""
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def create_tables(self):
        """Create the necessary tables (executed once per instance)."""
        conn = self.create_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                client_id BLOB PRIMARY KEY,
                client_name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                aes_key TEXT NOT NULL
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                client_id BLOB PRIMARY KEY,
                file_name TEXT NOT NULL ,
                path_name TEXT NOT NULL,
                verified BOOLEAN NOT NULL,
                FOREIGN KEY (client_id) REFERENCES clients(client_id)
            )
        ''')

        conn.commit()
        conn.close()

    def add_client(self, client_name, conn) -> bool:
        with DataBaseManager.shared_lock:
            try:
                if self.check_client_name_exists(client_name, conn):
                    print("Client already exists")
                    return False
                client_id = uuid.uuid4().bytes  # Generate a 128-bit UUID
                last_seen = datetime.datetime.now().isoformat()
                conn.execute('''
                    INSERT INTO clients (client_id, client_name, public_key, last_seen, aes_key)
                    VALUES (?, ?, ?, ?, ?)
                ''', (client_id, client_name,'', last_seen, ''))
                conn.commit()
                return True
            except sqlite3.Error as e:
                print(e)
                return False
        return False

    def add_file(self, client_id, file_name, path_name, verified, conn):
        with DataBaseManager.shared_lock:
            # Check if client_id is exactly 16 bytes
            if not isinstance(client_id, bytes) or len(client_id) != 16:
                raise ValueError("client_id must be exactly 16 bytes.")

            # Check if file_name and path_name are strings and less than or equal to 32 characters
            if not isinstance(file_name, str) or len(file_name) > 32:
                raise ValueError("file_name must be a string with a maximum length of 32 characters.")

            if not isinstance(path_name, str) or len(path_name) > 32:
                raise ValueError("path_name must be a string with a maximum length of 32 characters.")

            # Check if verified is either 0 or 1
            if verified not in [0, 1]:
                raise ValueError("verified must be either 0 (False) or 1 (True).")
            try:
                # Ensure the client_id exists in the clients table (Foreign Key check)
                cursor = conn.execute(''' SELECT COUNT(*) FROM clients WHERE client_id = ? ''', (client_id,))
                if cursor.fetchone()[0] == 0:
                    print("Client does not exist.")
                    raise ValueError("Client does not exist.")

                # Try to insert the file into the files table
                cursor.execute('''
                           INSERT INTO files (client_id, file_name, path_name, verified) 
                           VALUES (?, ?, ?, ?)
                       ''', (client_id, file_name, path_name, verified))
                conn.commit()
                print("File added successfully.")
            except sqlite3.IntegrityError as e:
                if 'UNIQUE constraint failed' in str(e):
                    print("File already exists for this client.")
                else:
                    print(f"Error inserting file: {e}")
            finally:
                cursor.close()
                conn.close()
                print("Connection to DB closed.")
    def check_file_exists(self, client_id, file_name):
        with DataBaseManager.shared_lock:
            try:
                conn = self.create_connection()
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM files WHERE client_id = ? AND file_name = ?
                ''', (client_id, file_name))
                result = cursor.fetchone()[0] > 0
                conn.close()
                return result
            except sqlite3.Error as e:
                print(e)
                return False
    def update_file_verified(self, client_id, file_name, verified):
        with DataBaseManager.shared_lock:
            try:
                conn = self.create_connection()
                conn.execute('''
                    UPDATE files SET verified = ? WHERE client_id = ? AND file_name = ?
                ''', (verified, client_id, file_name))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(e)

    def add_public_key(self, client_id, public_key):
        with DataBaseManager.shared_lock:
            try:
                conn = self.create_connection()
                conn.execute('''
                    UPDATE clients SET public_key = ? WHERE client_id = ?
                ''', (public_key, client_id))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(e)
    def add_aes_key(self, client_id, aes_key):
        with DataBaseManager.shared_lock:
            try:
                conn = self.create_connection()
                conn.execute('''
                    UPDATE clients SET aes_key = ? WHERE client_id = ?
                ''', (aes_key, client_id))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(e)
    def get_file_path(self, client_id):
        with DataBaseManager.shared_lock:
            try:
                conn = self.create_connection()
                cursor = conn.execute('''
                    SELECT file_name, path_name, verified FROM files WHERE client_id = ?
                ''', (client_id,))
                result = cursor.fetchone()
                conn.close()
                return result
            except sqlite3.Error as e:
                print(e)
                return None

    def get_client(self, client_id):
        with DataBaseManager.shared_lock:
            try:
                conn = self.create_connection()
                cursor = conn.execute('''
                    SELECT client_name, public_key, last_seen, aes_key FROM clients WHERE client_id = ?
                ''', (client_id,))
                result = cursor.fetchone()
                conn.close()
                return result
            except sqlite3.Error as e:
                print(e)
                return None

    def get_client_id(self, client_name):
        with DataBaseManager.shared_lock:
            try:
                conn = self.create_connection()
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

    def get_aes_key(self, client_id):
        with DataBaseManager.shared_lock:
            try:
                conn = self.create_connection()
                cursor = conn.execute('''
                    SELECT aes_key FROM clients WHERE client_id = ?
                ''', (client_id,))
                result = cursor.fetchone()
                conn.close()
                return result[0]
            except sqlite3.Error as e:
                print(e)
                return None
    def update_last_seen(self, client_id):
        with DataBaseManager.shared_lock:
            try:
                conn = self.create_connection()
                last_seen = datetime.datetime.now().isoformat()
                conn.execute('''
                    UPDATE clients SET last_seen = ? WHERE client_id = ?
                ''', (last_seen, client_id))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(e)

    def close(self):
        pass  # Each thread creates and closes its own connection, so no global connection to close.


