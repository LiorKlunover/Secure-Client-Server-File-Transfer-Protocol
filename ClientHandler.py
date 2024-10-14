
import socket
import threading
import uuid
import logging

from typing import Optional, Tuple , Union
from AES_EncryptionKey import AES_EncryptionKey

# Constants
CHUNK_SIZE = 1024
HEADER_SIZE = 23
STRING_SIZE = 255

# Operation Codes
REGISTER_REQUEST = 825
RECEIVED_PUBLIC_KEY = 826
RECONNECT_REQUEST = 827
RECEIVE_FILE = 828
CRC_OK = 900
CRC_NOT_OK = 901
CRC_TERMINATION = 902
TERMINATION_REQUEST = 903

# Response Codes
REGISTER_ACK = 1600
REGISTER_NACK = 1601
RECEIVED_PUBLIC_KEY_ACK_SENDING_AES = 1602
RECEIVED_FILE_ACK_WITH_CRC = 1603
RECEIVED_MESSAGE_ACK = 1604
RECONNECT_ACK_SENDING_AES = 1605
RECONNECT_NACK = 1606
GENERAL_ERROR = 1607

class ClientHandler:
    # Class-level lock shared by all instances of ClientHandler
    shared_lock = threading.Lock()
    # Configure logging

    def __init__(self, client_socket, server: 'Server', database: 'DataBaseManager', logger):
        self.client_socket = client_socket
        self.server = server
        self.database = database
        self.aes_key_obj = AES_EncryptionKey()
        self.logger = logger
        # Initialize client state
        self.client_header = None
        self.header_to_send = None
        self.version = None
        self.client_id_binary = None
        self.client_id = None
        self.client_name = None
        self.op_code = None
        self.payload = None
        self.payload_size = 0
        self.flag_connected = True
        self.error_msg = None
        # File transfer state
        self.decrypted_file_size = 0
        self.encrypted_file_size = 0
        self.file_name = None
        self.cksum = 0


    def start(self):
        """Main loop for handling client communication."""
        try:
            while self.flag_connected:
                self.receive()
                self.send(self.header_to_send)

        except Exception as e:
            self.logger.error(f"Error in client handler: {e}")
        finally:
            self.logger.info("Terminating connection")

    def send(self, data: bytes) -> None:
        """
        Send data to the client in a thread-safe manner.

        Args:
            data (bytes): The data to send

        Raises:
            RuntimeError: If the socket connection is broken
        """
        with self.shared_lock:  # Ensure thread-safe access to the socket
            self.logger.info(f'Sending op code: {self.op_code}')  # Log the operation code being sent
            total_sent = 0  # Initialize the total number of bytes sent
            while total_sent < len(data):  # Loop until all data is sent
                try:
                    # Send a chunk of data to the client
                    sent = self.client_socket.send(data[total_sent:total_sent + CHUNK_SIZE])
                    if sent == 0:
                        raise RuntimeError("Socket connection broken")  # Raise an error if the connection is broken
                    total_sent += sent  # Update the total number of bytes sent
                except Exception as e:
                    self.logger.error(f"Error sending data: {e}")  # Log any errors that occur during sending
                    raise  # Re-raise the exception to handle it further up the call stack

    def receive(self) -> None:
        """Receive data from the client in a thread-safe manner."""
        with self.shared_lock:  # Ensure thread-safe access to the socket
            try:
                chunks = []  # Initialize a list to store received chunks
                while True:
                    chunk = self.client_socket.recv(CHUNK_SIZE)  # Receive a chunk of data from the client
                    if not chunk or len(chunk) < CHUNK_SIZE:  # Check if the chunk is empty or less than the chunk size
                        chunks.append(chunk)  # Append the last chunk to the list
                        break  # Exit the loop if no more data is received
                    chunks.append(chunk)  # Append the received chunk to the list
                self.client_header = b''.join(chunks)  # Combine all chunks into a single bytes object

            except Exception as e:
                self.logger.error(f"Error receiving data: {e}")  # Log any errors that occur during receiving
                raise  # Re-raise the exception to handle it further up the call stack
        self.parse_header()  # Parse the received header

    def parse_header(self) -> None:
        """Parse the client header and extract relevant information."""
        try:
            self.client_id_binary = self.client_header[:16]  # Extract the first 16 bytes for the client ID
            self.client_id = uuid.UUID(bytes=self.client_id_binary)  # Convert the bytes to a UUID
            self.version = self.client_header[16]  # Extract the version byte
            self.op_code = int.from_bytes(self.client_header[17:19], 'big')  # Extract the operation code (2 bytes)
            self.payload_size = int.from_bytes(self.client_header[19:HEADER_SIZE], 'big')  # Extract the payload size (4 bytes)
            self.payload = self.client_header[HEADER_SIZE:]  # Extract the payload data
            self.error_msg = ""  # Reset the error message
            self.logger.info(f"Parsed header - OpCode received: {self.op_code}, PayloadSize: {self.payload_size}")  # Log the parsed information
            self.handle_received_opcode()  # Handle the received operation code
        except Exception as e:
            self.logger.error(f"Error parsing header: {e}")  # Log any errors that occur during parsing
            self.op_code = GENERAL_ERROR  # Set the operation code to GENERAL_ERROR in case of an exception
            self.handle_send_opcode(self.op_code)  # Handle the error operation code

    def handle_received_opcode(self) -> None:
        """Handle different operation codes received from the client."""
        if self.op_code == REGISTER_REQUEST:
            self._handle_register_request()  # Handle client registration request

        elif self.op_code == RECEIVED_PUBLIC_KEY:
            self._handle_public_key()  # Handle received public key from client

        elif self.op_code == RECONNECT_REQUEST:
            self._handle_reconnect_request()  # Handle client reconnection request

        elif self.op_code == RECEIVE_FILE:
            self._handle_receive_file()  # Handle file reception from client

        elif self.op_code == CRC_OK:
            self._handle_crc_ok()  # Handle CRC check success

        elif self.op_code == CRC_NOT_OK:
            self.error_msg = "Received invalid CRC"  # Set error message for invalid CRC
            self.op_code = RECEIVED_MESSAGE_ACK  # Acknowledge received message

        elif self.op_code == CRC_TERMINATION:
            self.flag_connected = False  # Terminate connection on CRC termination
            self.op_code = RECEIVED_MESSAGE_ACK  # Acknowledge received message

        elif self.op_code == TERMINATION_REQUEST:
            self.flag_connected = False  # Terminate connection on termination request
            self.op_code = RECEIVED_MESSAGE_ACK  # Acknowledge received message

        else:
            self.op_code = GENERAL_ERROR  # Set operation code to general error for unknown op codes

        self.handle_send_opcode(self.op_code)  # Handle sending the response based on the operation code

    def handle_send_opcode(self, op_code: int) -> None:
        """Prepare response based on operation code."""
        self.payload = self.client_id_binary  # Initialize payload with client ID

        if op_code == RECEIVED_PUBLIC_KEY_ACK_SENDING_AES or op_code == RECONNECT_ACK_SENDING_AES:
            aes_key = self.aes_key_obj.get_encrypted_aes_key()  # Encrypt AES key with client's RSA public key
            self.add_payload(aes_key)  # Add encrypted AES key to payload
        elif op_code == REGISTER_NACK:
            self.payload = b''  # Set payload to empty bytes for REGISTER_NACK
        elif op_code == RECEIVED_FILE_ACK_WITH_CRC:
            self.add_payload(self.encrypted_file_size)  # Add encrypted file size to payload
            file_name = self.file_name.encode('utf-8') + b'\0' * (STRING_SIZE - len(self.file_name))  # Encode file name and pad with null bytes
            self.add_payload(file_name)  # Add file name to payload
            self.add_payload(self.cksum)  # Add checksum to payload
        elif op_code == RECEIVED_MESSAGE_ACK:
            self.add_payload(self.error_msg)  # Add error message to payload

        self.header_to_send = self.create_header_to_send(op_code)  # Create header to send with the given opcode

    def _handle_register_request(self) -> None:
        """Handle client registration request."""
        self.client_name = self.payload.split(b'\0', 1)[0].decode('utf-8')  # Extract client name from payload
        if self.database.add_client(self.client_name):  # Attempt to add client to the database
            print(f"Client {self.client_name} registered successfully")  # Print success message
            self.op_code = REGISTER_ACK  # Set operation code to REGISTER_ACK
            self.client_id_binary = self.database.get_client_id(self.client_name)  # Retrieve client ID from database
            self.client_id = uuid.UUID(bytes=self.client_id_binary)  # Convert client ID bytes to UUID
        else:
            print(f"Client {self.client_name} failed to register")  # Print failure message
            self.error_msg = f"Client {self.client_name} already exists"  # Set error message for existing client
            self.op_code = REGISTER_NACK  # Set operation code to REGISTER_NACK

    def _handle_public_key(self) -> None:
        """Handle received public key from client."""
        public_key = self.payload[STRING_SIZE:]  # Extract the public key from the payload
        self.aes_key_obj.receive_rsa_public_key(public_key)  # Receive and set the client's RSA public key
        self.database.add_public_key(self.client_id_binary, public_key)  # Add the public key to the database
        self.database.add_aes_key(self.client_id_binary, self.aes_key_obj.get_aes_key())  # Add the AES key to the database
        self.op_code = RECEIVED_PUBLIC_KEY_ACK_SENDING_AES  # Set operation code to acknowledge received public key and send AES key
    def _handle_reconnect_request(self) -> None:
        """Handle client reconnection request."""
        if self.load_client_from_db():
            self.op_code = RECONNECT_ACK_SENDING_AES  # Set operation code to acknowledge reconnection and send AES key
        else:
            self.op_code = RECONNECT_NACK  # Set operation code to indicate reconnection failure

    def _handle_receive_file(self) -> None:
        """Handle file reception from client."""
        try:
            self._parse_file_metadata()  # Parse metadata from the received file payload
            if self.encrypted_file_size != len(self.payload):  # Check if the received payload size matches the expected encrypted file size
                self.op_code = CRC_TERMINATION  # Set operation code to CRC_TERMINATION if sizes do not match
                return  # Exit the function

            self._process_received_file()  # Process the received file
        except Exception as e:
            self.logger.error(f"Error handling file reception: {e}")  # Log any errors that occur during file reception
            self.op_code = GENERAL_ERROR  # Set operation code to GENERAL_ERROR in case of an exception
    def _parse_file_metadata(self) -> None:
        """Parse metadata for received file."""
        self.encrypted_file_size = int.from_bytes(self.payload[:4], 'big')  # Extract the encrypted file size from the first 4 bytes
        self.decrypted_file_size = int.from_bytes(self.payload[4:8], 'big')  # Extract the decrypted file size from the next 4 bytes
        self.file_name = self.payload[8:8 + STRING_SIZE].split(b'\0', 1)[0].decode('utf-8')  # Extract and decode the file name, removing null padding
        self.payload = self.payload[8 + STRING_SIZE:]  # Update the payload to exclude the metadata

    def _process_received_file(self) -> None:
        """Process and save received file."""
        try:
            # Decrypt the received file and save it, returning its checksum
            self.cksum = self.aes_key_obj.decrypt_and_save_file(self.payload, self.file_name)

            # Attempt to add the file to the database
            if self.database.add_file(self.client_id_binary, self.file_name, self.file_name, False):
                self.op_code = RECEIVED_FILE_ACK_WITH_CRC  # Set operation code to acknowledge file receipt with CRC
            else:
                self.op_code = GENERAL_ERROR  # Set operation code to indicate a general error
        except Exception as e:
            self.logger.error(f"Error processing file: {e}")  # Log any errors that occur during file processing
            self.op_code = GENERAL_ERROR  # Set operation code to indicate a general error

    def _handle_crc_ok(self) -> None:
        """Handle CRC OK response from client."""
        self.database.update_file_verified(self.client_id_binary, self.file_name, True)  # Mark the file as verified in the database
        self.op_code = RECEIVED_MESSAGE_ACK  # Set operation code to acknowledge the received message
        self.flag_connected = False  # Set the connection flag to False, indicating the client should disconnect

    def create_header_to_send(self, opcode: int) -> bytes:
        """Create a header with the given opcode and payload."""
        return (
            self.server.get_server_version().to_bytes(1, 'big') +  # Convert server version to a single byte
            opcode.to_bytes(2, 'big') +  # Convert opcode to 2 bytes
            len(self.payload).to_bytes(4, 'big') +  # Convert payload length to 4 bytes
            self.payload  # Append the payload itself
        )

    def add_payload(self, payload: Union[bytes, str, int]) -> None:
        """Add data to the payload in the correct format."""
        if isinstance(payload, bytes):
            self.payload += payload  # Append bytes directly to the payload
        elif isinstance(payload, str):
            self.payload += payload.encode('utf-8')  # Encode string to bytes and append to the payload
        elif isinstance(payload, int):
            self.payload += payload.to_bytes(4, 'big')  # Convert integer to 4 bytes (big-endian) and append to the payload
        else:
            raise ValueError(f"Invalid payload type: {type(payload)}")  # Raise an error for unsupported payload types




    def load_client_from_db(self) -> bool:
        """Load client information from database."""
        client = self.database.get_client(self.client_id_binary)  # Retrieve client information from the database using client ID
        if client:
            self.client_name, public_key, _, aes_key = client  # Unpack the retrieved client information
            self.aes_key_obj.receive_rsa_public_key(public_key)  # Set the client's RSA public key in the AES encryption object
            self.database.update_last_seen(self.client_id_binary)  # Update the last seen timestamp for the client in the database
            self.aes_key_obj.update_aes_key(aes_key)  # Update the AES key in the AES encryption object
            return True  # Return True indicating the client was successfully loaded
        return False  # Return False if the client was not found in the database



