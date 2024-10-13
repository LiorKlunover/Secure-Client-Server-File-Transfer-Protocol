# import socket
# import threading
# import uuid
# from AES_EncryptionKey import AES_EncryptionKey
#
# # Constants
# CHUNK_SIZE = 1024
# HEADER_SIZE = 23
# STRING_SIZE = 255
#
# # Operation Codes
# REGISTER_REQUEST = 825
# RECEIVED_PUBLIC_KEY = 826
# RECONNECT_REQUEST = 827
# RECEIVE_FILE = 828
# CRC_OK = 900
# CRC_NOT_OK = 901
# CRC_TERMINATION = 902
# TERMINATION_REQUEST = 903
#
# # Response Codes
# REGISTER_ACK = 1600
# REGISTER_NACK = 1601
# RECEIVED_PUBLIC_KEY_ACK_SENDING_AES = 1602
# RECEIVED_FILE_ACK_WITH_CRC = 1603
# RECEIVED_MESSAGE_ACK = 1604
# RECONNECT_ACK_SENDING_AES = 1605
# RECONNECT_NACK = 1606
# GENERAL_ERROR = 1607
#
# class ClientHandler:
#     # Class-level lock shared by all instances of ClientHandler
#     shared_lock = threading.Lock()
#
#     def __init__(self, client_socket, server: 'Server', database: 'DataBaseManager'):
#         self.client_socket = client_socket
#         self.server = server
#         self.database = database
#         self.aes_key_obj = AES_EncryptionKey()
#
#         # Initialize client state
#         self.client_header = None
#         self.header_to_send = None
#         self.version = None
#         self.client_id_binary = None
#         self.client_id = None
#         self.client_name = None
#         self.op_code = None
#         self.payload = None
#         self.payload_size = 0
#         self.flag_connected = True
#
#         # File transfer state
#         self.decrypted_file_size = 0
#         self.encrypted_file_size = 0
#         self.file_name = None
#         self.cksum = 0
#
#
#     def start(self):
#         """Starts the client handler by receiving data from the client."""
#         self.receive()
#         self.send(self.header_to_send)
#
#         if self.flag_connected:
#             self.start()
#         else:
#             print("Terminating connection")
#
#     def send(self, data):
#         """Sends data to the client in a thread-safe manner using a shared lock."""
#         with ClientHandler.shared_lock:
#             print('Sending data...')
#
#             print('Sending op code: ', self.op_code)
#             total_sent = 0
#             while total_sent < len(data):
#                 sent = self.client_socket.send(data[total_sent:total_sent + CHUNK_SIZE])
#                 print(f"Sent {sent} bytes")
#                 if sent == 0:
#                     raise RuntimeError("Socket connection broken")
#                 total_sent += sent
#             print("Sent all data")
#
#     def receive(self):
#         """Receives data from the client in a thread-safe manner, in chunks of 1024 bytes."""
#         with ClientHandler.shared_lock:
#             chunks = []
#             while True:
#                 chunk = self.client_socket.recv(CHUNK_SIZE)
#                 if not chunk or len(chunk) < CHUNK_SIZE:
#                     chunks.append(chunk)
#                     break
#                 chunks.append(chunk)
#             print("Received all chunks: ", len(chunks))
#             self.client_header = b''.join(chunks)
#
#         self.parse_header()
#
#     def parse_header(self):
#         """Parses the client header and returns the client ID and file size."""
#         # First, decode the header first 23bytes
#         self.client_id_binary = self.client_header[:16]
#         self.client_id = uuid.UUID(bytes = self.client_id_binary)
#         self.version = self.client_header[16]
#         self.op_code = int.from_bytes(self.client_header[17:19], 'big')
#         print(f"Received op code: {self.op_code}")
#         self.payload_size = int.from_bytes(self.client_header[19:HEADER_SIZE], 'big')
#         self.payload = self.client_header[HEADER_SIZE:]
#         self.handel_received_opCode()
#
#     def handel_received_opCode(self):
#         if self.op_code == REGISTER_REQUEST:
#             self.register()
#
#         elif self.op_code == RECEIVED_PUBLIC_KEY:
#             public_key = self.payload[STRING_SIZE:]
#             self.aes_key_obj.receive_rsa_public_key(public_key)
#             self.database.add_public_key(self.client_id_binary, public_key)
#             self.database.add_aes_key(self.client_id_binary, self.aes_key_obj.get_aes_key())
#             self.op_code = RECEIVED_PUBLIC_KEY_ACK_SENDING_AES
#
#         elif self.op_code == RECONNECT_REQUEST:
#             if self.load_client_from_db():
#                 self.op_code = RECONNECT_ACK_SENDING_AES
#             else:
#                 self.op_code = RECONNECT_NACK
#         elif self.op_code == RECEIVE_FILE:
#             self.encrypted_file_size = int.from_bytes(self.payload[:4], 'big')
#             self.decrypted_file_size = int.from_bytes(self.payload[4:8], 'big')
#             self.file_name = self.payload[8:8+STRING_SIZE].split(b'\0', 1)[0]
#             self.file_name = self.file_name.decode('utf-8')
#             self.payload = self.payload[8+STRING_SIZE:]
#
#             if self.encrypted_file_size != len(self.payload):
#                 self.op_code = CRC_TERMINATION
#             else:
#                 try:
#                     self.cksum = self.aes_key_obj.decrypt_and_save_file(self.payload, self.file_name)
#                     print(f"csum: {self.cksum}")
#                     if self.database.add_file(self.client_id_binary, self.file_name, self.file_name, 0):
#                         self.op_code = RECEIVED_FILE_ACK_WITH_CRC
#                     else:
#                         self.op_code = GENERAL_ERROR
#                 except Exception as e:
#                     print(f"Error decrypting file: {e}")
#                     self.op_code = GENERAL_ERROR
#
#         elif self.op_code == CRC_OK:
#             self.database.update_file_verified(self.client_id_binary, self.file_name, True)
#             self.op_code = RECEIVED_MESSAGE_ACK
#             self.flag_connected = False
#         elif self.op_code == CRC_NOT_OK:
#             self.op_code = RECEIVED_FILE_ACK_WITH_CRC
#
#         elif self.op_code == CRC_TERMINATION:
#             self.op_code = RECEIVED_MESSAGE_ACK
#         elif self.op_code == TERMINATION_REQUEST:
#             self.op_code = RECEIVED_MESSAGE_ACK
#         else:
#             self.op_code = GENERAL_ERROR
#         self.handle_send_opCode(self.op_code)
#
#     def handle_send_opCode(self, op_code):
#         self.payload = self.client_id_binary
#         if op_code == RECEIVED_PUBLIC_KEY_ACK_SENDING_AES or op_code == RECONNECT_ACK_SENDING_AES:
#             aes_key = self.aes_key_obj.get_encrypted_aes_key()
#             self.add_payload(aes_key)
#         elif op_code == REGISTER_NACK:
#             self.payload = b''
#         elif op_code == RECEIVED_FILE_ACK_WITH_CRC:
#             self.add_payload(self.encrypted_file_size)
#             file_name = self.file_name.encode('utf-8') + b'\0' * (STRING_SIZE - len(self.file_name))
#             self.add_payload(file_name)
#             self.add_payload(self.cksum)
#         elif op_code == RECEIVED_MESSAGE_ACK:
#             self.flag_connected = False
#         self.header_to_send = self.create_header_to_send(op_code)
#
#     def register(self):
#         self.client_name = self.payload.split(b'\0', 1)[0].decode('utf-8')
#         if self.database.add_client(self.client_name):
#             print(f"Client {self.client_name} registered successfully")
#             self.op_code = REGISTER_ACK
#             self.client_id_binary = self.database.get_client_id(self.client_name)
#             self.client_id = uuid.UUID(bytes = self.client_id_binary)
#         else:
#             print(f"Client {self.client_name} failed to register")
#             self.op_code = REGISTER_NACK
#
#     def create_header_to_send(self, opcode):
#         """Creates a header with the given opcode and payload."""
#         header = self.server.get_server_version().to_bytes(1, 'big')
#         header += opcode.to_bytes(2, 'big')
#         header += len(self.payload).to_bytes(4, 'big')
#         header += self.payload
#         return header
#     def add_payload(self, payload):
#         if type(payload) == bytes:
#             self.payload += payload
#         elif type(payload) == str:
#             self.payload += payload.encode('utf-8')
#         elif type(payload) == int:
#             self.payload += payload.to_bytes(4, 'big')
#         else:
#             raise ValueError("Invalid payload type")
#     def load_client_from_db(self):
#         client = self.database.get_client(self.client_id_binary)
#         if client:
#             self.client_name = client[0]
#             self.aes_key_obj.receive_rsa_public_key(client[1])
#             self.database.update_last_seen(self.client_id_binary)
#             self.aes_key_obj.update_aes_key(client[3])
#             return True
#         return False
#
#
#






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
        with self.shared_lock:
            self.logger.info(f'Sending op code: {self.op_code}')
            total_sent = 0
            while total_sent < len(data):
                try:
                    sent = self.client_socket.send(data[total_sent:total_sent + CHUNK_SIZE])
                    if sent == 0:
                        raise RuntimeError("Socket connection broken")
                    total_sent += sent
                except Exception as e:
                    self.logger.error(f"Error sending data: {e}")
                    raise

    def receive(self) -> None:
        """Receive data from the client in a thread-safe manner."""
        with self.shared_lock:
            try:
                chunks = []
                while True:
                    chunk = self.client_socket.recv(CHUNK_SIZE)
                    if not chunk or len(chunk) < CHUNK_SIZE:
                        chunks.append(chunk)
                        break
                    chunks.append(chunk)
                self.client_header = b''.join(chunks)

            except Exception as e:
                self.logger.error(f"Error receiving data: {e}")
                raise
        self.parse_header()

    def parse_header(self) -> None:
        """Parse the client header and extract relevant information."""
        try:
            self.client_id_binary = self.client_header[:16]
            self.client_id = uuid.UUID(bytes=self.client_id_binary)
            self.version = self.client_header[16]
            self.op_code = int.from_bytes(self.client_header[17:19], 'big')
            self.payload_size = int.from_bytes(self.client_header[19:HEADER_SIZE], 'big')
            self.payload = self.client_header[HEADER_SIZE:]
            self.error_msg = ""
            self.logger.info(f"Parsed header - OpCode received: {self.op_code}, PayloadSize: {self.payload_size}")
            self.handle_received_opcode()
        except Exception as e:
            self.logger.error(f"Error parsing header: {e}")
            self.op_code = GENERAL_ERROR
            self.handle_send_opcode(self.op_code)

    def handle_received_opcode(self) -> None:
        """Handle different operation codes received from the client."""
        if self.op_code == REGISTER_REQUEST:
            self._handle_register_request()

        elif self.op_code == RECEIVED_PUBLIC_KEY:
            self._handle_public_key()

        elif self.op_code == RECONNECT_REQUEST:
            self._handle_reconnect_request()

        elif self.op_code == RECEIVE_FILE:
            self._handle_receive_file()

        elif self.op_code == CRC_OK:
            self._handle_crc_ok()

        elif self.op_code == CRC_NOT_OK:
            self.error_msg = "Received invalid CRC"
            self.op_code = RECEIVED_MESSAGE_ACK

        elif self.op_code == CRC_TERMINATION:
            self.flag_connected = False
            self.op_code = RECEIVED_MESSAGE_ACK

        elif self.op_code == TERMINATION_REQUEST:
            self.flag_connected = False
            self.op_code = RECEIVED_MESSAGE_ACK
        else:
            self.op_code = GENERAL_ERROR

        self.handle_send_opcode(self.op_code)

    def handle_send_opcode(self, op_code: int) -> None:
        """Prepare response based on operation code."""
        self.payload = self.client_id_binary

        if op_code == RECEIVED_PUBLIC_KEY_ACK_SENDING_AES or op_code == RECONNECT_ACK_SENDING_AES:
            aes_key = self.aes_key_obj.get_encrypted_aes_key()
            self.add_payload(aes_key)
        elif op_code == REGISTER_NACK:
            self.payload = b''
        elif op_code == RECEIVED_FILE_ACK_WITH_CRC:
            self.add_payload(self.encrypted_file_size)
            file_name = self.file_name.encode('utf-8') + b'\0' * (STRING_SIZE - len(self.file_name))
            self.add_payload(file_name)
            self.add_payload(self.cksum)
        elif op_code == RECEIVED_MESSAGE_ACK:
            self.add_payload(self.error_msg)

        self.header_to_send = self.create_header_to_send(op_code)

    def _handle_register_request(self) -> None:
        """Handle client registration request."""
        self.client_name = self.payload.split(b'\0', 1)[0].decode('utf-8')
        if self.database.add_client(self.client_name):
            print(f"Client {self.client_name} registered successfully")
            self.op_code = REGISTER_ACK
            self.client_id_binary = self.database.get_client_id(self.client_name)
            self.client_id = uuid.UUID(bytes = self.client_id_binary)
        else:
            print(f"Client {self.client_name} failed to register")
            self.error_msg = f"Client {self.client_name} already exists"
            self.op_code = REGISTER_NACK

    def _handle_public_key(self) -> None:
        """Handle received public key from client."""
        public_key = self.payload[STRING_SIZE:]
        self.aes_key_obj.receive_rsa_public_key(public_key)
        self.database.add_public_key(self.client_id_binary, public_key)
        self.database.add_aes_key(self.client_id_binary, self.aes_key_obj.get_aes_key())
        self.op_code = RECEIVED_PUBLIC_KEY_ACK_SENDING_AES

    def _handle_reconnect_request(self) -> None:
        """Handle client reconnection request."""
        if self.load_client_from_db():
            self.op_code = RECONNECT_ACK_SENDING_AES
        else:
            self.op_code = RECONNECT_NACK

    def _handle_receive_file(self) -> None:
        """Handle file reception from client."""
        try:
            self._parse_file_metadata()
            if self.encrypted_file_size != len(self.payload):
                self.op_code = CRC_TERMINATION
                return

            self._process_received_file()
        except Exception as e:
            self.logger.error(f"Error handling file reception: {e}")
            self.op_code = GENERAL_ERROR

    def _parse_file_metadata(self) -> None:
        """Parse metadata for received file."""
        self.encrypted_file_size = int.from_bytes(self.payload[:4], 'big')
        self.decrypted_file_size = int.from_bytes(self.payload[4:8], 'big')
        self.file_name = self.payload[8:8 + STRING_SIZE].split(b'\0', 1)[0].decode('utf-8')
        self.payload = self.payload[8 + STRING_SIZE:]

    def _process_received_file(self) -> None:
        """Process and save received file."""
        try:
            self.cksum = self.aes_key_obj.decrypt_and_save_file(self.payload, self.file_name)
            if self.database.add_file(self.client_id_binary, self.file_name, self.file_name, False):
                self.op_code = RECEIVED_FILE_ACK_WITH_CRC
            else:
                self.op_code = GENERAL_ERROR
        except Exception as e:
            self.logger.error(f"Error processing file: {e}")
            self.op_code = GENERAL_ERROR

    def _handle_crc_ok(self) -> None:
        """Handle CRC OK response from client."""
        self.database.update_file_verified(self.client_id_binary, self.file_name, True)
        self.op_code = RECEIVED_MESSAGE_ACK
        self.flag_connected = False

    def create_header_to_send(self, opcode: int) -> bytes:
        """Create a header with the given opcode and payload."""
        return (
                self.server.get_server_version().to_bytes(1, 'big') +
                opcode.to_bytes(2, 'big') +
                len(self.payload).to_bytes(4, 'big') +
                self.payload
        )

    def add_payload(self, payload: Union[bytes, str, int]) -> None:
        """Add data to the payload in the correct format."""
        if isinstance(payload, bytes):
            self.payload += payload
        elif isinstance(payload, str):
            self.payload += payload.encode('utf-8')
        elif isinstance(payload, int):
            self.payload += payload.to_bytes(4, 'big')
        else:
            raise ValueError(f"Invalid payload type: {type(payload)}")




    def load_client_from_db(self) -> bool:
        """Load client information from database."""
        client = self.database.get_client(self.client_id_binary)
        if client:
            self.client_name, public_key, _, aes_key = client
            self.aes_key_obj.receive_rsa_public_key(public_key)
            self.database.update_last_seen(self.client_id_binary)
            self.aes_key_obj.update_aes_key(aes_key)
            return True
        return False



