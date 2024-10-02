import socket
import threading
import uuid
from AES_EncryptionKey import AES_EncryptionKey
import Crypto
# Define the chunk size (1024 bytes)
CHUNK_SIZE = 1024
HEADER_SIZE = 23
STRING_SIZE = 255

REGISTER_REQUEST = 825
RECEIVED_PUBLIC_KEY = 826
RECONNECT_REQUEST = 827
RECEIVE_FILE = 828
CRC_OK = 900
CRC_NOT_OK = 901
CRC_TERMINATION = 902

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

    def __init__(self, client_socket, server: 'Server',database: 'DataBaseManager'):
        self.client_socket = client_socket
        self.client_header = None
        self.header_to_send = None
        self.server = server
        self.version = None
        self.client_id_binary = None
        self.client_id = None
        self.client_name = None
        self.op_code = None
        self.payload = None
        self.payload_size = 0
        self.database = database
        self.decrypted_file_size = 0
        self.encrypted_file_size = 0
        self.file_name = None
        self.cksum = 0
        self.flag_connected = True
        self.conn_db = self.database.create_connection()
        self.aes_key_obj = AES_EncryptionKey()

    def start(self):
        """Starts the client handler by receiving data from the client."""
        self.receive()
        self.send(self.header_to_send)

        if self.flag_connected:
            self.start()

    def send(self, data):
        """Sends data to the client in a thread-safe manner using a shared lock."""
        with ClientHandler.shared_lock:
            print('Sending data...')
            print('op code:', self.op_code)
            total_sent = 0
            while total_sent < len(data):
                sent = self.client_socket.send(data[total_sent:total_sent + CHUNK_SIZE])
                print(f"Sent {sent} bytes")
                if sent == 0:
                    raise RuntimeError("Socket connection broken")
                total_sent += sent
            print("Sent all data")


    def receive(self):
        """Receives data from the client in a thread-safe manner, in chunks of 1024 bytes."""
        with ClientHandler.shared_lock:
            chunks = []
            while True:
                chunk = self.client_socket.recv(CHUNK_SIZE)
                print(f"Received {len(chunk)} bytes")
                if not chunk or len(chunk) < CHUNK_SIZE:
                    chunks.append(chunk)
                    break
                chunks.append(chunk)
            print("Received all chunks")
            self.client_header = b''.join(chunks)

        self.parse_header()

    def parse_header(self):
        """Parses the client header and returns the client ID and file size."""
        # First, decode the header first 23bytes
        self.client_id_binary = self.client_header[:16]
        self.client_id = uuid.UUID(bytes = self.client_id_binary)
        self.version = self.client_header[16]
        self.op_code = int.from_bytes(self.client_header[17:19], 'big')
        self.payload_size = int.from_bytes(self.client_header[19:HEADER_SIZE], 'big')
        self.payload = self.client_header[HEADER_SIZE:]
        self.handel_client_request_opCode()

    def handel_client_request_opCode(self):
        if self.op_code == REGISTER_REQUEST:
            self.register()

        elif self.op_code == RECEIVED_PUBLIC_KEY:
            public_key = self.payload[STRING_SIZE:]
            self.aes_key_obj.receive_rsa_public_key(public_key)
            self.database.add_public_key(self.client_id_binary, public_key)
            self.database.add_aes_key(self.client_id_binary, self.aes_key_obj.get_aes_key())
            self.op_code = RECEIVED_PUBLIC_KEY_ACK_SENDING_AES

        elif self.op_code == RECONNECT_REQUEST:
            if self.load_client_from_db():
                self.op_code = RECEIVED_PUBLIC_KEY_ACK_SENDING_AES
            else:
                self.op_code = RECONNECT_NACK
        elif self.op_code == RECEIVE_FILE:
            self.encrypted_file_size = int.from_bytes(self.payload[:4], 'big')
            self.decrypted_file_size = int.from_bytes(self.payload[4:8], 'big')
            self.file_name = self.payload[8:8+STRING_SIZE].split(b'\0', 1)[0]
            self.file_name = self.file_name.decode('utf-8')
            self.payload = self.payload[8+STRING_SIZE:]

            if self.encrypted_file_size != len(self.payload):
                self.op_code = CRC_TERMINATION
            else:
                try:
                    self.cksum = self.aes_key_obj.decrypt_and_save_file(self.payload, self.file_name)
                    self.database.add_file(self.client_id_binary, self.file_name, self.file_name, 0, self.conn_db)
                    self.op_code = RECEIVED_FILE_ACK_WITH_CRC
                except Exception as e:
                    print(f"Error decrypting file: {e}")
                    self.op_code = CRC_NOT_OK


        elif self.op_code == CRC_OK:
            self.database.update_file_verified(self.client_id_binary, self.file_name, self.file_name, 0)
            self.op_code = RECEIVED_MESSAGE_ACK

        elif self.op_code == CRC_NOT_OK:
            self.op_code = RECEIVED_FILE_ACK_WITH_CRC

        elif self.op_code == CRC_TERMINATION:
            self.op_code = RECEIVED_MESSAGE_ACK

        else:
            self.op_code = GENERAL_ERROR
        self.handle_send_opCode(self.op_code)

    def handle_send_opCode(self, op_code):
        self.payload = self.client_id_binary
        if op_code == RECEIVED_PUBLIC_KEY_ACK_SENDING_AES:
            aes_key = self.aes_key_obj.get_encrypted_aes_key()
            self.add_payload(aes_key)
        elif op_code == REGISTER_NACK:
            self.payload = b''
        elif op_code == RECEIVED_FILE_ACK_WITH_CRC:
            self.add_payload(self.encrypted_file_size)
            self.add_payload(self.file_name + b'\0' * (STRING_SIZE - len(self.file_name)))
            self.add_payload(self.cksum)
        self.header_to_send = self.create_header_to_send(op_code)

    def register(self):
        self.client_name = self.payload.split(b'\0', 1)[0].decode('utf-8')
        if self.database.add_client(self.client_name, self.conn_db):
            print(f"Client {self.client_name} registered successfully")
            self.op_code = REGISTER_ACK
            self.client_id_binary = self.database.get_client_id(self.client_name)
            self.client_id = uuid.UUID(bytes = self.client_id_binary)
        else:
            print(f"Client {self.client_name} failed to register")
            self.op_code = REGISTER_NACK



    def create_header_to_send(self, opcode):
        """Creates a header with the given opcode and payload."""
        header = self.server.get_server_version().to_bytes(1, 'big')
        header += opcode.to_bytes(2, 'big')
        header += len(self.payload).to_bytes(4, 'big')
        header += self.payload
        return header
    def add_payload(self, payload):
        if type(payload) == bytes:
            self.payload += payload
        elif type(payload) == str:
            self.payload += payload.encode('utf-8')
        elif type(payload) == int:
            self.payload += payload.to_bytes(4, 'big')
        else:
            raise ValueError("Invalid payload type")
    def load_client_from_db(self):
        client = self.database.get_client(self.client_id_binary)
        if client:
            self.client_name = client[0]
            self.aes_key_obj.receive_rsa_public_key(client[1])
            self.database.update_last_seen(self.client_id_binary)
            self.aes_key_obj.update_aes_key(client[3])
            return True
        return False


