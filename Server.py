import socket
import threading
from ClientHandler import ClientHandler
from DataBaseManager import DataBaseManager

class Server:
    def __init__(self, host='0.0.0.0'):
        self.host = host
        self.version = 20
        self.port = self.get_port_from_file()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_db = DataBaseManager()
        print(f"Server listening on {self.host}:{self.port}")


    def get_port_from_file(self):
        try:
            with open("port.info", "r") as f:
                return int(f.read())
        except FileNotFoundError:
            print("File not found")
            return 1256

    def get_server_version(self):
        return self.version

    def start(self):
        """Start accepting clients and spawn threads for handling them."""
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Accepted connection from {addr}")
            client_handler = ClientHandler(client_socket, self, self.server_db)
            client_thread = threading.Thread(target=self.handle_client, args=(client_handler,))

            client_thread.start()

    def handle_client(self, client_handler):
        """Handle client interaction - send/receive request or messages."""
        try:
            # For demonstration: Receive client request
            print("Receiving client request...")
            client_handler.start()

            # Sending acknowledgment after receiving the file
            # client_handler.send(b'File received successfully

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_handler.client_socket.close()

if __name__ == "__main__":
    server = Server('127.0.0.1')
    server.start()


