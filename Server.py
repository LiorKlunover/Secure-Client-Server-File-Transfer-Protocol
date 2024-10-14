
"""
Secure File Transfer Server

This module implements a secure, multi-threaded server for handling encrypted file transfers.
It uses AES encryption for file content and manages client connections through a SQLite database.

Author: Lior Klunover
Version: 1.0.0
"""

import logging
import socket
import threading
import sys
from typing import Optional, Tuple
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass
from contextlib import contextmanager

from ClientHandler import ClientHandler
from DataBaseManager import DataBaseManager

# Constants
DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 1256
MAX_CONNECTIONS = 5
LOGGER_NAME = 'secure_transfer_server'


@dataclass
class ServerConfig:
    """Server configuration parameters."""
    host: str
    port: int
    max_connections: int
    db_path: str


class SecureTransferServer:
    """
    A secure file transfer server that handles multiple client connections.

    This server uses threading to handle multiple clients simultaneously and
    maintains encrypted connections for secure file transfers.

    Attributes:
        config (ServerConfig): Server configuration parameters
        logger (logging.Logger): Logger instance for server operations
        _running (bool): Flag indicating if the server is running
        _server_socket (Optional[socket.socket]): Server socket instance
        _clients (set): Set of active client handlers
    """

    def __init__(self, config: ServerConfig):
        """
        Initialize the server with the given configuration.

        Args:
            config (ServerConfig): Server configuration parameters
        """
        self.config = config
        self.logger = self._setup_logging()
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._clients = set()
        self.version = 20
        try:
            self.database = DataBaseManager(self.config.db_path)
            self.logger.info("Database connection established successfully")
        except Exception as e:
            self.logger.critical(f"Failed to initialize database: {e}")
            raise

    @staticmethod
    def _setup_logging() -> logging.Logger:
        """Configure and return a logger for the server."""
        logger = logging.getLogger(LOGGER_NAME)
        logger.setLevel(logging.INFO)

        # File handler with rotation
        file_handler = RotatingFileHandler(
            'server.log', maxBytes=10485760, backupCount=5)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s'))

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'))

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    @contextmanager
    def _create_server_socket(self):
        """Context manager for server socket creation and cleanup."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.config.host, self.config.port))
            self._server_socket.listen(self.config.max_connections)
            yield self._server_socket
        finally:
            if self._server_socket:
                self._server_socket.close()
                self._server_socket = None

    def start(self) -> None:
        """Start the server and begin accepting client connections."""
        self._running = True
        self.logger.info(f"Starting server on {self.config.host}:{self.config.port}")

        with self._create_server_socket():
            while self._running:
                try:
                    self._accept_client()
                except KeyboardInterrupt:
                    self.logger.info("Server shutdown initiated by user")
                    break
                except Exception as e:
                    self.logger.error(f"Error in main server loop: {e}")
                    continue

    def stop(self) -> None:
        """Gracefully stop the server and cleanup resources."""
        self.logger.info("Stopping server...")
        self._running = False

        # Close all client connections
        for client in self._clients.copy():
            client.stop()

        self.database.close()
        self.logger.info("Server stopped successfully")

    def _accept_client(self) -> None:
        """Accept a new client connection and start handling it in a new thread."""
        try:
            client_socket, addr = self._server_socket.accept()
            self.logger.info(f"New connection from {addr}")

            client_handler = ClientHandler(client_socket, self, self.database,self.logger)
            self._clients.add(client_handler)

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(client_handler,),
                name=f"ClientThread-{addr[0]}:{addr[1]}"
            )
            client_thread.daemon = True
            client_thread.start()

        except Exception as e:
            self.logger.error(f"Error accepting client connection: {e}")

    def _handle_client(self, client_handler: ClientHandler) -> None:
        """
        Handle a client connection in a separate thread.

        Args:
            client_handler (ClientHandler): The client handler instance
        """
        try:
            client_handler.start()
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
        finally:
            self._clients.remove(client_handler)

    def get_server_version(self) -> int:
        """Return the server version."""
        return self.version

    @classmethod
    def from_port_file(cls, host: str = DEFAULT_HOST) -> 'SecureTransferServer':
        """
        Create a server instance with port read from a file.

        Args:
            host (str): Host address to bind to

        Returns:
            SecureTransferServer: A new server instance
        """
        try:
            with open("port.info", "r") as f:
                port = int(f.read().strip())
        except (FileNotFoundError, ValueError) as e:
            logging.warning(f"Failed to read port from file: {e}. Using default port.")
            port = DEFAULT_PORT

        config = ServerConfig(
            host=host,
            port=port,
            max_connections=MAX_CONNECTIONS,
            db_path= 'defensive.db'
        )
        return cls(config)


def main():
    """Main function to run the server."""
    server = SecureTransferServer.from_port_file('127.0.0.1')

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutdown signal received")
    finally:
        server.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
