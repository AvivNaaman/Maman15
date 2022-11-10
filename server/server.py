import socket
from session import ClientSession
import logging

from db import Database


class Server:
    """ Represents an instance of a server. """

    PORT_INFO_FILENAME = "port.info"
    DEFAULT_PORT = 1234
    BIND_HOST = '0.0.0.0'

    def __init__(self):
        self.__port = self.__get_port_number()

    def __get_port_number(self):
        """ Returns the bind port of the server. """
        try:
            with open(self.PORT_INFO_FILENAME) as file:
                return int(file.readline())
        except:
            logging.warning(f"Failed to get port number from {self.PORT_INFO_FILENAME}."
                            f" falling back to default port number {self.DEFAULT_PORT}.")

    def start(self):
        """ Starts the created server instance. """
        database = Database()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

                server.bind((self.BIND_HOST, self.__port))
                server.listen()

                logging.info(f"Server bounded to {self.BIND_HOST}:{self.__port}. Waiting for clients.")

                while True:
                    client_socket, address = server.accept()
                    logging.info(f"Got a new client from address {address}.")
                    ClientSession(client_socket, database).start()
        except:
            database.close()