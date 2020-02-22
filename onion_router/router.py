import threading

from connection.skt import Skt
from onion_router.circuit import Circuit


class OnionRouter:

    def __init__(self, node=None):
        """
        The Constructor for Onion Router
        :param node: The node Object that will be used for the router.
        """
        self.node = node
        self.skt = Skt(node.host, node.port)  # The Socket object for the router to get new connection
        self.circuits_list = []  # The list of circuits
        self.circuits_threads = []  # The list of threads corresponding to circuits
        self.current_circ_id = 0  # Holds the circuit id for the router

    def get_rand_circ_id(self) -> int:
        """
        Simple incrementing circ id generator for router
        :return: the next circuit id
        """
        self.current_circ_id += 1
        return self.current_circ_id

    def listen(self):
        """
        Listen on the socket
        :return: nothing if works, -1 if error
        """
        l = self.skt.server_listen()
        if l != 0:
            print("Error listening")
            exit(0)
        return -1

    def accept(self):
        """
        Accept a socket connection and start a new circuit thread
        :return: -1 if error comes
        """

        # Accept the connection
        a = self.skt.server_accept()
        if a != 0:
            print("Error accepting connection")
            exit(0)

        # Fetch a new circuit ID
        cktid = self.get_rand_circ_id()

        # Create a new circuit and add it to the list
        ckt = Circuit(cktid, self.node, self.skt.conn)
        self.circuits_list.append(ckt)

        # Create a new thread that starts circuit's main function
        # Add the thread to the list
        circuit_th = threading.Thread(target=ckt.main, args=())
        self.circuits_threads.append(circuit_th)
        circuit_th.start()

        return -1
