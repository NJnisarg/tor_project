from connection.skt import Skt


class OnionProxy:

    def __init__(self, node):
        """
        The Constructor for Onion Router
        :param node: The node Object that will be used for the router
        :param is_exit_node: The Policy for the node. Defaults to true
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
