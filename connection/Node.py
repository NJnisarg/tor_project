"""
This class holds information about each hop of a circuit.
"""


class Node:

    def __init__(self, host, port, identity_key, onion_key):
        self.host = host
        self.port = port
        self.identity_key = identity_key
        self.onion_key = onion_key
