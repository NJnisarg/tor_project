import json
from node_directory_service.node_directory_service import NodeDirectoryService
from connection.node import Node
from connection.skt import Skt
from circuit import Circuit
from cell.cell import Cell, CellConstants
from crypto.core_crypto import CoreCryptoRSA


class OnionRouter:

    def __init__(self, node=None, is_exit_node=True):
        self.node = node
        self.skt = Skt(node.host, node.port)
        self.is_exit_node = is_exit_node
        self.circuits_list = []
        self.routing_table = {}

    def get_rand_circ_id(self) -> int:
        return 1

    def listen(self):
        l = self.skt.server_listen()
        if l != 0:
            print("Error listening")
            exit(0)
        return -1

    def accept(self):
        a = self.skt.server_accept()
        if a != 0:
            print("Error accepting connection")
            exit(0)
        cktid = self.get_rand_circ_id()
        ckt = Circuit(cktid, self.node, self.skt)
        self.circuits_list.add(cktid, ckt)
        return -1

