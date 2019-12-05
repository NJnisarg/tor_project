from node_directory_service.node_directory_service import NodeDirectoryService
from connection.skt import Skt
from circuit import Circuit

class OnionRouter:

    def __init__(self, node=None, is_exit_node=True):
        self.node = node
        self.skt = Skt(node.host, node.port)
        self.is_exit_node = is_exit_node
        self.routing_table = {}

    def process_cell(self, data):
        