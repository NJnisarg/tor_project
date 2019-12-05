import sys
from node_directory_service.node_directory_service import NodeDirectoryService
from connection.circuit import Circuit
from connection.skt import Skt

"""
    This file contains the main starting point of the onion router.
    This file will be run when the onion router is booted up
"""


# This function is the actual entry point that will be called
def main():
	print("Node started!")
	print("Creating an onion router")
	node = NodeDirectoryService.get_nodes_from_csv()[sys.argv[1]]
	skt = Skt(node.host, node.port)
