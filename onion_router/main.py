import sys
import json
from node_directory_service.node_directory_service import NodeDirectoryService
from connection.node import Node
from connection.skt import Skt
from circuit import Circuit
from onion_router import OnionRouter

"""
    This file contains the main starting point of the onion router.
    This file will be run when the onion router is booted up
"""


# This function is the actual entry point that will be called
def main():
	print("Node started!")
	print("Creating an onion router")
	node = NodeDirectoryService.get_nodes_from_csv()[sys.argv[1]] 
    onion_router = OnionRouter(node)

    onion_router.listen()
    onion_router.accept()

    onion_router.circuits_list[0].create_circuit()

    print("Circuit ready")
