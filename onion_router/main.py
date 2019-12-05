import sys
from node_directory_service.node_directory_service import NodeDirectoryService
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
    or = OnionRouter(node)

    listen = or.skt.server_listen()
    if listen != 0:
        print("Error listening")
        exit(0)

    accept = or.skt.server_accept()
    if accept != 0:
        print("Error accepting connection")
        exit(0)
    
    data = or.skt.server_recv_data().decode()
    or.process_cell(data)
