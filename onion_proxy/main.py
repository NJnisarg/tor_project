from node_directory_service.node_directory_service import NodeDirectoryService
from connection.circuit import Circuit
from connection.skt import Skt

"""
    This file contains the main starting point of the onion proxy.
    This file will be run when the onion proxy is booted up
"""


# This function is the actual entry point that will be called
def main():
	print("Onion proxy started!")
	skt = Skt('127.0.0.1', 4444)

	print("Creating a circuit")
	node_container = NodeDirectoryService.get_rand_three_nodes()
	circuit = Circuit(node_container, skt)

	# Open a TCP connection to all the nodes in the circuit
	for idx, hop in enumerate(circuit.node_container):
		err_code = circuit.open_connection(idx)
		if err_code == 0:
			continue
		else:
			print("Error in connecting to the node:", idx)
			exit(0)

	# Now setup the circuit incrementally with all the nodes
