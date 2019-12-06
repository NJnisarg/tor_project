from node_directory_service.node_directory_service import NodeDirectoryService
from onion_proxy.circuit import Circuit
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
	circ_id = Circuit.get_rand_circ_id()
	node_container = NodeDirectoryService.get_rand_three_nodes()
	circuit = Circuit(node_container, skt, circ_id)

	# Open a TCP connection to first node in the circuit
	err_code = circuit.open_connection(1)
	if err_code == 0:
		print("Opened TCP Connection to the node")
		# Now we call create a cell and send it
		err_code = circuit.create_circuit_hop1()
		if err_code == 0:
			print("Established the session key. DH Handshake successful")
		else:
			print("could not establish the session key. Closed the TCP Connection with the node 1")
	else:
		print("Error in establishing TCP connection to the node:")
		exit(0)

# Now setup the circuit incrementally with all the nodes
