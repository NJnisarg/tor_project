import sys

sys.path.append('/home/praveenreddy/tor_project')

from node_directory_service.node_directory_service import NodeDirectoryService
from onion_proxy.circuit import Circuit
from connection.skt import Skt

"""
    This file contains the main starting point of the onion proxy.
    This file will be run when the onion proxy is booted up
"""

current_circ_id = 0


# This function is the actual entry point that will be called
def main():
	print("Onion proxy started!")

	print("Creating a circuit")
	circ_id = Circuit.get_rand_circ_id(current_circ_id)
	node_container = NodeDirectoryService.get_rand_three_nodes()
	skt = Skt(node_container[0].host, node_container[0].port)

	circuit = Circuit(node_container, skt, circ_id)

	# Open a TCP connection to first node in the circuit
	err_code = circuit.open_connection(1)
	if err_code == 0:
		print("Opened TCP Connection to the node")
		# Now we call create a cell and send it
		err_code = circuit.create_circuit_hop1()
		if err_code == 0:
			print("Router 1: Established the session key. DH Handshake successful.")
			print("The session key for router 1:", circuit.session_key01)
			err_code = circuit.create_circuit_hop2()
			if err_code == 0:
				print("Router 2: Established the session key. DH Handshake successful")
				print("The session key for router 2:", circuit.session_key02)

				err_code = circuit.create_circuit_hop3()
				if err_code == 0:
					print("Router 3: Established the session key. DH Handshake successful")
					print("The session key for router 3:", circuit.session_key03)
					# Lets try youtube for begin cell
					err_code = circuit.begin_end_destination_stream('45.55.99.72', 80)
					if err_code == 0:
						print("TCP stream to end destination established")
					else:
						print("Can't establish connected to end TCP host")
				else:
					print("Router 3: could not establish the session key. Closed the TCP Connection with the node 3")
			else:
				print("Router 2: could not establish the session key. Closed the TCP Connection with the node 2")
		else:
			print("Router 1: could not establish the session key. Closed the TCP Connection with the node 1")
	else:
		print("Error in establishing TCP connection to the node:")
		exit(0)


# Now setup the circuit incrementally with all the nodes
main()
