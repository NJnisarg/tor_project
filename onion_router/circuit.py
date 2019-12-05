from typing import List
from connection.node import Node
from connection.skt import Skt
from cell.cell import Cell, CellConstants


class Circuit:

	def get_rand_circ_id(self) -> int:
		return 1

	def __init__(self, node_container: List[Node], skt: Skt):
		self.node_container = node_container
		self.skt = skt
		self.session_key = None

	# def open_connection(self, hop_i: int) -> int:
	# 	err_code = self.skt.remote_connect(self.node_container[hop_i].host, self.node_container[hop_i].port)
	# 	if err_code == 0:
	# 		return 0
	# 	else:
	# 		return -1

	# def create_circuit_hop1(self):
	# 	# First create a CREATE2 Cell.
	# 	create_data = {
	# 		'HTYPE': CellConstants.CREATE_HANDSHAKE_TYPE['TAP'],
	# 		'HLEN': CellConstants.TAP_C_HANDSHAKE_LEN,
	# 		'HDATA': ""

	# 	}
	# 	created_cell = Cell(self.get_rand_circ_id(), CellConstants.CMD_ENUM['CREATE2'], CellConstants.PAYLOAD_LEN, create_data)

	# 	# Send the cell to the first hop and wait for reply

	# 	# Process the reply of the CREATED2 cell and return the response code
