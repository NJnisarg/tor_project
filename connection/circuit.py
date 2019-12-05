import json
from typing import List
from connection.node import Node
from connection.skt import Skt
from cell.cell import Cell, CellConstants
from crypto.core_crypto import CoreCryptoRSA


class Circuit:
	"""
	The class representing the Circuit object for the Onion Proxy.
	"""

	def get_rand_circ_id(self) -> int:
		"""
		Returns a random circId for the circuit. Follows the Tor Spec to create the circId
		:return: circId --> integer
		"""
		return 1

	def __init__(self, node_container: List[Node], skt: Skt):
		"""

		:param node_container: The list of Node objects including the Client itself
		:param skt: The Client's socket object. We will use this to connect to the nodes in the container
		"""
		self.node_container = node_container
		self.skt = skt
		self.session_key01 = None
		self.session_key02 = None
		self.session_key03 = None

	def open_connection(self, hop_i: int) -> int:
		"""

		:param hop_i: The index of the node in the node container that the client wants to connect to
		:return: Returns a status code. 0 --> Success and -1 means error
		"""
		err_code = self.skt.client_connect(self.node_container[hop_i].host, self.node_container[hop_i].port)
		if err_code == 0:
			return 0
		else:
			return -1

	def create_circuit_hop1(self) -> int:
		"""
		The function to setup circuit with the first hop in the circuit. Created the CREATE/CREATE2 cell and sends it
		down the socket. It assumes that the open_connection was called on the first node and the socket is connected
		to the first node
		:return: Returns a status code. 0 --> Success DH Handshake and -1 --> Means error in processing the cell or the DH Handshake.
		On error it closes the socket to node 1
		"""
		# First create a CREATE2 Cell.

		# Encrypting the g^x with the onion public key of the tor node 1
		h_data = CoreCryptoRSA.hybrid_encrypt("g^x", self.node_container[1].onion_key_pub)
		create_data = {
			'HTYPE': CellConstants.CREATE_HANDSHAKE_TYPE['TAP'],
			'HLEN': CellConstants.TAP_C_HANDSHAKE_LEN,
			'HDATA': h_data

		}
		create_cell = Cell(self.get_rand_circ_id(), CellConstants.CMD_ENUM['CREATE2'], CellConstants.PAYLOAD_LEN, create_data)
		self.skt.client_send_data(json.loads(create_cell.JSON_CELL))

		# Process the reply of the CREATED2 cell and return the response code
		created_cell = json.dumps(self.skt.client_recv_data())

		# The cell is correctly structured
		if created_cell['CIRCID'] == self.get_rand_circ_id() and created_cell['CMD'] == CellConstants.CMD_ENUM['CREATED2']:
			created_payload = created_cell['PAYLOAD']
			gy = created_payload['HDATA']['Y']
			gxy = gy  # use some function to compute the gxy here
			if created_payload['HDATA']['KEY_DER'] == CoreCryptoRSA.kdf_tor(gxy):
				print("Handshake successful!")
				self.session_key01 = gxy
				return 0
			else:
				self.skt.close()
				return -1
		else:
			self.skt.close()
			return -1
