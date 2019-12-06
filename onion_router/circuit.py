from typing import List
from connection.node import Node
from connection.skt import Skt
from cell.cell import Cell, CellConstants, CreateCellPayload
from cell.control_cell import TapCHData, TapSHData
import json
from node_directory_service.node_directory_service import NodeDirectoryService
from crypto.core_crypto import CoreCryptoRSA, CoreCryptoDH, CoreCryptoHash

class Circuit:

	def __init__(self, circ_id: int, node: Node, skt: Skt, sk=None):
		self.circ_id = circ_id
		self.node = node
		self.skt = skt
		self.session_key = sk
		self.routing_table = {}

	def process_cell(self, cell: Cell):
		if cell['CMD'] == CellConstants.CMD_ENUM['CREATE2']:
			self.process_create_cell(cell)

	def process_create_cell(self, cell: Cell):
		create_cell_circid = cell['CIRCID']
		create_cell_cmd = cell['CMD']
		create_cell_payload_length = cell['LENGTH']
		create_cell_payload = cell['PAYLOAD']

		gx = CoreCryptoRSA.hybrid_decrypt(create_cell_payload['HDATA'], self.node.onion_key_pri)

		self.send_created_cell(create_cell_circid, gx)

	def send_created_cell(self, create_cell_circid, gx):
		self.routing_table[create_cell_circid] =  None

		created_cell = Cell()
		gxy = created_cell.build_created_cell(3, self.circ_id, gx)

		self.session_key = gxy

		self.skt.server_send_data(created_cell.net_serialize())	

	def create_circuit(self):
		cell = Cell.net_deserialize(str(self.skt.server_recv_data()), [CreateCellPayload.deserialize, TapCHData.deserialize])
		
		self.process_cell(cell)

		print("OR in circuit ready")

		# Listen for extend relay cells and complete circuit creation here


