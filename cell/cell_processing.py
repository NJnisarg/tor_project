from typing import Dict
from cell.cell import Cell
from cell.control_cell import CreateCellPayload, TapCHData, TapSHData, CreatedCellPayload
from crypto.core_crypto import CoreCryptoRSA, CoreCryptoDH, CoreCryptoHash


class Builder:

	@staticmethod
	def build_create_cell(handshake_type: str, x ,gx, circ_id: int, onion_key) -> Cell:
		client_h_data = CoreCryptoRSA.hybrid_encrypt(gx, onion_key)
		create_cell_payload = CreateCellPayload(CreateCellPayload.CREATE_HANDSHAKE_TYPE[handshake_type], CreateCellPayload.CREATE_HANDSHAKE_LEN[handshake_type], client_h_data)
		create_cell = Cell(circ_id, Cell.CMD_ENUM['CREATE2'], Cell.PAYLOAD_LEN, create_cell_payload)
		return create_cell

	@staticmethod
	def build_created_cell(y, gy, circ_id: int, gx: str) -> Cell:
		# y, gy = CoreCryptoDH.generate_dh_priv_key()
		gxy = CoreCryptoDH.compute_dh_shared_key(y, gx)
		server_h_data = TapSHData(gy, CoreCryptoHash.compute_hash_derivative_key(gxy))
		created_cell_payload = CreatedCellPayload(CreatedCellPayload.TAP_S_HANDSHAKE_LEN, server_h_data)
		created_cell = Cell(circ_id, Cell.CMD_ENUM['CREATED2'], Cell.PAYLOAD_LEN, created_cell_payload)
		return created_cell


class Parser:

	@staticmethod
	def parse_create_cell(dict_cell: Dict) -> Cell:

		if 'CMD' not in dict_cell:
			return None

		if dict_cell['CMD'] != Cell.CMD_ENUM['CREATE2']:
			return None

		client_h_data = dict_cell['PAYLOAD']['HDATA']
		client_h_data = TapCHData(client_h_data['PADDING'], client_h_data['SYMKEY'], client_h_data['GX1'], client_h_data['GX2'])

		create_cell_payload = CreateCellPayload(dict_cell['PAYLOAD']['HTYPE'], dict_cell['PAYLOAD']['HLEN'], client_h_data)

		create_cell = Cell(dict_cell['CIRCID'], Cell.CMD_ENUM['CREATE2'], dict_cell['LENGTH'], create_cell_payload)

		return create_cell

	@staticmethod
	def parse_created_cell(dict_cell: Dict) -> Cell:

		if 'CMD' not in dict_cell:
			return None

		if dict_cell['CMD'] != Cell.CMD_ENUM['CREATED2']:
			return None

		server_h_data = dict_cell['PAYLOAD']['HDATA']
		server_h_data = TapSHData(server_h_data['GY'], server_h_data['KH'])

		created_cell_payload = CreatedCellPayload(dict_cell['PAYLOAD']['HLEN'], server_h_data)

		created_cell = Cell(dict_cell['CIRCID'], Cell.CMD_ENUM['CREATED2'], dict_cell['LENGTH'], created_cell_payload)

		return created_cell


class Processor:

	@staticmethod
	def process_create_cell(cell: Cell):

		return None

	@staticmethod
	def process_created_cell(cell: Cell, required_circ_id: int, x: str):
		if cell.CIRCID == required_circ_id:
			created_h_data = cell.PAYLOAD.HDATA
			gy = created_h_data.GY
			gxy = CoreCryptoDH.compute_dh_shared_key(gy, x)
			if created_h_data.KH == CoreCryptoRSA.kdf_tor(gxy):
				print("Handshake successful!")
				return gxy
			else:
				return None
		else:
			return None

