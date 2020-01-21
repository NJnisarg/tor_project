from typing import Dict
from cell.cell import Cell
from cell.control_cell import CreateCellPayload, TapCHData, TapSHData, CreatedCellPayload
from cell.relay_cell import RelayCellPayload, RelayExtendedPayload
from crypto.core_crypto import CoreCryptoRSA, CoreCryptoDH


class Builder:

	@staticmethod
	def build_create_cell(handshake_type: str, x ,gx, circ_id: int, onion_key) -> Cell:
		# client_h_data = CoreCryptoRSA.hybrid_encrypt(gx, onion_key)
		client_h_data = TapCHData("","","m1","m2")
		create_cell_payload = CreateCellPayload(CreateCellPayload.CREATE_HANDSHAKE_TYPE[handshake_type], CreateCellPayload.CREATE_HANDSHAKE_LEN[handshake_type], client_h_data)
		create_cell = Cell(circ_id, Cell.CMD_ENUM['CREATE2'], Cell.PAYLOAD_LEN, create_cell_payload)
		return create_cell

	@staticmethod
	def extend2_build_create_cell(handshake_type: str, x, gx, circ_id: int, onion_key) -> Cell:
		# client_h_data = CoreCryptoRSA.hybrid_encrypt(gx, onion_key)
		client_h_data = TapCHData("", "", "m1", "m2")
		create_cell_payload = CreateCellPayload(CreateCellPayload.CREATE_HANDSHAKE_TYPE[handshake_type],CreateCellPayload.CREATE_HANDSHAKE_LEN[handshake_type], client_h_data)
		create_cell = Cell(circ_id, Cell.CMD_ENUM['RELAY'], Cell.PAYLOAD_LEN, create_cell_payload)
		return create_cell

	@staticmethod
	def build_created_cell(y, gy, circ_id: int, gx: str) -> Cell:
		# y, gy = CoreCryptoDH.generate_dh_priv_key()
		gxy = CoreCryptoDH.compute_dh_shared_key(y, gx)
		kdf_dict = CoreCryptoRSA.kdf_tor(gxy)
		server_h_data = TapSHData(gy, kdf_dict['KH'])
		created_cell_payload = CreatedCellPayload(CreatedCellPayload.TAP_S_HANDSHAKE_LEN, server_h_data)
		created_cell = Cell(circ_id, Cell.CMD_ENUM['CREATED2'], Cell.PAYLOAD_LEN, created_cell_payload)
		return created_cell

	@staticmethod
	def build_extended_cell(y, gy, circ_id: int, gx: str) -> Cell:
		gxy = CoreCryptoDH.compute_dh_shared_key(y, gx)
		kdf_dict = CoreCryptoRSA.kdf_tor(gxy)
		server_h_data = TapSHData(gy, kdf_dict['KH'])
		extended_cell_payload = RelayExtendedPayload(RelayExtendedPayload.TAP_S_HANDSHAKE_LEN, server_h_data)
		extended_cell = Cell(circ_id, RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTENDED2'], Cell.PAYLOAD_LEN, extended_cell_payload)
		return extended_cell


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
	def extend2_parse_create_cell(dict_cell: Dict) -> Cell:

		if 'CMD' not in dict_cell:
			return None

		if dict_cell['CMD'] != Cell.CMD_ENUM['RELAY']:
			return None

		client_h_data = dict_cell['PAYLOAD']['HDATA']
		client_h_data = TapCHData(client_h_data['PADDING'], client_h_data['SYMKEY'], client_h_data['GX1'],
								  client_h_data['GX2'])

		create_cell_payload = CreateCellPayload(dict_cell['PAYLOAD']['HTYPE'], dict_cell['PAYLOAD']['HLEN'],client_h_data)
		create_cell = Cell(dict_cell['CIRCID'], Cell.CMD_ENUM['RELAY'], dict_cell['LENGTH'], create_cell_payload)
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

	@staticmethod
	def parse_extended_cell(dict_cell: Dict) -> Cell:

		if 'CMD' not in dict_cell:
			return None

		if dict_cell['CMD'] != Cell.RELAY_CMD_ENUM['RELAY_EXTENDED2']:
			return None

		server_h_data = dict_cell['PAYLOAD']['HDATA']
		server_h_data = TapSHData(server_h_data['GY'], server_h_data['KH'])

		extended_cell_payload = RelayExtendedPayload(dict_cell['PAYLOAD']['HLEN'], server_h_data)

		extended_cell = Cell(dict_cell['CIRCID'], RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTENDED2'], dict_cell['LENGTH'], extended_cell_payload)

		return extended_cell


class Processor:

	@staticmethod
	def process_create_cell(cell: Cell, private_onion_key):
		create_cell_circid = cell.CIRCID
		create_cell_cmd = cell.CMD
		create_cell_payload_length = cell.LENGTH
		create_cell_payload = cell.PAYLOAD
		gx = CoreCryptoRSA.hybrid_decrypt(create_cell_payload.HDATA, private_onion_key)
		return gx

	@staticmethod
	def extend2_process_create_cell(cell: Cell, private_onion_key):
		create_cell_circid = cell.CIRCID
		create_cell_cmd = cell.CMD
		create_cell_payload_length = cell.LENGTH
		create_cell_payload = cell.PAYLOAD
		gx = CoreCryptoRSA.hybrid_decrypt(create_cell_payload.HDATA, private_onion_key)
		return gx

	@staticmethod
	def process_created_cell(cell: Cell, required_circ_id: int, x: str):
		if cell.CIRCID == required_circ_id:
			created_h_data = cell.PAYLOAD.HDATA
			gy = created_h_data.GY
			gxy = CoreCryptoDH.compute_dh_shared_key(gy, x)
			kdf_dict = CoreCryptoRSA.kdf_tor(gxy)
			if created_h_data.KH == kdf_dict['KH']:
				print("Handshake successful!")
				return kdf_dict
			else:
				return None
		else:
			return None

	@staticmethod
	def process_extended_cell(cell: Cell, required_circ_id: int, x: str):
		if cell.CIRCID == required_circ_id:
			extended_h_data = cell.PAYLOAD.HDATA
			gy = extended_data.GY
			gxy = CoreCryptoDH.compute_dh_shared_key(gy, x)
			kdf_dict = CoreCryptoRSA.kdf_tor(gxy)
			if extended_h_data.KH == kdf_dict['KH']:
				print("Handshake successful!")
				return kdf_dict
			else:
				return None
		else:
			return None

"""
The processing functions for created and extended cells return
dictionaries created by kdf_tor() function.

For verifying KH, the kdf_dict has to be accessed. This is added
to the 'extended' cell handling and similar changes have been made
in the parsing and processing of 'created' cells
"""