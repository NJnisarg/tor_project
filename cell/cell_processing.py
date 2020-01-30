from typing import Dict
from cell.cell import Cell
from cell.control_cell import CreateCellPayload, TapCHData, TapSHData, CreatedCellPayload
from cell.relay_cell import RelayCellPayload, RelayExtendedPayload, RelayBeginPayload
from crypto.core_crypto import CoreCryptoRSA, CoreCryptoDH, CoreCryptoMisc
from connection.skt import Skt


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
	def build_extended_cell(y, gy, streamID: int, circ_id: int, gx: str, recognized) -> Cell:
		gxy = CoreCryptoDH.compute_dh_shared_key(y, gx)
		kdf_dict = CoreCryptoRSA.kdf_tor(gxy)
		server_h_data = TapSHData(gy, kdf_dict['KH'])

		# Construct extended2 payload
		extended_cell_payload_relay = RelayExtendedPayload(RelayExtendedPayload.TAP_S_HANDSHAKE_LEN, server_h_data)
		
		# Calculate digest from the extended2 payload
		payload_dict = {
			'HLEN' = extended_cell_payload_relay.HLEN,
			'HDATA' = extended_cell_payload_relay.HDATA
		}
		digest = CoreCryptoMisc.calculate_digest(payload_dict)

		# Construct the Relay cell with extended2 payload which is the payload for the Cell class
		extended_cell_payload = RelayCellPayload(RelayCellPayload.RELAY_CMD_ENUM['EXTENDED2'], recognized, streamID, digest, Cell.PAYLOAD_LEN-11, extended_cell_payload_relay)

		# Construct the actual cell
		extended_cell = Cell(circ_id, Cell.CMD_ENUM['RELAY'], Cell.PAYLOAD_LEN, extended_cell_payload)
		return extended_cell


	@staticmethod
	def build_begin_cell(addrport: str, flag_dict, circ_id: int, recognized, streamID) -> Cell:
		flags = ''
		i = 0
		while i < 29:
			flags = flags + '0'
		
		if flag_dict['IPV6_PREF'] == 1:
			flags = flags + '1'
		else:
			flags = flags + '0'
		
		if flag_dict['IPV4_NOT_OK'] == 1:
			flags = flags + '1'
		else:
			flags = flags + '0'
		
		if flag_dict['IPV6_OK'] == 1:
			flags = flags + '1'
		else:
			flags = flags + '0'
		
		begin_cell_payload_relay = RelayBeginPayload(addrport, flags)

		payload_dict = {
			'ADDRPORT': addrport,
			'FLAGS': flags
		}
		digest = CoreCryptoMisc.calculate_digest(payload_dict)

		begin_cell_payload = RelayCellPayload(RelayCellPayload.RELAY_CMD_ENUM['RELAY_BEGIN'], recognized, streamID, digest, Cell.PAYLOAD_LEN-11, begin_cell_payload_relay)
		begin_cell = Cell(circ_id, Cell.CMD_ENUM['RELAY'], Cell.PAYLOAD_LEN, begin_cell_payload)
		return build_cell


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
		if dict_cell['CMD'] != Cell.CMD_ENUM['RELAY']:
			return None
		if dict_cell['PAYLOAD']['RELAY_CMD'] != RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTENDED2']:
			return None

		server_h_data = dict_cell['PAYLOAD']['Data']['HDATA']
		server_h_data = TapSHData(server_h_data['GY'], server_h_data['KH'])

		extended_cell_payload_relay = RelayExtendedPayload(dict_cell['PAYLOAD']['Data']['HLEN'], server_h_data)

		extended_cell_payload = RelayCellPayload(dict_cell['PAYLOAD']['RELAY_CMD'], dict_cell['PAYLOAD']['RECOGNIZED'], dict_cell['PAYLOAD']['StreamID'],dict_cell['PAYLOAD']['Digest'], dict_cell['PAYLOAD']['Length'], extended_cell_payload_relay)

		extended_cell = Cell(dict_cell['CIRCID'], dict_cell['CMD'], dict_cell['LENGTH'], extended_cell_payload)

		return extended_cell

	@staticmethod
	def parse_begin_cell(dict_cell: Dict) -> Cell:

		if 'CMD' not in dict_cell:
			return None
		if dict_cell['CMD'] != Cell.CMD_ENUM['RELAY']:
			return None
		if dict_cell['PAYLOAD']['RELAY_CMD'] != RelayCellPayload.RELAY_CMD_ENUM['RELAY_BEGIN']:
			return None

		begin_cell_payload_relay = RelayBeginPayload(dict_cell['PAYLOAD']['Data']['ADDRPORT'], dict_cell['PAYLOAD']['Data']['FLAGS'])
		begin_cell_payload = RelayCellPayload(dict_cell['PAYLOAD']['RELAY_CMD'], dict_cell['PAYLOAD']['RECOGNIZED'], dict_cell['PAYLOAD']['StreamID'],dict_cell['PAYLOAD']['Digest'], dict_cell['PAYLOAD']['Length'], begin_cell_payload_relay)
		begin_cell = Cell(dict_cell['CIRCID'], dict_cell['CMD'], dict_cell['LENGTH'], begin_cell_payload)

		return begin_cell


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
			extended_h_data = cell.PAYLOAD.Data.HDATA
			gy = extended_h_data.GY
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


"""
The processing function for begin cell is simple since it just creates
a socket between client(exit node) and server to connect to. It returns one of
two values:
-1: This implies an error and the exit node has to send a RELAY_END cell to the
previous onion router.
socket: This implies success and the exit node has to send a RELAY_CONNECTED cell to the
previous onion router, which is when the data transmission takes place.
"""

	@staticmethod
	def process_begin_cell(cell: Cell, required_circ_id: int, streamID: int, local_host: str, local_port: int, remote_host: str, remote_port: int):
		
		# Bind Socket to local host
		socket = Skt(local_host, local_port)

		# Connect socket to remote host
		if socket.client_connect(remote_host, remote_port) == 0:
			return socket
		else:
			return -1
