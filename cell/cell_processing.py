from typing import Dict

from cell.cell import Cell
from cell.control_cell import CreateCellPayload, TapCHData, TapSHData, CreatedCellPayload
from cell.relay_cell import RelayCellPayload, RelayExtendedPayload, RelayBeginPayload, RelayExtendPayload
from cell.serializers import EncoderDecoder
from connection.skt import Skt
from crypto.core_crypto import CoreCryptoRSA, CoreCryptoDH, CoreCryptoMisc


class Builder:
	"""
	The class that has methods to build various types of cells
	"""
	@staticmethod
	def build_create_cell(handshake_type: str, x_bytes: bytes, gx_bytes: bytes, circ_id: int, onion_key) -> Cell:
		"""
		The method used to build a Create/Create2 cell
		:param handshake_type: The handshake type. TAP or ntor.
		:param x_bytes: The diffie hellman private key as a bytes object
		:param gx_bytes: The diffie hellman public key as a bytes object
		:param circ_id: The circuit ID
		:param onion_key: The onion key of the next hop used in hybrid_encrypt method
		:return: The create Cell object
		"""
		client_h_data = CoreCryptoRSA.hybrid_encrypt(gx_bytes, onion_key)
		create_cell_payload = CreateCellPayload(CreateCellPayload.CREATE_HANDSHAKE_TYPE[handshake_type],
												CreateCellPayload.CREATE_HANDSHAKE_LEN[handshake_type],
												client_h_data)
		create_cell = Cell(circ_id, Cell.CMD_ENUM['CREATE2'], Cell.PAYLOAD_LEN, create_cell_payload)
		return create_cell

	@staticmethod
	def build_create_cell_from_extend(circ_id: int, htype, hlen, hdata) -> Cell:
		"""
		The method used to build a Create cell from an Extend cell
		:param circ_id: The circuit ID
		:param htype: The Handshake type. TAP or ntor
		:param hlen: The Length of Handshake object
		:param hdata: The Handshake data object of type TapCHData
		:return: The create Cell object
		"""
		create_cell_payload = CreateCellPayload(htype, hlen, hdata)
		create_cell = Cell(circ_id, Cell.CMD_ENUM['CREATE2'], Cell.PAYLOAD_LEN, create_cell_payload)
		return create_cell

	@staticmethod
	def build_extend_cell(handshake_type: str, x_bytes: bytes, gx_bytes: bytes, circ_id: int, onion_key, lspec: str) -> Cell:
		"""
		The method used to build a Extend/Extend2 cell
		:param handshake_type: The handshake type. TAP or ntor.
		:param x_bytes: The diffie hellman private key as a bytes object
		:param gx_bytes: The diffie hellman public key as a bytes object
		:param circ_id: The circuit ID
		:param onion_key: The onion key of the next hop used in hybrid_encrypt method
		:param lspec: The link specifier as a string
		:return: The extend Cell object
		"""
		client_h_data = CoreCryptoRSA.hybrid_encrypt(gx_bytes, onion_key)
		nspec = 1  # Always keep this 1 to avoid going to hell
		extend_cell_payload = RelayExtendPayload(nspec,
												RelayExtendPayload.LSTYPE_ENUM['TLS_TCP_IPV4'],
												RelayExtendPayload.LSTYPE_LSLEN_ENUM['TLS_TCP_IPV4'],
												lspec,
												CreateCellPayload.CREATE_HANDSHAKE_TYPE[handshake_type],
												CreateCellPayload.CREATE_HANDSHAKE_LEN[handshake_type],
												client_h_data)

		relay_cell_payload = RelayCellPayload(RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTEND2'], 1, 0, "", 509, extend_cell_payload)

		relay_extend_cell = Cell(circ_id, Cell.CMD_ENUM['RELAY'], Cell.PAYLOAD_LEN, relay_cell_payload)

		return relay_extend_cell

	@staticmethod
	def build_created_cell(y_bytes: bytes, gy_bytes: bytes, circ_id: int, gx_bytes: bytes) -> Cell:
		"""
		The method used to build a created/created2 cell object
		:param y_bytes: The diffie hellman private key bytes of the receiver
		:param gy_bytes: The diffie hellman public key bytes of the receiver
		:param circ_id: The circuit ID
		:param gx_bytes: The diffie hellman public key bytes of the sender
		:return: The created Cell object
		"""
		gxy = CoreCryptoDH.compute_dh_shared_key(gx_bytes, y_bytes)
		kdf_dict = CoreCryptoRSA.kdf_tor(gxy)

		server_h_data = TapSHData(EncoderDecoder.bytes_to_utf8str(gy_bytes), kdf_dict['KH'])
		created_cell_payload = CreatedCellPayload(CreatedCellPayload.TAP_S_HANDSHAKE_LEN, server_h_data)
		created_cell = Cell(circ_id, Cell.CMD_ENUM['CREATED2'], Cell.PAYLOAD_LEN, created_cell_payload)
		return created_cell

	@staticmethod
	def build_extended_cell(y, gy, streamID: int, circ_id: int, gx: str, recognized) -> Cell:
		"""
		The method to build the extended Cell object
		:param y:
		:param gy:
		:param streamID:
		:param circ_id:
		:param gx:
		:param recognized:
		:return: The Extended Cell
		"""
		gxy = CoreCryptoDH.compute_dh_shared_key(y, gx)
		kdf_dict = CoreCryptoRSA.kdf_tor(gxy)
		server_h_data = TapSHData(gy, kdf_dict['KH'])

		# Construct extended2 payload
		extended_cell_payload_relay = RelayExtendedPayload(RelayExtendedPayload.TAP_S_HANDSHAKE_LEN, server_h_data)

		# Calculate digest from the extended2 payload
		payload_dict = {
			'HLEN': extended_cell_payload_relay.HLEN,
			'HDATA': extended_cell_payload_relay.HDATA
		}
		digest = CoreCryptoMisc.calculate_digest(payload_dict)

		# Construct the Relay cell with extended2 payload which is the payload for the Cell class
		extended_cell_payload = RelayCellPayload(RelayCellPayload.RELAY_CMD_ENUM['EXTENDED2'], recognized, streamID,
		                                         digest, Cell.PAYLOAD_LEN - 11, extended_cell_payload_relay)
		# Construct the actual cell
		extended_cell = Cell(circ_id, Cell.CMD_ENUM['RELAY'], Cell.PAYLOAD_LEN, extended_cell_payload)
		return extended_cell

	@staticmethod
	def build_extended_cell_from_created_cell(circ_id: int, hlen, hdata) -> Cell:
		"""
		The method to build the Extended Cell from a received Created Cell
		:param circ_id: The circuit ID
		:param hlen: The handshake len(from Created Cell)
		:param hdata: The handshake Data of type TapCHData(from Created Cell)
		:return: The Extended Cell
		"""
		relay_extended_cell_payload = RelayExtendedPayload(hlen, hdata)

		# Calculate digest from the extended2 payload
		# payload_dict = {
		#     'HLEN': relay_extended_cell_payload.HLEN,
		#     'HDATA': relay_extended_cell_payload.HDATA
		# }
		# digest = CoreCryptoMisc.calculate_digest(payload_dict)
		# Using a digest here will ruin the code structure where the payload of a cell is another object
		# Function to get payload from digest?

		# Construct the Relay cell with extended2 payload which is the payload for the Cell class
		extended_cell_payload = RelayCellPayload(RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTENDED2'], False, 0, "", Cell.PAYLOAD_LEN - 11, relay_extended_cell_payload)

		# Construct the actual cell
		extended_cell = Cell(circ_id, Cell.CMD_ENUM['RELAY'], Cell.PAYLOAD_LEN, extended_cell_payload)
		return extended_cell

	@staticmethod
	def build_begin_cell(addrport: str, flag_dict, circ_id: int, recognized, streamID) -> Cell:
		"""
		The method to build a Begin Cell
		:param addrport:
		:param flag_dict:
		:param circ_id:
		:param recognized:
		:param streamID:
		:return: The Begin Cell object
		"""
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

		begin_cell_payload = RelayCellPayload(RelayCellPayload.RELAY_CMD_ENUM['RELAY_BEGIN'], recognized, streamID, digest, Cell.PAYLOAD_LEN - 11, begin_cell_payload_relay)
		begin_cell = Cell(circ_id, Cell.CMD_ENUM['RELAY'], Cell.PAYLOAD_LEN, begin_cell_payload)
		return begin_cell


class Parser:
	"""
	The class with methods that parse a Python dictionary into a Cell object
	"""

	@staticmethod
	def parse_create_cell(dict_cell: Dict) -> Cell:
		"""
		The method to parse a Create Cell
		:param dict_cell: The python Dict version of a cell
		:return: Return a well formed Create Cell object
		"""

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
	def parse_extend_cell(dict_cell: Dict) -> Cell:
		"""
		The method to parse an Extend Cell
		:param dict_cell: The python Dict version of a cell
		:return: Return a well formed Extend Cell object
		"""
		if 'CMD' not in dict_cell:
			return None

		if dict_cell['CMD'] != Cell.CMD_ENUM['RELAY']:
			return None

		client_h_data = dict_cell['PAYLOAD']['Data']['HDATA']
		client_h_data = TapCHData(client_h_data['PADDING'], client_h_data['SYMKEY'], client_h_data['GX1'], client_h_data['GX2'])

		extend_cell_payload = RelayExtendPayload(dict_cell['PAYLOAD']['Data']['NSPEC'],
												dict_cell['PAYLOAD']['Data']['LSTYPE'],
												dict_cell['PAYLOAD']['Data']['LSLEN'],
												dict_cell['PAYLOAD']['Data']['LSPEC'],
												dict_cell['PAYLOAD']['Data']['HTYPE'],
												dict_cell['PAYLOAD']['Data']['HLEN'],
												client_h_data)

		relay_cell_payload = RelayCellPayload(dict_cell['PAYLOAD']['RELAY_CMD'],
											dict_cell['PAYLOAD']['RECOGNIZED'],
											dict_cell['PAYLOAD']['StreamID'],
											dict_cell['PAYLOAD']['Digest'],
											dict_cell['PAYLOAD']['Length'],
											extend_cell_payload)

		relay_extend_cell = Cell(dict_cell['CIRCID'], dict_cell['CMD'], dict_cell['LENGTH'], relay_cell_payload)

		return relay_extend_cell

	@staticmethod
	def parse_created_cell(dict_cell: Dict) -> Cell:
		"""
		The method to parse a created cell object
		:param dict_cell: The python Dict version of a cell
		:return: Return a well formed Created Cell object
		"""
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
		"""
		The method to parse a extended cell object
		:param dict_cell: The python Dict version of a cell
		:return: Return a well formed Extended Cell object
		"""
		if 'CMD' not in dict_cell:
			return None
		if dict_cell['CMD'] != Cell.CMD_ENUM['RELAY']:
			return None
		if dict_cell['PAYLOAD']['RELAY_CMD'] != RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTENDED2']:
			return None

		server_h_data = dict_cell['PAYLOAD']['Data']['HDATA']
		server_h_data = TapSHData(server_h_data['GY'], server_h_data['KH'])

		extended_cell_payload_relay = RelayExtendedPayload(dict_cell['PAYLOAD']['Data']['HLEN'], server_h_data)

		extended_cell_payload = RelayCellPayload(dict_cell['PAYLOAD']['RELAY_CMD'], dict_cell['PAYLOAD']['RECOGNIZED'],
												dict_cell['PAYLOAD']['StreamID'], dict_cell['PAYLOAD']['Digest'],
												dict_cell['PAYLOAD']['Length'], extended_cell_payload_relay)

		extended_cell = Cell(dict_cell['CIRCID'], dict_cell['CMD'], dict_cell['LENGTH'], extended_cell_payload)

		return extended_cell

	@staticmethod
	def parse_begin_cell(dict_cell: Dict) -> Cell:
		"""
		The method to parse a Begin cell object
		:param dict_cell: The python Dict version of a cell
		:return: Return a well formed Begin Cell object
		"""
		if 'CMD' not in dict_cell:
			return None
		if dict_cell['CMD'] != Cell.CMD_ENUM['RELAY']:
			return None
		if dict_cell['PAYLOAD']['RELAY_CMD'] != RelayCellPayload.RELAY_CMD_ENUM['RELAY_BEGIN']:
			return None

		begin_cell_payload_relay = RelayBeginPayload(dict_cell['PAYLOAD']['Data']['ADDRPORT'],
													dict_cell['PAYLOAD']['Data']['FLAGS'])
		begin_cell_payload = RelayCellPayload(dict_cell['PAYLOAD']['RELAY_CMD'], dict_cell['PAYLOAD']['RECOGNIZED'],
											dict_cell['PAYLOAD']['StreamID'], dict_cell['PAYLOAD']['Digest'],
											dict_cell['PAYLOAD']['Length'], begin_cell_payload_relay)
		begin_cell = Cell(dict_cell['CIRCID'], dict_cell['CMD'], dict_cell['LENGTH'], begin_cell_payload)

		return begin_cell


class Processor:
	"""
	The class with methods used to Process a cell and return any required useful data
	"""
	@staticmethod
	def process_create_cell(cell: Cell, private_onion_key, y_bytes: bytes) -> (bytes, Dict):
		"""
		Process the create cell and return the g^x (public key of sender)
		:param y_bytes: The private DH key generated by the router node in bytes
		:param cell: The Create Cell Object
		:param private_onion_key: The private key of the receiver which will be used in hybrid decrypt
		:return: g^x as bytes object
		"""
		create_cell_payload = cell.PAYLOAD
		gx_bytes = CoreCryptoRSA.hybrid_decrypt(create_cell_payload.HDATA, private_onion_key)
		gxy = CoreCryptoDH.compute_dh_shared_key(gx_bytes, y_bytes)
		kdf_dict = CoreCryptoRSA.kdf_tor(gxy)
		return gx_bytes, kdf_dict

	@staticmethod
	def process_extend_cell(cell: Cell, private_onion_key):
		"""
		The method to process an extend cell and return the parts needed to build a Create cell
		:param cell: The Extend Cell Object
		:param private_onion_key:
		:return: A 5-tuple of <addr,port,htype,hlen,hdata>
		"""
		extend_cell_payload = cell.PAYLOAD.Data
		LSPEC = extend_cell_payload.LSPEC
		addr = LSPEC.split(":")[0]
		port = int(LSPEC.split(":")[1])

		htype = extend_cell_payload.HTYPE
		hlen = extend_cell_payload.HLEN
		hdata = extend_cell_payload.HDATA

		return addr, port, htype, hlen, hdata

	@staticmethod
	def process_created_cell(cell: Cell, required_circ_id: int, x_bytes: bytes):
		"""
		The method to process a created cell and return the kdf_dict that will be used after DH handshake
		:param cell: The Created Cell Object
		:param required_circ_id: The circuit ID that is expected
		:param x_bytes: The private key of the sender in bytes
		:return: The KDF Dict
		"""
		if cell.CIRCID == required_circ_id:
			created_h_data = cell.PAYLOAD.HDATA
			gy_str = created_h_data.GY
			gy_bytes = EncoderDecoder.utf8str_to_bytes(gy_str)
			gxy = CoreCryptoDH.compute_dh_shared_key(gy_bytes, x_bytes)
			kdf_dict = CoreCryptoRSA.kdf_tor(gxy)
			if created_h_data.KH == kdf_dict['KH']:
				print("Handshake successful!")
				return kdf_dict
			else:
				return None
		else:
			return None

	@staticmethod
	def process_created_cell_for_extended(cell: Cell):
		"""
		The method to process created cell for building extended cell
		:param cell: The Created Cell object
		:return: A 2-tuple of <hlen,hdata>
		"""
		payload = cell.PAYLOAD
		hlen = payload.HLEN
		hdata = payload.HDATA
		return hlen, hdata

	@staticmethod
	def process_extended_cell(cell: Cell, required_circ_id: int, x_bytes: bytes):
		"""
		The processing functions for created and extended cells return
		dictionaries created by kdf_tor() function.

		For verifying KH, the kdf_dict has to be accessed. This is added
		to the 'extended' cell handling and similar changes have been made
		in the parsing and processing of 'created' cells
		"""
		if cell.CIRCID == required_circ_id:
			extended_h_data = cell.PAYLOAD.Data.HDATA
			gy_str = extended_h_data.GY
			gy_bytes = EncoderDecoder.utf8str_to_bytes(gy_str)
			gxy = CoreCryptoDH.compute_dh_shared_key(gy_bytes, x_bytes)
			kdf_dict = CoreCryptoRSA.kdf_tor(gxy)
			if extended_h_data.KH == kdf_dict['KH']:
				print("Handshake successful!")
				return kdf_dict
			else:
				return None
		else:
			return None

	@staticmethod
	def process_begin_cell(cell: Cell, required_circ_id: int, streamID: int, local_host: str, local_port: int, remote_host: str, remote_port: int):
		"""
		The processing function for begin cell is simple since it just creates
		a socket between client(exit node) and server to connect to. It returns one of
		two values:
		-1: This implies an error and the exit node has to send a RELAY_END cell to the
		previous onion router.
		socket: This implies success and the exit node has to send a RELAY_CONNECTED cell to the
		previous onion router, which is when the data transmission takes place.
		"""

		# Bind Socket to local host
		socket = Skt(local_host, local_port)

		# Connect socket to remote host
		if socket.client_connect(remote_host, remote_port) == 0:
			return socket
		else:
			return -1
