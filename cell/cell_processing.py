from ipaddress import IPv4Address
from struct import pack, unpack
from typing import Dict, Tuple

from cell.cell import Cell
from cell.control_cell import CreateCellPayload, TapCHData, TapSHData, CreatedCellPayload
from cell.relay_cell import RelayCellPayload, RelayExtendedPayload, RelayBeginPayload, RelayExtendPayload
from connection.skt import Skt
from crypto.core_crypto import CoreCryptoRSA, CoreCryptoDH, CoreCryptoMisc, CryptoConstants as CC


class Builder:
	"""
	The class that has methods to build various types of cells
	"""
	@staticmethod
	def build_create_cell(handshake_type: str, x_bytes: bytes, gx_bytes: bytes, circ_id: int, onion_key) -> Cell:
		"""
		The method used to build a Create/Create2 cell
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
	def build_extend_cell(handshake_type: str, x_bytes: bytes, gx_bytes: bytes, circ_id: int, onion_key, hop2_ip, hop2_port) -> Cell:
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
		lspec = bytearray(IPv4Address(hop2_ip).packed) + pack('!H', int(hop2_port))
		extend_cell_payload = RelayExtendPayload(nspec,
												RelayExtendPayload.LSTYPE_ENUM['TLS_TCP_IPV4'],
												RelayExtendPayload.LSTYPE_LSLEN_ENUM['TLS_TCP_IPV4'],
												lspec,
												CreateCellPayload.CREATE_HANDSHAKE_TYPE[handshake_type],
												CreateCellPayload.CREATE_HANDSHAKE_LEN[handshake_type],
												client_h_data)

		relay_cell_payload = RelayCellPayload(RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTEND2'], 0, 0, b'', Cell.PAYLOAD_LEN - 11, extend_cell_payload)

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

		server_h_data = TapSHData(gy_bytes, kdf_dict['KH'])
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

		extended_cell_payload = RelayCellPayload(RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTENDED2'], 0, 0, b'', Cell.PAYLOAD_LEN - 11, relay_extended_cell_payload)

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
	def parse_basic_cell(cell_bytes: bytes) -> Tuple:
		length = len(cell_bytes)-4-1-2
		fmt_str = '=IBH' + str(length) + 's'
		return unpack(fmt_str, cell_bytes)

	@staticmethod
	def parse_encoded_relay_cell(cell_bytes: bytes) -> Tuple:
		cell_tuple = Parser.parse_basic_cell(cell_bytes)

		fmt_str = '=BHH4sH'+str(Cell.PAYLOAD_LEN - 11)+'s'
		relay_cell_payload_tuple = unpack(fmt_str, cell_tuple[3])

		return relay_cell_payload_tuple

	@staticmethod
	def parse_encoded_create_cell(cell_bytes: bytes) -> Cell:
		cell_tuple = Parser.parse_basic_cell(cell_bytes)

		hlen = CreateCellPayload.CREATE_HANDSHAKE_LEN['TAP']
		payload_fmt_str = '=HH'+str(hlen)+'s'
		create_cell_payload_tuple = unpack(payload_fmt_str, cell_tuple[3][0:(2+2+hlen)])

		h_data_fmt_str = '='+str(CC.PK_PAD_LEN)+'s'+str(CC.KEY_LEN)+'s'+str(CC.PK_ENC_LEN - CC.PK_PAD_LEN - CC.KEY_LEN)+'s'+str(CC.DH_LEN-(CC.PK_ENC_LEN-CC.PK_PAD_LEN-CC.KEY_LEN))+'s'
		h_data_tuple = unpack(h_data_fmt_str, create_cell_payload_tuple[2])

		h_data = TapCHData(h_data_tuple[0], h_data_tuple[1], h_data_tuple[2], h_data_tuple[3])
		create_cell_payload = CreateCellPayload(create_cell_payload_tuple[0], create_cell_payload_tuple[1], h_data)
		create_cell = Cell(cell_tuple[0], cell_tuple[1], cell_tuple[2], create_cell_payload)

		return create_cell

	@staticmethod
	def parse_encoded_created_cell(cell_bytes: bytes) -> Cell:

		cell_tuple = Parser.parse_basic_cell(cell_bytes)

		hlen = CreatedCellPayload.TAP_S_HANDSHAKE_LEN
		payload_fmt_str = '=H'+str(hlen)+'s'
		created_cell_payload_tuple = unpack(payload_fmt_str, cell_tuple[3][0:(2+hlen)])

		h_data_fmt_str = '='+str(CC.DH_LEN)+'s'+str(CC.HASH_LEN)+'s'
		h_data_tuple = unpack(h_data_fmt_str, created_cell_payload_tuple[1])

		server_h_data = TapSHData(h_data_tuple[0], h_data_tuple[1])

		created_cell_payload = CreatedCellPayload(created_cell_payload_tuple[0], server_h_data)

		created_cell = Cell(cell_tuple[0], cell_tuple[1], cell_tuple[2], created_cell_payload)

		return created_cell

	@staticmethod
	def parse_encoded_extend_cell(cell_bytes: bytes) -> Cell:
		cell_tuple = Parser.parse_basic_cell(cell_bytes)
		relay_cell_payload_tuple = Parser.parse_encoded_relay_cell(cell_bytes)

		part_fmt_str1 = '=BBB'
		part_tuple1 = unpack(part_fmt_str1, relay_cell_payload_tuple[5][0:3])

		part_fmt_str2 = '=BBB' + str(part_tuple1[2])+'s'+'HH'
		part_tuple2 = unpack(part_fmt_str2, relay_cell_payload_tuple[5][0:(3+part_tuple1[2]+2+2)])

		fmt_str = '=BBB' + str(part_tuple1[2])+'s'+'HH' + str(part_tuple2[5])+'s'
		relay_extend_payload_tuple = unpack(fmt_str, relay_cell_payload_tuple[5][0:(3+part_tuple1[2]+2+2+part_tuple2[5])])

		h_data_fmt_str = '=' + str(CC.PK_PAD_LEN) + 's' + str(CC.KEY_LEN) + 's' + str(
			CC.PK_ENC_LEN - CC.PK_PAD_LEN - CC.KEY_LEN) + 's' + str(
			CC.DH_LEN - (CC.PK_ENC_LEN - CC.PK_PAD_LEN - CC.KEY_LEN)) + 's'
		h_data_tuple = unpack(h_data_fmt_str, relay_extend_payload_tuple[6])

		h_data = TapCHData(h_data_tuple[0], h_data_tuple[1], h_data_tuple[2], h_data_tuple[3])
		relay_extend_payload = RelayExtendPayload(relay_extend_payload_tuple[0],
		                                          relay_extend_payload_tuple[1],
		                                          relay_extend_payload_tuple[2],
		                                          relay_extend_payload_tuple[3],
		                                          relay_extend_payload_tuple[4],
		                                          relay_extend_payload_tuple[5],
		                                          h_data)

		relay_cell_payload = RelayCellPayload(relay_cell_payload_tuple[0],
		                                      relay_cell_payload_tuple[1],
		                                      relay_cell_payload_tuple[2],
		                                      relay_cell_payload_tuple[3],
		                                      relay_cell_payload_tuple[4],
		                                      relay_extend_payload)

		extend_cell = Cell(cell_tuple[0], cell_tuple[1], cell_tuple[2], relay_cell_payload)

		return extend_cell

	@staticmethod
	def parse_encoded_extended_cell(cell_bytes: bytes) -> Cell:
		cell_tuple = Parser.parse_basic_cell(cell_bytes)
		relay_cell_payload_tuple = Parser.parse_encoded_relay_cell(cell_bytes)

		part_fmt_str1 = '=H'
		part_tuple1 = unpack(part_fmt_str1, relay_cell_payload_tuple[5][0:2])

		fmt_str = '=H' + str(part_tuple1[0]) + 's'
		relay_extended_payload_tuple = unpack(fmt_str, relay_cell_payload_tuple[5][0:2+part_tuple1[0]])

		h_data_fmt_str = '='+str(CC.DH_LEN)+'s'+str(CC.HASH_LEN)+'s'
		h_data_tuple = unpack(h_data_fmt_str, relay_extended_payload_tuple[1])

		server_h_data = TapSHData(h_data_tuple[0], h_data_tuple[1])

		relay_extended_payload = RelayExtendedPayload(relay_extended_payload_tuple[0], server_h_data)

		relay_cell_payload = RelayCellPayload(relay_cell_payload_tuple[0],
		                                      relay_cell_payload_tuple[1],
		                                      relay_cell_payload_tuple[2],
		                                      relay_cell_payload_tuple[3],
		                                      relay_cell_payload_tuple[4],
		                                      relay_extended_payload)

		extended_cell = Cell(cell_tuple[0], cell_tuple[1], cell_tuple[2], relay_cell_payload)

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
		addr, port = unpack('!IH', LSPEC)
		addr = str(IPv4Address(addr))
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
			gy_bytes = created_h_data.GY
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
			gy_bytes = extended_h_data.GY
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
