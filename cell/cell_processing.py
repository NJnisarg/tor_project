from ipaddress import IPv4Address
from struct import pack, unpack
from typing import Dict, Tuple

from cell.cell import Cell
from cell.control_cell import CreateCellPayload, TapCHData, TapSHData, CreatedCellPayload
from cell.relay_cell import RelayCellPayload, RelayExtendedPayload, RelayBeginPayload, RelayExtendPayload,RelayConnectedPayload
from connection.skt import Skt
from crypto.core_crypto import CoreCryptoRSA, CoreCryptoDH, CoreCryptoMisc, CoreCryptoSymmetric, CryptoConstants as CC


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
	def build_begin_cell(addrport: bytes, flag_dict, circ_id: int, recognized: int, streamID: int, kdf_dict1: Dict, kdf_dict2: Dict, kdf_dict3: Dict) -> Cell:
		"""
		The method to build a Begin Cell
		:param addrport:
		:param flag_dict:
		:param circ_id:
		:param recognized:
		:param streamID:
		:return: The Begin Cell object
		"""
		flags = int(0)
		flags |= flag_dict['IPV6_PREF']
		flags |= (flag_dict['IPV4_NOT_OK'] << 1)
		flags |= (flag_dict['IPV6_OK'] << 2)

		digest_dict = {
			'addrPort': addrport,
			'flags': flags,
			'relayCMD': RelayCellPayload.RELAY_CMD_ENUM['RELAY_BEGIN'],
			'recognized': recognized,
			'streamID': streamID,
			'relayPayloadLen': Cell.PAYLOAD_LEN - 11
		}
		digest = b''  # CoreCryptoMisc.calculate_digest(digest_dict)

		# Encrypt the values by packing and unpacking
		enc_addrport = CoreCryptoSymmetric.encrypt_from_origin(addrport, kdf_dict1, kdf_dict2, kdf_dict3)
		enc_flags = unpack('!I', CoreCryptoSymmetric.encrypt_from_origin(pack('!I', flags), kdf_dict1, kdf_dict2, kdf_dict3))[0]
		enc_relay_cmd = RelayCellPayload.RELAY_CMD_ENUM['RELAY_BEGIN']  # unpack('!B', CoreCryptoSymmetric.encrypt_from_origin(pack('!B', RelayCellPayload.RELAY_CMD_ENUM['RELAY_BEGIN']), kdf_dict1, kdf_dict2, kdf_dict3))[0]
		enc_recognized = unpack('!H', CoreCryptoSymmetric.encrypt_from_origin(pack('!H', recognized), kdf_dict1, kdf_dict2, kdf_dict3))[0]
		enc_stream_id = unpack('!H', CoreCryptoSymmetric.encrypt_from_origin(pack('!H', streamID), kdf_dict1, kdf_dict2, kdf_dict3))[0]
		enc_relay_payload_len = unpack('!H', CoreCryptoSymmetric.encrypt_from_origin(pack('!H', Cell.PAYLOAD_LEN - 11), kdf_dict1, kdf_dict2, kdf_dict3))[0]
		enc_digest = CoreCryptoSymmetric.encrypt_from_origin(digest, kdf_dict1, kdf_dict2, kdf_dict3)

		relay_begin_payload = RelayBeginPayload(enc_addrport, enc_flags)
		relay_cell_payload = RelayCellPayload(enc_relay_cmd, enc_recognized, enc_stream_id, enc_digest, enc_relay_payload_len, relay_begin_payload)
		begin_cell = Cell(circ_id, Cell.CMD_ENUM['RELAY'], Cell.PAYLOAD_LEN, relay_cell_payload)
		return begin_cell

	@staticmethod
	def build_relay_connected_cell(CIRCID: int, StreamID, kdf_dict, IPv4_address : str,TTL : int) -> Cell:

		"""

		:param CIRCID: The Circuit ID
		:param StreamID: The Stream ID
		:param kdf_dict: A dictionary (key) to encrypt data
		:param IPv4_address: The IPv4 address to which the connection was made [4 octets]
		:param TTL: A number of seconds (TTL) for which the address may be cached [4 octets]
		:return:
		"""


		# Encrypt the values by packing and unpacking
		enc_StreamID = unpack('!H', CoreCryptoSymmetric.encrypt_for_hop(pack('!H', StreamID), kdf_dict))[0]
		enc_relay_payload_len = unpack('!H',CoreCryptoSymmetric.encrypt_for_hop(pack('!H', Cell.PAYLOAD_LEN - 11),kdf_dict))[0]
		enc_IPv4_address = unpack('!I', CoreCryptoSymmetric.encrypt_for_hop(pack('!I', int(IPv4Address(IPv4_address))), kdf_dict))[0]
		enc_TTL = unpack('!I',CoreCryptoSymmetric.encrypt_for_hop(pack('!I', TTL), kdf_dict))[0]
		# enc_digest = CoreCryptoSymmetric.encrypt_for_hop(digest, kdf_dict)


		relay_connected_cell_payload = RelayConnectedPayload(enc_IPv4_address, enc_TTL)

		relay_cell_payload = RelayCellPayload(RelayCellPayload.RELAY_CMD_ENUM['RELAY_CONNECTED'], 0, enc_StreamID, b'',
												 enc_relay_payload_len, relay_connected_cell_payload)

		# Construct the actual cell
		relay_cell = Cell(CIRCID, Cell.CMD_ENUM['RELAY'], Cell.PAYLOAD_LEN, relay_cell_payload)
		return relay_cell



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
	def parse_encoded_connected_cell(cell_bytes: bytes)-> Cell:
		cell_tuple = Parser.parse_basic_cell(cell_bytes)

		relay_payload_tuple = Parser.parse_encoded_relay_cell(cell_bytes)
		
		relay_connected_tuple=unpack('=II',relay_payload_tuple[5][0:8])
		relay_connected_obj=RelayConnectedPayload(relay_connected_tuple[0],relay_connected_tuple[1])
		relay_payload_obj=RelayCellPayload(relay_payload_tuple[0],relay_payload_tuple[1],relay_payload_tuple[2],relay_payload_tuple[3],relay_payload_tuple[4],relay_connected_obj)

		cell=Cell(cell_tuple[0],cell_tuple[1],cell_tuple[2],relay_payload_obj)
		return cell		


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
	def parse_encoded_begin_cell(cell_bytes: bytes) -> Cell:
		cell_tuple = Parser.parse_basic_cell(cell_bytes)
		relay_cell_payload_tuple = Parser.parse_encoded_relay_cell(cell_bytes)

		fmt_str = '=6sI'
		relay_begin_payload_tuple = unpack(fmt_str, relay_cell_payload_tuple[5][0:6+4])

		relay_begin_payload = RelayBeginPayload(relay_begin_payload_tuple[0], relay_begin_payload_tuple[1])

		relay_cell_payload = RelayCellPayload(relay_cell_payload_tuple[0],
		                                      relay_cell_payload_tuple[1],
		                                      relay_cell_payload_tuple[2],
		                                      relay_cell_payload_tuple[3],
		                                      relay_cell_payload_tuple[4],
		                                      relay_begin_payload)

		begin_cell = Cell(cell_tuple[0], cell_tuple[1], cell_tuple[2], relay_cell_payload)

		return begin_cell

	@staticmethod
	def parse_encoded_data_cell(cell_bytes: bytes) -> Cell:
		cell_tuple = Parser.parse_basic_cell(cell_bytes)

		relay_cell_payload_tuple = Parser.parse_encoded_relay_cell(cell_bytes)

		relay_data_payload = relay_cell_payload_tuple[5]

		relay_cell_payload = RelayCellPayload(relay_cell_payload_tuple[0],
												relay_cell_payload_tuple[1],
												relay_cell_payload_tuple[2],
												relay_cell_payload_tuple[3],
												relay_cell_payload_tuple[4],
												relay_data_payload)

		relay_data_cell = Cell(cell_tuple[0], cell_tuple[1], cell_tuple[2], relay_cell_payload)

		return relay_data_cell



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
	def process_begin_cell(cell: Cell, kdf_dict: Dict) -> Tuple:
		# Take the encrypted values from the cell
		enc_recognized = cell.PAYLOAD.RECOGNIZED
		enc_stream_id = cell.PAYLOAD.StreamID
		enc_digest = cell.PAYLOAD.Digest
		enc_length = cell.PAYLOAD.Length
		enc_addrport = cell.PAYLOAD.Data.ADDRPORT
		enc_flags = cell.PAYLOAD.Data.FLAGS

		# Remove one layer of onion skin
		dec_recognized = unpack('!H', CoreCryptoSymmetric.decrypt_for_hop(pack('!H', enc_recognized), kdf_dict))[0]
		dec_stream_id = unpack('!H', CoreCryptoSymmetric.decrypt_for_hop(pack('!H', enc_stream_id), kdf_dict))[0]
		dec_digest = CoreCryptoSymmetric.decrypt_for_hop(enc_digest, kdf_dict)
		dec_length = unpack('!H', CoreCryptoSymmetric.decrypt_for_hop(pack('!H', enc_length), kdf_dict))[0]
		dec_addrport = CoreCryptoSymmetric.decrypt_for_hop(enc_addrport, kdf_dict)
		dec_flags = unpack('!I', CoreCryptoSymmetric.decrypt_for_hop(pack('!I', enc_flags), kdf_dict))[0]

		# Set the decrypted values
		cell.PAYLOAD.RECOGNIZED = dec_recognized
		cell.PAYLOAD.StreamID = dec_stream_id
		cell.PAYLOAD.Digest = dec_digest
		cell.PAYLOAD.Length = dec_length
		cell.PAYLOAD.Data = RelayBeginPayload(dec_addrport, dec_flags)

		# Return
		return dec_recognized, cell

	@staticmethod
	def process_connected_cell_router(cell: Cell, kdf_dict: Dict) -> Cell:
		"""
		Function for processing a connected cell when it arrives in a router
		:param cell: The cell object for the connected cell
		:param kdf_dict: The key derivative function dictionary for the session key
		"""
		# Take values to be encrypted from the cell
		dec_recognized = cell.PAYLOAD.RECOGNIZED
		dec_stream_id = cell.PAYLOAD.StreamID
		dec_digest = cell.PAYLOAD.Digest
		dec_length = cell.PAYLOAD.Length
		dec_IPv4 = cell.PAYLOAD.Data.IPv4
		dec_TTL = cell.PAYLOAD.Data.TTL

		# Add one layer of onion skin
		enc_recognized = unpack('!H', CoreCryptoSymmetric.encrypt_for_hop(pack('!H', dec_recognized), kdf_dict))[0]
		enc_stream_id = unpack('!H', CoreCryptoSymmetric.encrypt_for_hop(pack('!H', dec_stream_id), kdf_dict))[0]
		enc_digest = CoreCryptoSymmetric.encrypt_for_hop(dec_digest, kdf_dict)
		enc_length = unpack('!H', CoreCryptoSymmetric.encrypt_for_hop(pack('!H', dec_length), kdf_dict))[0]
		enc_IPv4 = unpack('!I', CoreCryptoSymmetric.encrypt_for_hop(pack('!I', dec_IPv4), kdf_dict))[0]
		enc_TTL = unpack('!I', CoreCryptoSymmetric.encrypt_for_hop(pack('!I', dec_TTL), kdf_dict))[0]

		# Adding encrypted values to the cell
		cell.PAYLOAD.RECOGNIZED = enc_recognized
		cell.PAYLOAD.StreamID = enc_stream_id
		cell.PAYLOAD.Digest = enc_digest
		cell.PAYLOAD.Length = enc_length
		cell.PAYLOAD.Data.IPv4 = enc_IPv4
		cell.PAYLOAD.Data.TTL = enc_TTL

		return cell

	@staticmethod
	def process_connected_cell_proxy(cell: Cell, kdf_dict1: Dict, kdf_dict2: Dict, kdf_dict3: Dict) -> Cell:
		"""
		Function for processing a connected cell when it arrives in a router
		:param cell: The cell object for the connected cell
		:param kdf_dict1, kdf_dict2, kdf_dict3: The key derivative function dictionaries for the three session keys
		"""
		# Take values from the cell
		enc_recognized = cell.PAYLOAD.RECOGNIZED
		enc_stream_id = cell.PAYLOAD.StreamID
		enc_digest = cell.PAYLOAD.Digest
		enc_length = cell.PAYLOAD.Length
		enc_IPv4 = cell.PAYLOAD.Data.IPv4
		enc_TTL = cell.PAYLOAD.Data.TTL

		# Decrypt all onion layers
		dec_recognized = unpack('!H', CoreCryptoSymmetric.decrypt_from_origin(pack('!H', enc_recognized), kdf_dict1, kdf_dict2, kdf_dict3))[0]
		dec_stream_id = unpack('!H', CoreCryptoSymmetric.decrypt_from_origin(pack('!H', enc_stream_id), kdf_dict1, kdf_dict2, kdf_dict3))[0]
		dec_digest = CoreCryptoSymmetric.decrypt_from_origin(enc_digest, kdf_dict1, kdf_dict2, kdf_dict3)
		dec_length = unpack('!H', CoreCryptoSymmetric.decrypt_from_origin(pack('!H', enc_length), kdf_dict1, kdf_dict2, kdf_dict3))[0]
		dec_IPv4 = unpack('!I', CoreCryptoSymmetric.decrypt_from_origin(pack('!I', enc_IPv4), kdf_dict1, kdf_dict2, kdf_dict3))[0]
		dec_TTL = unpack('!I', CoreCryptoSymmetric.decrypt_from_origin(pack('!I', enc_TTL), kdf_dict1, kdf_dict2, kdf_dict3))[0]

		# Adding decrypted values to the cell
		cell.PAYLOAD.RECOGNIZED = dec_recognized
		cell.PAYLOAD.StreamID = dec_stream_id
		cell.PAYLOAD.Digest = dec_digest
		cell.PAYLOAD.Length = dec_length
		cell.PAYLOAD.Data.IPv4 = dec_IPv4
		cell.PAYLOAD.Data.TTL = dec_TTL

		return cell

	@staticmethod
	def process_relay_data_cell(cell: Cell, kdf_dict: Dict):
		"""
        Function for processing a relay data cell when it arrives in a router
        :param cell: The cell object for the relay data cell
        :param kdf_dict: The key derivative function dictionary for the session key
        """
		# Take values to be encrypted from the cell
		enc_recognized = cell.PAYLOAD.RECOGNIZED
		enc_stream_id = cell.PAYLOAD.StreamID
		enc_digest = cell.PAYLOAD.Digest
		enc_length = cell.PAYLOAD.Length
		enc_bytestring = cell.PAYLOAD.Data

		# Add one layer of onion skin
		dec_recognized = unpack('!H', CoreCryptoSymmetric.decrypt_for_hop(pack('!H', enc_recognized), kdf_dict))[0]
		dec_stream_id = unpack('!H', CoreCryptoSymmetric.decrypt_for_hop(pack('!H', enc_stream_id), kdf_dict))[0]
		dec_digest = CoreCryptoSymmetric.decrypt_for_hop(enc_digest, kdf_dict)
		dec_length = unpack('!H', CoreCryptoSymmetric.decrypt_for_hop(pack('!H', enc_length), kdf_dict))[0]
		dec_bytestring = CoreCryptoSymmetric.decrypt_for_hop( enc_bytestring, kdf_dict)[0]

		# Adding encrypted values to the cell
		cell.PAYLOAD.RECOGNIZED = dec_recognized
		cell.PAYLOAD.StreamID = dec_stream_id
		cell.PAYLOAD.Digest = dec_digest
		cell.PAYLOAD.Length = dec_length
		cell.PAYLOAD.Data = dec_bytestring




		if dec_recognized==0:
			http = dec_bytestring.decode("utf-8")

			method = http.split(" ")[0]
			url = http.split(" ")[1]

			http_dict ={
				"method" : method,
				"url" : url
			}
			return dec_recognized, http_dict, cell

		else:
			return dec_recognized, None, cell
