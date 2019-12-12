import json
from typing import Dict, Callable, List
from crypto.core_crypto import CryptoConstants as CC, CoreCryptoDH, CoreCryptoRSA, CoreCryptoHash
from cell.control_cell import LinkSpecifier, TapCHData, TapSHData
from cell.control_cell import TapSHData, TapCHData


class Cell:
	"""
	The Class representing a Tor Cell
	"""
	CMD_ENUM = {
		'PADDING': 0,
		'CREATE': 1,
		'CREATED': 2,
		'RELAY': 3,
		'DESTROY': 4,
		'CREATE_FAST': 5,
		'CREATED_FAST': 6,
		'NETINFO': 8,
		'RELAY_EARLY': 9,
		'CREATE2': 10,
		'CREATED2': 11,
		'PADDING_NEGOTIATE': 12,
		'VERSIONS': 7,
		'VPADDING': 128,
		'CERTS': 129,
		'AUTH_CHALLENGE': 130,
		'AUTHENTICATE': 131,
		'AUTHORIZE': 132
	}

	PAYLOAD_LEN = 509

	@staticmethod
	def CELL_LEN(v: int) -> int:
		"""

		:param v: The version value
		:return: The Size of entire cell based on the version of the cell
		"""
		return 512 if v < 4 else 514

	def __init__(self, CIRCID: int=None, CMD: int=None, LENGTH: int=None, PAYLOAD=None):
		"""
		Constructor
		:param CIRCID: The circuit id
		:param CMD: The command value
		:param PAYLOAD: The Payload object
		:param LENGTH: The length of the payload
		"""
		self.CIRCID = CIRCID
		self.CMD = CMD
		self.LENGTH = LENGTH
		self.PAYLOAD = PAYLOAD

	def serialize(self) -> Dict:
		return {'CIRCID': self.CIRCID, 'CMD': self.CMD, 'LENGTH': self.LENGTH, 'PAYLOAD': self.PAYLOAD.serialize()}

	@staticmethod
	def deserialize(dict_cell: Dict, payload_deserializer_arr: List[Callable]=None):
		return Cell(dict_cell['CIRCID'], dict_cell['CMD'], dict_cell['LENGTH'], payload_deserializer_arr[0](dict_cell['PAYLOAD'], payload_deserializer_arr[1:]))

	def net_serialize(self) -> str:
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_cell: str, payload_deserializer_arr: List[Callable]=None):
		return Cell.deserialize(json.loads(net_cell), payload_deserializer_arr)

	def build_create_cell(self, handshake_type: str, cell_ver: int, circ_id: int, onion_key) -> (str, str):
		x, gx = CoreCryptoDH.generate_dh_priv_key()
		client_h_data = CoreCryptoRSA.hybrid_encrypt(gx, onion_key)
		create_cell_payload = CreateCellPayload(CreateCellPayload.CREATE_HANDSHAKE_TYPE[handshake_type], CreateCellPayload.CREATE_HANDSHAKE_LEN[handshake_type], client_h_data)

		self.CIRCID = circ_id
		self.CMD = Cell.CMD_ENUM['CREATE2']
		self.LENGTH = Cell.CELL_LEN(cell_ver)
		self.PAYLOAD = create_cell_payload

		return x, gx

	def build_created_cell(self, cell_ver: int, circ_id: int, gx: str) -> (str, str):
		y, gy = CoreCryptoDH.generate_dh_priv_key()
		gxy = CoreCryptoDH.compute_dh_shared_key(y, gx)
		server_h_data = TapSHData(gy, CoreCryptoRSA.kdf_tor(gxy))
		created_cell_payload = CreatedCellPayload(CreatedCellPayload.TAP_S_HANDSHAKE_LEN, server_h_data)

		self.CIRCID = circ_id
		self.CMD = Cell.CMD_ENUM['CREATED2']
		self.LENGTH = Cell.CELL_LEN(cell_ver)
		self.PAYLOAD = created_cell_payload

		return gxy

	def build_extend_cell(self, handshake_type: str, cell_ver: int, circ_id: int, onion_key, addr, port, nspec, ls_type):
		# Encrypting the g^x with the onion public key of the tor node i
		x, gx = CoreCryptoDH.generate_dh_priv_key()
		h_data = CoreCryptoRSA.hybrid_encrypt(gx, onion_key)

		REMOTE_ADDR = {'address': addr, 'port': port}
		NSPEC_ARR = [LinkSpecifier(LinkSpecifier.LSTYPE[ls_type], LinkSpecifier.LSLEN[ls_type], json.dumps(REMOTE_ADDR))]
		extend_data = ExtendCellPayload(nspec, NSPEC_ARR, CreateCellPayload.CREATE_HANDSHAKE_TYPE[handshake_type], CreateCellPayload.TAP_C_HANDSHAKE_LEN, h_data)

		self.CIRCID = circ_id
		self.CMD = Cell.CMD_ENUM['EXTEND2']
		self.LENGTH = Cell.CELL_LEN(cell_ver)
		self.PAYLOAD = extend_data
		return x, gx

	def build_extended_cell(self):
		return None


class CreateCellPayload:

	"""
	The Class representing the Create Cell's Payload Object
	"""
	TAP_C_HANDSHAKE_LEN = CC.DH_LEN + CC.KEY_LEN + CC.PK_PAD_LEN

	CREATE_HANDSHAKE_TYPE = {
		'TAP': 0x0000,
		'reserved': 0x0001,
		'ntor': 0x0002
	}

	CREATE_HANDSHAKE_LEN = {
		'TAP': TAP_C_HANDSHAKE_LEN
	}

	def __init__(self, HTYPE: int=None, HLEN: int=None, HDATA=None):
		"""
		Constructor
		:param HTYPE: The Handshake type. Its a value from the CREATE_HANDSHAKE_TYPE Dict defined in CellConstants
		:param HLEN: The Length of the HDATA. For HTYPE = 'TAP', the value is TAP_C_HANDSHAKE_LEN defined in CellConstants
		:param HDATA: The actual Handshake data. Contains the first half of Diffie Hellman Handshake
		"""
		self.HTYPE = HTYPE
		self.HLEN = HLEN
		self.HDATA = HDATA

	def serialize(self) -> Dict:
		return {'HTYPE': self.HTYPE, 'HLEN': self.HLEN, 'HDATA': self.HDATA.serialize()}

	@staticmethod
	def deserialize(dict_payload: Dict, payload_deserializer_arr: List[Callable]=None):
		return CreateCellPayload(dict_payload['HTYPE'], dict_payload['HLEN'], payload_deserializer_arr[0](dict_payload['HDATA']))

	def net_serialize(self) -> str:
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_payload: str, payload_deserializer_arr: List[Callable]=None):
		return CreateCellPayload.deserialize(json.loads(net_payload), payload_deserializer_arr)


class CreatedCellPayload:

	"""
	The Class representing the Created Cell's Payload Object
	"""

	TAP_S_HANDSHAKE_LEN = CC.DH_LEN + CC.HASH_LEN

	def __init__(self, HLEN: int=None, HDATA=None):
		"""
		Constructor
		:param HLEN: The Length of the HDATA. For HTYPE = 'TAP', the value is TAP_S_HANDSHAKE_LEN defined in CellConstants
		:param HDATA: The actual Handshake data. Contains the first half of Diffie Hellman Handshake
		"""
		self.HLEN = HLEN
		self.HDATA = HDATA

	def extract_from_h_data(self):
		dict_hdata = json.loads(self.HDATA)
		return dict_hdata

	def serialize(self) -> Dict:
		return {'HLEN': self.HLEN, 'HDATA': self.HDATA.serialize()}

	@staticmethod
	def deserialize(dict_payload: Dict, payload_deserializer_arr: List[Callable]=None):
		return CreatedCellPayload(dict_payload['HLEN'], payload_deserializer_arr[0](dict_payload['HDATA']))

	def net_serialize(self) -> str:
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_payload: str, payload_deserializer_arr: List[Callable]=None):
		return CreatedCellPayload.deserialize(json.loads(net_payload), payload_deserializer_arr)


class ExtendCellPayload:

	"""
	The Class representing the Extend Cell's Payload Object
	"""

	def __init__(self, NSPEC: int=None, NSPEC_ARR: List=None, HTYPE: int=None, HLEN: int=None, HDATA=None):
		"""
		Constructor
		:param NSPEC: The number of Link Specifiers
		:param NSPEC_ARR: The Array of size NSPEC. Contains those many Link Specifiers
		:param HTYPE: The Handshake type. Its a value from the CREATE_HANDSHAKE_TYPE Dict defined in CellConstants
		:param HLEN: The Length of the HDATA. For HTYPE = 'TAP', the value is TAP_C_HANDSHAKE_LEN defined in CellConstants
		:param HDATA: The actual Handshake data. Contains the first half of Diffie Hellman Handshake
		"""
		self.NSPEC = NSPEC
		self.NSPEC_ARR = NSPEC_ARR
		self.HTYPE = HTYPE
		self.HLEN = HLEN
		self.HDATA = HDATA

	def serialize(self) -> Dict:
		serialized_NPSEC_ARR = []
		for LSPEC in self.NSPEC_ARR:
			serialized_NPSEC_ARR.append(LSPEC.serialize())
		return {'NSPEC': self.NSPEC, 'NSPEC_ARR': serialized_NPSEC_ARR, 'HTYPE': self.HTYPE, 'HLEN': self.HLEN, 'HDATA': self.HDATA.serialize()}

	@staticmethod
	def deserialize(dict_payload: Dict, payload_deserializer_arr: List[Callable]=None):
		deserialized_NSPEC_ARR = []
		for dict_LSPEC in dict_payload['NSPEC_ARR']:
			deserialized_NSPEC_ARR.append(payload_deserializer_arr[0](dict_LSPEC))
		return ExtendCellPayload(dict_payload['NSPEC'], deserialized_NSPEC_ARR, dict_payload['HTYPE'], dict_payload['HLEN'], payload_deserializer_arr[1](dict_payload['HDATA']))

	def net_serialize(self) -> str:
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_payload: str, payload_deserializer_arr: List[Callable]=None):
		return ExtendCellPayload.deserialize(json.loads(net_payload), payload_deserializer_arr)
