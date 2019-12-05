import json
from typing import Dict, Callable, List
from crypto.core_crypto import CryptoConstants as CC


class CellConstants:
	"""
	This class defines the different Cell Constants used in the Tor Spec.
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

	TAP_C_HANDSHAKE_LEN = CC.DH_LEN + CC.KEY_LEN + CC.PK_PAD_LEN
	TAP_S_HANDSHAKE_LEN = CC.DH_LEN + CC.HASH_LEN

	CREATE_HANDSHAKE_TYPE = {
		'TAP': 0x0000,
		'reserved': 0x0001,
		'ntor': 0x0002
	}

	@staticmethod
	def CELL_LEN(v: int) -> int:
		"""

		:param v: The version value
		:return: The Size of entire cell based on the version of the cell
		"""
		return 512 if v < 4 else 514


class Cell:
	"""
	The Class representing a Tor Cell
	"""

	def __init__(self, CIRCID: int, CMD: int, LENGTH: int, PAYLOAD):
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
		"""
		Serializes the Cell object and returns a python Dict. It recursively also serializes the Payload
		:return: Cell as a python Dict
		"""
		return {'CIRCID': self.CIRCID, 'CMD': self.CMD, 'LENGTH': self.LENGTH, 'PAYLOAD': self.PAYLOAD.serialize()}

	@staticmethod
	def deserialize(dict_cell: Dict, payload_deserializer: Callable):
		"""
		Converts a dict to a Cell Object

		:param dict_cell: The cell as a python dictionary
		:param payload_deserializer: The serializer function to serialize the Payload
		:return: A cell object
		"""
		return Cell(dict_cell['CIRCID'], dict_cell['CMD'], dict_cell['LENGTH'], payload_deserializer(dict_cell['PAYLOAD']))

	def net_serialize(self) -> str:
		"""
		The function that will serialize the cell object for transmitting over network
		:return: Returns the JSON String by converting the object first into a python dict
		"""
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_cell: str, payload_deserializer: Callable):
		"""
		Converts a network string into a Cell object
		:param net_cell: The cell that comes as a JSON String from the network
		:param payload_deserializer: The function to deserialize the payload
		:return: A Cell object
		"""
		return Cell.deserialize(json.loads(net_cell), payload_deserializer)


class CreateCellPayload:

	"""
	The Class representing the Create Cell's Payload Object
	"""

	def __init__(self, HTYPE: int, HLEN: int, HDATA: str):
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
		"""
		Serializes the payload as a python Dict
		:return: Python Dict representation of Payload
		"""
		return {'HTYPE': self.HTYPE, 'HLEN': self.HLEN, 'HDATA': self.HDATA}

	@staticmethod
	def deserialize(dict_payload: Dict):
		"""
		Returns the Payload as a python Object
		:param dict_payload: The python dict that will be deserialized
		:return: The CreateCellPayload Object
		"""
		return CreateCellPayload(dict_payload['HTYPE'], dict_payload['HLEN'], dict_payload['HDATA'])

	def net_serialize(self) -> str:
		"""
		The JSON String serialized from the python dict representation of the Payload object
		:return: JSON String
		"""
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_payload: str):
		"""
		The deserialized Payload object from a JSON String
		:param net_payload: The JSON String from network
		:return: A Payload object
		"""
		return CreateCellPayload.deserialize(json.loads(net_payload))


class CreatedCellPayload:

	"""
	The Class representing the Created Cell's Payload Object
	"""

	def __init__(self, HLEN: int, HDATA: str):
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
		"""
		Serializes the payload as a python Dict
		:return: Python Dict representation of Payload
		"""
		return {'HLEN': self.HLEN, 'HDATA': self.HDATA}

	@staticmethod
	def deserialize(dict_payload: Dict):
		"""
		Returns the Payload as a python Object
		:param dict_payload: The python dict that will be deserialized
		:return: The CreateCellPayload Object
		"""
		return CreatedCellPayload(dict_payload['HLEN'], dict_payload['HDATA'])

	def net_serialize(self) -> str:
		"""
		The JSON String serialized from the python dict representation of the Payload object
		:return: JSON String
		"""
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_payload: str):
		"""
		The deserialized Payload object from a JSON String
		:param net_payload: The JSON String from network
		:return: A Payload object
		"""
		return CreatedCellPayload.deserialize(json.loads(net_payload))


class ExtendCellPayload:

	"""
	The Class representing the Extend Cell's Payload Object
	"""
	LSTYPE = {
		'IPv4': 0,
		'IPv6': 1,
		'LegacyId': 2,
		'Ed25519Id': 3
	}

	LSLEN = {
		'IPv4': 6,
		'IPv6': 18,
		'LegacyId': 20,
		'Ed25519Id': 32
	}

	def __init__(self, NSPEC: int, NSPEC_ARR: List, HTYPE: int, HLEN: int, HDATA: str):
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
		"""
		Serializes the payload as a python Dict
		:return: Python Dict representation of Payload
		"""
		return {'NSPEC': self.NSPEC, 'NSPEC_ARR': self.NSPEC_ARR, 'HTYPE': self.HTYPE, 'HLEN': self.HLEN, 'HDATA': self.HDATA}

	@staticmethod
	def deserialize(dict_payload: Dict):
		"""
		Returns the Payload as a python Object
		:param dict_payload: The python dict that will be deserialized
		:return: The CreateCellPayload Object
		"""
		return ExtendCellPayload(dict_payload['NSPEC'], dict_payload['NSPEC_ARR'], dict_payload['HTYPE'], dict_payload['HLEN'], dict_payload['HDATA'])

	def net_serialize(self) -> str:
		"""
		The JSON String serialized from the python dict representation of the Payload object
		:return: JSON String
		"""
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_payload: str):
		"""
		The deserialized Payload object from a JSON String
		:param net_payload: The JSON String from network
		:return: A Payload object
		"""
		return ExtendCellPayload.deserialize(json.loads(net_payload))
