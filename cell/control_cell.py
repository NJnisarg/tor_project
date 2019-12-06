from typing import Dict, List, Callable
import json


class TapCHData:
	"""
	The Object representing the TAP Handshake's client data
	"""

	def __init__(self, PADDING: str=None, SYMKEY: str=None, GX1:str=None, GX2: str=None):
		"""
		Constructor
		:param PADDING: PK_PAD_LEN size of padding
		:param SYMKEY: KEY_LEN Size of symmetric key
		:param GX1: First part of DH g^x
		:param GX2: Second part of DH g^x
		"""
		self.GX2 = GX2
		self.GX1 = GX1
		self.SYMKEY = SYMKEY
		self.PADDING = PADDING

	def serialize(self) -> Dict:
		return {'PADDING': self.PADDING, 'SYMKEY': self.SYMKEY, 'GX1': self.GX1, 'GX2': self.GX2}

	@staticmethod
	def deserialize(dict_payload: Dict, payload_deserializer_arr: List[Callable]=None):
		return TapCHData(dict_payload['PADDING'], dict_payload['SYMKEY'], dict_payload['GX1'], dict_payload['GX2'])

	def net_serialize(self) -> str:
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_payload: str, payload_deserializer_arr: List[Callable]=None):
		return TapCHData.deserialize(json.loads(net_payload))


class TapSHData:
	"""
	The Object representing the TAP Handshake's server data
	"""

	def __init__(self, GY: str=None, KH: str=None):
		"""
		Constructor
		:param GY: The g^y part of the DH Handshake
		:param KH: The Key derivative's hash value
		"""
		self.GY = GY
		self.KH = KH

	def serialize(self) -> Dict:
		return {'GY': self.GY, 'KH': self.KH}

	@staticmethod
	def deserialize(dict_payload: Dict, payload_deserializer_arr: List[Callable]=None):
		return TapSHData(dict_payload['GY'], dict_payload['KH'])

	def net_serialize(self) -> str:
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_payload: str, payload_deserializer_arr: List[Callable]=None):
		return TapSHData.deserialize(json.loads(net_payload))


class LinkSpecifier:
	"""
	The Object that represents the Link specifier struct in the extend cell of Tor
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

	def __init__(self, LSTYPE: int=None, LSLEN: int=None, LSPEC: str=None):
		"""
		Constructor
		:param LSTYPE: The Link specifier Type
		:param LSLEN:  The Length of the Link specifier string/bytes of LSPEC
		:param LSPEC: A string that is LSLEN long
		"""
		self.LSTYPE = LSTYPE
		self.LSLEN = LSLEN
		self.LSPEC = LSPEC

	def serialize(self) -> Dict:
		return {'LSTYPE': self.LSTYPE, 'LSLEN': self.LSLEN, 'LSPEC': self.LSPEC}

	@staticmethod
	def deserialize(dict_payload: Dict, payload_deserializer_arr: List[Callable]=None):
		return LinkSpecifier(dict_payload['LSTYPE'], dict_payload['LSLEN'], dict_payload['LSPEC'])

	def net_serialize(self) -> str:
		return json.dumps(self.serialize())

	@staticmethod
	def net_deserialize(net_payload: str, payload_deserializer_arr: List[Callable]=None):
		return TapCHData.deserialize(json.loads(net_payload))
