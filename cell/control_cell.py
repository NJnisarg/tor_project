from typing import Dict, Any

from crypto.crypto_constants import CryptoConstants as CC


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

	def reprJSON(self) -> Dict[str, Any]:
		return vars(self)


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

	def reprJSON(self) -> Dict[str, Any]:
		return vars(self)


class TapCHData:
	"""
	The Object representing the TAP Handshake's client data
	"""

	def __init__(self, PADDING:str=None, SYMKEY:str=None, GX1:str=None, GX2:str=None):
		"""
		Constructor
		:param PADDING: PK_PAD_LEN size of padding
		:param SYMKEY: KEY_LEN Size of symmetric key
		:param GX1: First part of DH g^x
		:param GX2: Second part of DH g^x
		"""
		self.PADDING = PADDING
		self.SYMKEY = SYMKEY
		self.GX1 = GX1
		self.GX2 = GX2

	def reprJSON(self) -> Dict[str, Any]:
		return vars(self)


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

	def reprJSON(self) -> Dict[str, Any]:
		return vars(self)
