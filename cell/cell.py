from crypto.core_crypto import CoreCryptoRSA
from crypto.core_crypto import CryptoConstants as CC


class CellConstants:
	PAYLOAD_LEN = 509

	@staticmethod
	def CELL_LEN(v: int) -> int:
		return 512 if v < 4 else 514

	TAP_C_HANDSHAKE_LEN = CC.DH_LEN + CC.KEY_LEN + CC.PK_PAD_LEN

	CREATE_HANDSHAKE_TYPE = {
		'TAP': 0x0000,
		'reserved': 0x0001,
		'ntor': 0x0002

	}

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


class Cell:

	def __init__(self, CIRCID=None, CMD=None, PAYLOAD=None, LENGTH=None):
		self.CIRCID = CIRCID
		self.CMD = CMD
		self.LENGTH = LENGTH
		self.PAYLOAD = PAYLOAD
