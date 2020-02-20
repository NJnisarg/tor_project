from typing import Dict, Any


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

	LENGTH_LEN = 2
	COMMAND_LEN = 1
	PAYLOAD_LEN = 509

	@staticmethod
	def CIRCID_LEN(v: int) -> int:
		if v <= 3:
			return 2
		elif v >= 4:
			return 4

	@staticmethod
	def CELL_LEN(v: int) -> int:
		"""
		The Length of a cell for a given version. The size changes because of the CIRCID_LEN
		:param v: The version value
		:return: The Size of entire cell based on the version of the cell
		"""
		return Cell.CIRCID_LEN(v) + Cell.COMMAND_LEN + Cell.PAYLOAD_LEN

	def __init__(self, CIRCID: int = None, CMD: int = None, LENGTH: int = None, PAYLOAD=None):
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

	def reprJSON(self) -> Dict[str, Any]:
		return vars(self)
