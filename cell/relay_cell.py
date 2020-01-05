from typing import List, Dict, Any
from crypto.core_crypto import CryptoConstants as CC

class RelayCellPayload:

    RELAY_CMD_ENUM = {
        'RELAY_BEGIN': 1,
        'RELAY_DATA': 2,
        'RELAY_END': 3,
        'RELAY_CONNECTED': 4,
        'RELAY_SENDME': 5,
        'RELAY_EXTEND': 6,
        'RELAY_EXTENDED': 7,
        'RELAY_TRUNCATE': 8,
        'RELAY_TRUNCATED': 9,
        'RELAY_DROP': 10,
        'RELAY_RESOLVE': 11,
        'RELAY_RESOLVED': 12,
        'RELAY_BEGIN_DIR': 13,
        'RELAY_EXTEND2': 14,
        'RELAY_EXTENDED2': 15,
    }

    def __init__(self, RELAY_CMD, RECOGNIZED, StreamID, Digest, Length, Data):
        """
        Constructor
        :param RELAY_CMD: The relay command value
        :param RECOGNIZED: Specifies whether the cell is encrypted or not
        :param Digest:
        :param Length: The length of the payload
        :param Data: The Payload object
        """
        self.RELAY_CMD=RELAY_CMD
        self.RECOGNIZED=RECOGNIZED
        self.StreamID=StreamID
        self.Digest=Digest
        self.Length=Length
        self.Data=Data

        def reprJSON(self) -> Dict[str, Any]:
            return vars(self)
    
class RelayExtendedPayload:

    """
    The class representing Extended Cell's payload object
    """

    TAP_S_HANDSHAKE_LEN = CC.DH_LEN + CC.HASH_LEN

    def __init__(self, HLEN: int=None, HDATA=None):
        """
		Constructor
		:param HLEN: The Length of the HDATA
		:param HDATA: The actual Handshake data. Contains the first half of Diffie Hellman Handshake
		"""
		self.HLEN = HLEN
		self.HDATA = HDATA

    def reprJSON(self) -> Dict[str, Any]:
		return vars(self)
