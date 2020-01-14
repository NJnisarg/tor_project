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
    
class Relay_Extend2_Payload:

    def __init__(self, NPSEC,LSTPYE,LSLEN,HTYPE,HLEN,HDATA):
       '''
        An EXTEND2 cell's relay payload contains:
        NSPEC(Number of link specifiers)     [1 byte]
        NSPEC times:
            LSTYPE(Link specifier type)           [1 byte]
            LSLEN(Link specifier length)         [1 byte]
            LSPEC(Link specifier)                [LSLEN bytes]
        HTYPE(Client Handshake Type)         [2 bytes]
        HLEN(Client Handshake Data Len)     [2 bytes]
        HDATA(Client Handshake Data)         [HLEN bytes]
        '''
       self.NSPEC=NPSEC
       self.LSTYPE=NPSEC*LSTYPE
       self.LSLEN=NPSEC*LSLEN
       self.LSPEC = NPSEC*LSPEC
       self.HTYPE=HTYPE
       self.HLEN=HLEN
       self.HDATA=HDATA


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

class RelayBeginPayload:
    
    """
    The class representing Relay Begin Cell's payload object
    """

    def __init__(self, ADDRPORT: str, FLAGS: str):
        """
        Constructor
        :param ADDRPORT: The hostname, the IPv4 address or the IPv6 address of the host to connect to.
        :param FLAGS: A set of options (32) to specify conditions for the creation of the payload. Check TOR Spec sec 6.2.
        """
        self.ADDRPORT = ADDRPORT
        self.FLAGS = FLAGS

    def reprJSON(self) -> Dict[str, any]:
        return vars(self)
