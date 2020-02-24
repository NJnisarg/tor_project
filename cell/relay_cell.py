from typing import Dict, Any

from cell.cell import Cell
from crypto.crypto_constants import CryptoConstants as CC


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
        self.FORMAT_STR = '=BHH4sH'+str(Cell.PAYLOAD_LEN - 11)+'s'
        self.FORMAT_STR_ARR = ['RELAY_CMD', 'RECOGNIZED', 'StreamID', 'Digest', 'Length', 'Data']
        self.RELAY_CMD=RELAY_CMD
        self.RECOGNIZED=RECOGNIZED
        self.StreamID=StreamID
        self.Digest=Digest
        self.Length=Length
        self.Data=Data

    def reprJSON(self) -> Dict[str, Any]:
        return vars(self)


class RelayExtendPayload:

    LSTYPE_ENUM = {
        'TLS_TCP_IPV4': 0,
        'TLS_TCP_IPV6': 1,
        'Legacy_identity': 2,
        'Ed25519_identity': 3
    }

    # Values in bytes
    LSTYPE_LSLEN_ENUM = {
        'TLS_TCP_IPV4': 6,
        'TLS_TCP_IPV6': 16,
        'Legacy_identity': 20,
        'Ed25519_identity': 32
    }

    def __init__(self, NPSEC, LSTYPE, LSLEN, LSPEC, HTYPE, HLEN, HDATA):
        """
        An EXTEND2 cell's relay payload contains:
        NSPEC(Number of link specifiers)     [1 byte]
        NSPEC times:
            LSTYPE(Link specifier type)           [1 byte]
            LSLEN(Link specifier length)         [1 byte]
            LSPEC(Link specifier)                [LSLEN bytes]
        HTYPE(Client Handshake Type)         [2 bytes]
        HLEN(Client Handshake Data Len)     [2 bytes]
        HDATA(Client Handshake Data)         [HLEN bytes]
        """
        self.FORMAT_STR = '=BBB'+str(LSLEN)+'s'+'HH'+str(HLEN)+'s'
        self.FORMAT_STR_ARR = ['NSPEC', 'LSTYPE', 'LSLEN', 'LSPEC', 'HTYPE', 'HLEN', 'HDATA']
        self.NSPEC = 1  # We will always pass NSPEC = 1. If not ignore it and make it 1.
        self.LSTYPE = LSTYPE
        self.LSLEN = LSLEN
        self.LSPEC = LSPEC
        self.HTYPE = HTYPE
        self.HLEN = HLEN
        self.HDATA = HDATA

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
        self.FORMAT_STR = '=H' + str(HLEN) + 's'
        self.FORMAT_STR_ARR = ['HLEN', 'HDATA']
        self.HLEN = HLEN
        self.HDATA = HDATA

    def reprJSON(self) -> Dict[str, Any]:
        return vars(self)


class RelayBeginPayload:

    """
    The class representing Relay Begin Cell's payload object
    """

    def __init__(self, ADDRPORT: bytes, FLAGS: int):
        # TODO: Add support for hostname and IPv6 formats as well
        """
        Constructor
        :param ADDRPORT: The hostname, the IPv4 address or the IPv6 address of the host to connect to. Currently we support only IPv4 address
        :param FLAGS: A set of options (32) to specify conditions for the creation of the payload. Check TOR Spec sec 6.2.
        """
        self.FORMAT_STR = '=6sI'
        self.FORMAT_STR_ARR = ['ADDRPORT', 'FLAGS']
        self.ADDRPORT = ADDRPORT
        self.FLAGS = FLAGS

    def reprJSON(self) -> Dict[str, any]:
        return vars(self)


class RelayConnectedPayload:

    """
    The class representing Relay Connected Payload object
    """

    def __init__(self, IPv4: int, TTL: int):
        # TODO: Add support for hostname and IPv6 formats as well
        """
        Constructor
        :param IPv4: IPv4 address to which the connection was made 
        :param TTL:A number of seconds (TTL) for which the address may be cached
        """
        self.FORMAT_STR='=II'
        self.IPv4=IPv4
        self.TTL=TTL
    def reprJSON(self) -> Dict[str, any]:
        return vars(self)
