from typing import List, Dict, Any

class Relay_Extended2_Payload:

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