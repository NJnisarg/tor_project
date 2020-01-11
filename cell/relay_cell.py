from typing import List, Dict, Any

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
    





