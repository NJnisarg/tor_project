from cell.cell_processing import Parser, Processor, Builder
from cell.serializers import Serialize
from cell.cell import Cell
from crypto.core_crypto import CoreCryptoDH


class ProcessCell:

    def __init__(self, cell_dict=None, conn=None, skt=None, sending_skt=None, node=None, circ_id=0):
        self.cell_dict = cell_dict
        self.conn = conn
        self.skt = skt
        self.cmd_to_func = {
            Cell.CMD_ENUM['CREATE2']: self.handle_create_cell,
        }
        self.sending_skt = sending_skt
        self.node = node
        self.circ_id = circ_id

    def handle_create_cell(self):
        if self.sending_skt == self.conn:
            create_cell = Parser.parse_create_cell(self.cell_dict)
            gx = Processor.process_create_cell(create_cell, self.node.onion_key_pri)
            y, gy = CoreCryptoDH.generate_dh_priv_key()
            created_cell = Builder.build_created_cell(y, gy, self.circ_id, gx)
            self.conn.sendall(Serialize.obj_to_json(created_cell).encode('utf-8'))
            return None
        else:
            print("Some error")
            return None

