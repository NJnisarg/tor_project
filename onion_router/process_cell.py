from cell.cell_processing import Parser, Processor, Builder
from cell.serializers import Serialize
from cell.cell import Cell
from crypto.core_crypto import CoreCryptoDH


class ProcessCell:

    def __init__(self, cell_dict=None, conn=None, skt=None, sending_skt=None, node=None, circ_id=0):
        """
        The constructor for Process Cell class
        :param cell_dict: The cell as a dict to be processed
        :param conn: The connection object from which cell is received
        :param skt: The socket object to be used for next hop
        :param sending_skt: The socket that was passed as chosen to be used for sending
        :param node: The node object for the router
        :param circ_id: The circuit ID
        """
        self.cell_dict = cell_dict
        self.conn = conn
        self.skt = skt
        self.cmd_to_func = {
            Cell.CMD_ENUM['CREATE2']: self.handle_create_cell,
        }  # A lookup for the function to be called based on the cell
        self.sending_skt = sending_skt
        self.node = node
        self.circ_id = circ_id

    def handle_create_cell(self):
        """
        The actual function that handles the create cell processing for the circuit of a router
        :return:
        """
        if self.sending_skt == self.conn:

            # Call the Parser for create cell
            create_cell = Parser.parse_create_cell(self.cell_dict)

            # Process the create cell
            gx = Processor.process_create_cell(create_cell, self.node.onion_key_pri)
            y, gy = CoreCryptoDH.generate_dh_priv_key()

            # After processing the create cell, we make a created cell
            # and send it down the socket
            created_cell = Builder.build_created_cell(y, gy, self.circ_id, gx)
            print(created_cell)
            self.conn.sendall(Serialize.obj_to_json(created_cell).encode('utf-8'))
            return None
        else:
            print("Some error")
            return None

