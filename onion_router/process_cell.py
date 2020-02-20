from cell.cell import Cell
from cell.cell_processing import Parser, Processor, Builder
from cell.relay_cell import RelayCellPayload
from cell.serializers import Serialize, Deserialize
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
            Cell.CMD_ENUM['RELAY']: self.handle_relay_cell,
            Cell.CMD_ENUM['CREATED2']: self.handle_created_cell
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
            print("Created cell sent")
            return 0
        else:
            print("Some error")
            return 1

    def handle_relay_cell(self):
        relaycmd_to__func = {
            RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTEND']: self.handle_relay_extend_cell
        }

        if self.sending_skt == self.conn:
            return relaycmd_to__func[self.cell_dict['PAYLOAD']['RELAY_CMD_ENUM']]()

        else:
            print("Some error")
            return 1

    def handle_relay_extend_cell(self):
        extend_cell = Parser.extend2_parse_create_cell(self.cell_dict)
        # Assume process extend2 cell returns the address and port of next hop node
        # address, port will be in LSPEC
        # extend2_process_create_cell function needs to be changed accordingly
        addr, port, htype, hlen, hdata = Processor.extend2_process_create_cell(extend_cell, self.node.onion_key_pri)

        # Connect with next node
        self.skt.client_connect(addr, port)

        # Create a CREATE2 Cell.
        create_cell = Builder.build_create_cell(self.circ_id, htype, hlen, hdata)

        # Sending a JSON String down the socket
        self.skt.client_send_data(Serialize.obj_to_json(create_cell).encode('utf-8'))

        # Get the created cell in response and convert it to python Cell Object
        recv_data = self.skt.client_recv_data().decode('utf-8')
        dict_cell = Deserialize.json_to_dict(recv_data)
        created_cell = Parser.parse_created_cell(dict_cell)

        # process created cell
        hlen, hdata = Processor.process_created_cell(created_cell)

        # Create extended cell
        extended_cell = Builder.build_extended_cell(self.circ_id, hlen, hdata)

        # send extended to conn
        self.conn.sendall(Serialize.obj_to_json(extended_cell).encode('utf-8'))
        print("Extended cell sent")

        return 0


