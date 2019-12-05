import json
from node_directory_service.node_directory_service import NodeDirectoryService
from connection.node import Node
from connection.skt import Skt
from circuit import Circuit
from cell.cell import Cell, CellConstants
from crypto.core_crypto import CoreCryptoRSA


class OnionRouter:

    def __init__(self, node=None, is_exit_node=True):
        self.node = node
        self.skt = Skt(node.host, node.port)
        self.is_exit_node = is_exit_node
        self.routing_table = {}

    def process_cell(self, cell):

		if created_cell['CMD'] == CellConstants.CMD_ENUM['CREATE2']:
            create_cell_circid = cell['CIRCID']
            create_cell_cmd = cell['CMD']
            create_cell_payload_length = cell['LENGTH']
            create_cell_payload = cell['PAYLOAD']

            gx = CoreCryptoRSA.hybrid_encrypt(create_cell_payload['HDATA'], self.node.onion_key_pri)
            gy = 'g^y'
            gxy = gy # use some function to compute the gxy here

            or.routing_table.add(create_cell_circid, None)
            circuit = Circuit(node, skt, gxy)

            # Create a CREATED2 Cell.
            created_data = {
                'HLEN': CellConstants.TAP_C_HANDSHAKE_LEN,
                'HDATA': {
                    'Y' : gy,
                    'KEY_DER' : CoreCryptoRSA.kdf_tor(gxy)
                }
            }
            created_cell = Cell(circuit.get_rand_circ_id(), CellConstants.CMD_ENUM['CREATED2'], created_data, CellConstants.PAYLOAD_LEN)
            self.skt.server_send_data(json.loads(created_cell.JSON_CELL))
