import select

from cell.serializers import Deserialize
from connection.node import Node
from connection.skt import Skt
import threading

from onion_router.process_cell import ProcessCell


class Circuit:

	def __init__(self, circ_id: int, node: Node, conn, session_key=None):
		self.circ_id = circ_id
		self.node = node
		self.conn = conn
		self.skt = Skt(node.host, 12345)
		self.session_key = session_key
		self.routing_table = {}

	def main(self):
		sockets_list = [self.conn]
		while True:
			socket_list = [self.conn, self.skt]
			for socket in socket_list:
				cell = str(socket.recv(1024).decode())
				if cell is None or cell == "":
					continue
				cell_dict = Deserialize.json_to_dict(cell)
				if cell_dict:
					print(cell_dict)
					proc_thread = threading.Thread(target=self.process_cell, args=(cell_dict))
					proc_thread.start()
			# except:
			#     print("Error")

	def process_cell(self, cell):
		processcell = ProcessCell(cell, self.conn, self.skt, self.node, self.circ_id)
		processcell.cmd_to_func[cell['CMD']]()
		return None
