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
			read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])
			for socket in read_sockets:
				cell = str(socket.recv(1024).decode())
				if cell is None or cell == "":
					continue
				cell_dict = Deserialize.json_to_dict(cell)
				if cell_dict:
					print(cell_dict)
					proc_thread = threading.Thread(target=self.process_cell, args=(cell_dict, socket,))
					proc_thread.start()
			# except:
			#     print("Error")

	def process_cell(self, cell, socket):
		"""
		:param cell:
		:param socket:
		:return:
		"""
		# self.conn -> with proxy
		# self.skt -> to next router
		processcell = ProcessCell(cell, self.conn, self.skt, socket, self.node, self.circ_id)
		flag = processcell.cmd_to_func[cell['CMD']]()
		if flag != 0:
			print("some error")
		return None
