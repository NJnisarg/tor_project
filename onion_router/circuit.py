import select

from cell.serializers import Deserialize
from connection.node import Node
from connection.skt import Skt
import threading

from onion_router.process_cell import ProcessCell


class Circuit:

	def __init__(self, circ_id: int, node: Node, conn, session_key=None):
		"""
		The constructor for a single circuit on the router side
		:param circ_id: The ID of the circuit
		:param node: The node object from the router
		:param conn: The socket.conn from the previous hop
		:param session_key: The session key it shares with the proxy
		"""
		self.circ_id = circ_id
		self.node = node
		self.conn = conn
		self.skt = Skt(node.host, node.port + 27)  # Create a new socket object to talk to next hop
		self.session_key = session_key
		self.routing_table = {}  # May or may not be used.

	def main(self):
		"""
		The main function invoked when the thread for a circuit is created
		:return: Nothing
		"""

		sockets_list = [self.conn]
		while True:
			read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])
			for socket in read_sockets:
				# Get the cell from previous hop
				cell = str(socket.recv(65536).decode())
				if cell is None or cell == "":
					continue

				# Convert the cell to a dictionary
				cell_dict = Deserialize.json_to_dict(cell)
				if cell_dict:
					print(cell_dict)
					# start a thread to process the cell received
					proc_thread = threading.Thread(target=self.process_cell, args=(cell_dict, socket,))
					proc_thread.start()

	def process_cell(self, cell, socket):
		"""
		Function to process the cell received
		:param cell: The cell as dict
		:param socket: The socket object
		:return: None
		"""
		# self.conn -> with proxy
		# self.skt -> to next router
		processcell = ProcessCell(cell, self.conn, self.skt, socket, self.node, self.circ_id)
		flag = processcell.cmd_to_func[cell['CMD']]()
		if flag != 0:
			print("some error")
		return None
