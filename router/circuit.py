from connection.node import Node
from connection.skt import Skt
import threading


class Circuit:

	def __init__(self, circ_id: int, node: Node, conn, session_key=None):
		self.circ_id = circ_id
		self.node = node
		self.conn = conn
		self.skt = Skt(node.host, 12345)
		self.session_key = session_key
		self.routing_table = {}

	def main(self):
		while True:
			try:
				cell = self.conn.recv(1024)
				if cell:
					threading.Thread(target=self.process_cell(), args=(), daemon=True)
			except:
				print("Error")

	def process_cell(self):
		return None
