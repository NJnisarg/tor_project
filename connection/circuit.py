from typing import List
from connection.node import Node
from connection.skt import Skt

class Circuit:

	def __init__(self, node_container: List[Node], skt: Skt):
		self.node_container = node_container
		self.skt = skt
		self.session_key01 = None
		self.session_key02 = None
		self.session_key03 = None

	def open_tcp_hop_1(self):
		self.skt.remote_connect(self.node_container[1].host, self.node_container[1].port)

	def create_circuit_hop_1(self):
		# Create a cell
		cell = ""

		# Carry out any processing on the cell

		# Send the create cell to the first hop
		# Wait for the ack of Created and then take action
		self.skt.send_data(cell)
		ack = self.skt.recv_data()

		# If the ack is created then we can return the status as true

		# If the ack failed, we can return as failed

		return None
