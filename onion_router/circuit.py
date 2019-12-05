from typing import List
from connection.node import Node
from connection.skt import Skt
from cell.cell import Cell, CellConstants


class Circuit:

	def get_rand_circ_id(self) -> int:
		return 1

	def __init__(self, node: Node, skt: Skt, sk):
		self.node = node
		self.skt = skt
		self.session_key = sk
