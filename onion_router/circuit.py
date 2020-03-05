import selectors
from ipaddress import IPv4Address
from http.client import HTTPConnection

from cell.cell import Cell
from cell.cell_processing import Builder, Parser, Processor
from cell.relay_cell import RelayCellPayload
from cell.serializers import ComplexStructEncoder
from connection.node import Node
from connection.skt import Skt
from crypto.core_crypto import CoreCryptoDH

from struct import pack, unpack


class Circuit:

	def __init__(self, circ_id: int, node: Node, conn, session_key=None, is_last_node=True):
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
		self.is_last_node = is_last_node
		self.stream_ids = []
		self.stream_skts = {}
		self.sktSelector = selectors.DefaultSelector()  # The sktSelector object to select the Socket for IO

		self.sktSelector.register(self.conn, selectors.EVENT_READ, 0)  # Register the conn socket with invocation on READ == RECV event

		self.cmd_to_func = {
			Cell.CMD_ENUM['CREATE']: self.handle_create_cell,
			Cell.CMD_ENUM['CREATE2']: self.handle_create_cell,
			Cell.CMD_ENUM['CREATED']: self.handle_created_cell,
			Cell.CMD_ENUM['CREATED2']: self.handle_created_cell,
			Cell.CMD_ENUM['RELAY']: self.handle_relay_cell,
		}  # A lookup for the function to be called based on the cell

		self.relaycmd_to_func = {
			RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTEND']: self.handle_relay_extend_cell,
			RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTEND2']: self.handle_relay_extend_cell,
			RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTENDED']: self.handle_relay_extended_cell,
			RelayCellPayload.RELAY_CMD_ENUM['RELAY_EXTENDED2']: self.handle_relay_extended_cell,
			RelayCellPayload.RELAY_CMD_ENUM['RELAY_BEGIN']: self.handle_relay_begin_cell,
			RelayCellPayload.RELAY_CMD_ENUM['RELAY_CONNECTED']: self.handle_relay_connected_cell,
			RelayCellPayload.RELAY_CMD_ENUM['RELAY_DATA']: self.handle_relay_data_cell
		}  # A lookup for the function to be called based on the relay cell

	def main(self):
		"""
		The main function invoked when the thread for a circuit is created
		:return: Nothing
		"""
		while True:
			events = self.sktSelector.select()
			for key, mask in events:
				self.process_cell(key.fileobj, mask, key.data)

	def process_cell(self, sock, mask, direction):

		# The cell is incoming from previous hop
		cell_bytes = None
		if direction == 0:
			cell_bytes = self.conn.recv(65536)

		elif direction == 1:
			cell_bytes = self.skt.client_recv_data()

		if cell_bytes is not None and cell_bytes != "":

			cell_tuple = Parser.parse_basic_cell(cell_bytes)
			self.cmd_to_func[cell_tuple[1]](cell_bytes, direction)

		else:
			return

	def handle_create_cell(self, cell_bytes, direction):
			# Call the Parser for create cell
			create_cell = Parser.parse_encoded_create_cell(cell_bytes)

			# Process the create cell
			y, y_bytes, gy, gy_bytes = CoreCryptoDH.generate_dh_priv_key()
			gx_bytes, kdf_dict = Processor.process_create_cell(create_cell, self.node.onion_key_pri, y_bytes)

			# After processing the create cell, we make a created cell
			# and send it down the socket
			created_cell = Builder.build_created_cell(y_bytes, gy_bytes, self.circ_id, gx_bytes)
			print(created_cell)
			self.conn.sendall(ComplexStructEncoder.encode(created_cell))
			print("Created cell sent")

			self.session_key = kdf_dict
			return 0

	def handle_created_cell(self, cell_bytes, direction):
		created_cell = Parser.parse_encoded_created_cell(cell_bytes)

		# process created cell
		hlen, hdata = Processor.process_created_cell_for_extended(created_cell)

		# Create extended cell
		extended_cell = Builder.build_extended_cell_from_created_cell(self.circ_id, hlen, hdata)

		# send extended to conn
		self.conn.sendall(ComplexStructEncoder.encode(extended_cell))
		self.is_last_node = False
		print("Extended cell sent")

	def handle_relay_cell(self, cell_bytes, direction):
			relay_cell_payload_tuple = Parser.parse_encoded_relay_cell(cell_bytes)
			return self.relaycmd_to_func[relay_cell_payload_tuple[0]](cell_bytes, direction)

	def handle_relay_extend_cell(self, cell_bytes, direction):
		if self.is_last_node:
			extend_cell = Parser.parse_encoded_extend_cell(cell_bytes)
			addr, port, htype, hlen, hdata = Processor.process_extend_cell(extend_cell, self.node.onion_key_pri)

			# Connect with next node
			print(addr, port)
			err_code = self.skt.client_connect(addr, port)
			print(err_code)

			# Successfully connected, register it to the selectors list
			if err_code == 0:
				self.sktSelector.register(self.skt.skt, selectors.EVENT_READ, 1)

			# Create a CREATE2 Cell.
			create_cell = Builder.build_create_cell_from_extend(self.circ_id, htype, hlen, hdata)

			# Sending a JSON String down the socket
			self.skt.client_send_data(ComplexStructEncoder.encode(create_cell))

			return 1
		else:
			# Forwarding the cell down the stream
			self.skt.client_send_data(cell_bytes)

			return 2

	def handle_relay_extended_cell(self, cell_bytes, direction):
		self.conn.sendall(cell_bytes)

		return 2

	def handle_relay_begin_cell(self,cell_bytes, direction):
		begin_cell = Parser.parse_encoded_begin_cell(cell_bytes)
		recognized, begin_cell = Processor.process_begin_cell(begin_cell, self.session_key)

		if recognized == 0:
			print("Recognized the begin cell!")

			# Getting the IP and port
			addrport = bytearray(begin_cell.PAYLOAD.Data.ADDRPORT)
			ip_addr, port = unpack('!IH', addrport)
			ip_addr = str(IPv4Address(ip_addr))

			# Appending the stream ID to this circuit
			stream_id = begin_cell.PAYLOAD.StreamID
			self.stream_ids.append(stream_id)

			# Creating the socket and connecting it to end host! Fuck yeah
			conn = self.stream_skts[stream_id] = HTTPConnection(ip_addr, port)
			conn.request("GET", "/")
			res = conn.getresponse()
			print(res.status, res.reason)
			if res:
				# The last parameter for build_relay_connected_cell is supposed to be TTL in secs
				connected_cell = Builder.build_relay_connected_cell(self.circ_id, stream_id, self.session_key, ip_addr, 360)
				self.conn.sendall(ComplexStructEncoder.encode(connected_cell))

		else:
			print("Begin cell not for us. Lets pass it on!")
			self.skt.client_send_data(ComplexStructEncoder.encode(begin_cell))

	def handle_relay_connected_cell(self, cell_bytes, direction):
		"""
		Function for handling the connected cell when it is received by a router
		:param cell_bytes: The struct received by the router for the connected cell
		"""
		parsed_connected_cell = Parser.parse_encoded_connected_cell(cell_bytes)
		processed_connected_cell = Processor.process_connected_cell_router(parsed_connected_cell, self.session_key)
		self.conn.sendall(ComplexStructEncoder.encode(processed_connected_cell))
		return

	def handle_relay_data_cell(self, cell_bytes, direction):
		"""
		Function for handling the data cell when received by a router
		:param cell_bytes: The struct received by the router for the data cell
		:param direction:
		:return:
		"""
		parsed_relay_data_cell = Parser.parse_encoded_relay_data_cell(cell_bytes)
		recognized, http_request_payload, relay_data_cell = Processor.process_relay_data_cell(parsed_relay_data_cell, self.session_key)
		if recognized == 0 and direction == 0:
			stream_id = relay_data_cell.PAYLOAD.StreamID
			conn = self.stream_skts[stream_id]
			conn.request(http_request_payload['method'], http_request_payload['url'])
			res = conn.getresponse()
			print(res.status, res.reason)
			return
		elif recognized != 0 and direction == 0:
			print("Not for me! Pass it on")
			self.skt.client_send_data(ComplexStructEncoder.encode(relay_data_cell))
			return
		else:
			print("shouldn't reach here at this stage")
			return
