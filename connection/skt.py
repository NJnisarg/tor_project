import socket


class Skt:
	"""
	This module is a simple wrapper around the socket library.
	It can be used anywhere in the entire project
	"""

	def __init__(self, own_host: str, own_port: int):
		"""
		The constructor for Skt
		:param own_host: The host ip for the socket itself
		:param own_port: The host port for the socket itself
		"""
		self.host = own_host
		self.port = own_port
		self.skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.skt.bind((self.host, self.port))
		self.conn = None
		self.remote_addr = None

	def client_connect(self, remote_host: str, remote_port: int) -> int:
		"""
		The method to connect to a remote socket
		:param remote_host: The remote host ip to connect to
		:param remote_port: The remote host port to connect to
		:return err_code: 0 if no error and -1 if there is an error
		"""
		try:
			self.skt.connect((remote_host, remote_port))
			return 0
		except Exception as e:
			return -1

	def server_accept(self) -> int:
		"""
		The method to accept connection from a remote socket
		:return err_code: 0 if no error and -1 if there is an error
		"""
		try:
			self.conn, self.remote_addr = self.skt.accept()
			return 0
		except Exception as e:
			return -1

	def server_listen(self) -> int:
		"""
		The method to listen for connection from a remote socket
		:return err_code: 0 if no error and -1 if there is an error
		"""
		try:
			self.skt.listen()
			return 0
		except Exception as e:
			return -1

	def client_send_data(self, data: str):
		"""
		The method to send data as client
		:param data: The data in string format to be sent
		"""
		self.skt.sendall(data)

	def client_recv_data(self) -> bytes:
		"""
		To receive all data at once as client
		:return: Returns all the bytes of data
		"""
		return self.skt.recv(65536)

	def server_send_data(self, data: str):
		"""
		The method to send data as server
		:param data: The data in string format to be sent
		"""
		self.conn.sendall(data)

	def server_recv_data(self) -> bytes:
		"""
		To receive all data at once as server
		:return: Returns all the bytes of data
		"""
		fragments = []
		while True:
			chunk = self.conn.recv(65536)
			if not chunk:
				break
			fragments.append(chunk)
		arr = b''.join(fragments)
		return arr

	def close(self):
		"""
		Function to safely close the socket object
		"""
		self.skt.close()
