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

	def remote_connect(self, remote_host: str, remote_port: int):
		"""
		The method to connect to a remote socket
		:param remote_host: The remote host ip to connect to
		:param remote_port: The remote host port to connect to
		"""
		self.skt.connect((remote_host, remote_port))

	def send_data(self, data: str):
		"""
		The method to send data
		:param data: The data in string format to be sent
		"""
		self.skt.sendall(data)

	def recv_data(self) -> bytes:
		"""
		To receive all data at once
		:return: Returns all the bytes of data
		"""
		fragments = []
		while True:
			chunk = self.skt.recv(1024)
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
