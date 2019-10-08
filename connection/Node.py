from cryptography.hazmat.primitives.asymmetric import rsa


class Node:
	"""
	The class representing one node in the circuit.
	The node object holds the information for each node. It includes the host, port and the keys for that node
	"""
	def __init__(self, host: str, port: int, identity_key_pri: rsa.RSAPrivateKey, identity_key_pub: rsa.RSAPublicKey, onion_key_pri: rsa.RSAPrivateKey, onion_key_pub: rsa.RSAPublicKey):
		"""

		:param host: The host ip of the node
		:param port: The host port of the node
		:param identity_key_pri: The private key of the identity key pair
		:param identity_key_pub: The public key of the identity key pair
		:param onion_key_pri: The private key of the onion key pair
		:param onion_key_pub: The public key of the onion key pair
		"""
		self.host = host
		self.port = port
		self.identity_key_pri = identity_key_pri
		self.identity_key_pub = identity_key_pub
		self.onion_key_pri = onion_key_pri
		self.onion_key_pub = onion_key_pub
