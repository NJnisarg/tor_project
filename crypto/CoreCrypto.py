from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CoreCryptoRSA:
	"""
	This is the RSA core crypto module for the entire project. It behaves as a wrapper crypto primitives
	"""

	# Constants used in the Tor Spec for RSA
	RSA_FIXED_EXPONENT = 65537
	RSA_KEY_SIZE = 1024

	@staticmethod
	def generate_rsa_key_pair() -> (rsa.RSAPrivateKey, rsa.RSAPublicKey):
		"""
		The function generates a new RSA key pair to be used
		:returns a 2-tuple of type -> (rsa.RSAPrivateKey, rsa.RSAPublicKey)
		"""

		private_key = rsa.generate_private_key(
			public_exponent=CoreCryptoRSA.RSA_FIXED_EXPONENT,
			key_size=CoreCryptoRSA.RSA_KEY_SIZE,
			backend=default_backend()
		)
		public_key = private_key.public_key()

		return private_key, public_key

	@staticmethod
	def load_private_key_from_disc(pem_file: str, password_for_encryption=None) -> rsa.RSAPrivateKey:

		"""
		Loads a pem file into a RSAPrivateKey Object.
		:param password_for_encryption: The password that might have been used for encrypting the pem file itself
		:param pem_file: The file containing the private RSA key
		:return: RSAPrivateKey object
		"""
		try:
			with open(pem_file, "rb") as key_file:
				private_key = serialization.load_pem_private_key(
					key_file.read(),
					password=password_for_encryption,
					backend=default_backend()
				)
				return private_key
		except:
			print("Error reading the pem file.")
			return None

	@staticmethod
	def load_public_key_from_disc(pem_file: str) -> rsa.RSAPublicKey:
		"""
		Loads a pem file into a RSAPublicKey Object.
		:param pem_file: The file containing the public RSA key
		:return: RSAPublicKey Object.
		"""

		try:
			with open(pem_file, "rb") as key_file:
				public_key = serialization.load_ssh_public_key(
					key_file.read(),
					backend=default_backend()
				)
				return public_key
		except:
			print("Error reading the pem file.")
			return None

	@staticmethod
	def load_key_pair_from_disc(pem_file: str, password_for_pem_file=None) -> (rsa.RSAPrivateKey, rsa.RSAPublicKey):
		"""
		This function simply takes the private key pem file and gives you back the entire key pair
		:param pem_file: The file containing the private RSA key
		:param password_for_pem_file: The password that might have been used for encrypting the pem file itself
		:return: a 2-tuple of type -> (rsa.RSAPrivateKey, rsa.RSAPublicKey)
		"""

		private_key = CoreCryptoRSA.load_private_key_from_disc(pem_file, password_for_pem_file)
		public_key = private_key.public_key()

		return private_key, public_key
