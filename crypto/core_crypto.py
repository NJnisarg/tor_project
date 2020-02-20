import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cell.control_cell import TapCHData
from cell.serializers import EncoderDecoder
from crypto.crypto_constants import CryptoConstants


class CoreCryptoRSA:
	"""
	This is the RSA core crypto module for the entire project. It behaves as a wrapper crypto primitives
	"""

	# Constants used in the Tor Spec for RSA
	RSA_FIXED_EXPONENT = 65537
	RSA_KEY_SIZE = 2048  # The Spec suggest 1024, but we violate it to avoid certain errors in hybrid_encrypt and hybrid_decrypt

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
	def load_public_key_from_disc(openssh_file: str) -> rsa.RSAPublicKey:
		"""
		Loads a pem file into a RSAPublicKey Object.
		:param openssh_file: The file containing the public RSA key
		:return: RSAPublicKey Object.
		"""

		try:
			with open(openssh_file, "rb") as key_file:
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

	@staticmethod
	def hybrid_encrypt(message: bytes, pk: rsa.RSAPublicKey) -> TapCHData:
		"""
		This method is the hybrid encrypt outlined in the Tor spec 0.4 section
		:param message: The message to be encrypted
		:param pk: The RSA public to encrypt the message with
		:return: The object TapCHData that has the client handshake data
		"""
		# First convert the message to a byte array so that we can slice it etc.
		message = bytearray(message)

		if len(message) <= CryptoConstants.PK_ENC_LEN - CryptoConstants.PK_PAD_LEN:
			# Then encrypt the message using the onion key
			p = pk.encrypt(message,
							padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

			# Create the TAP_H_DATA object
			padding_bytes = bytes(CryptoConstants.PK_PAD_LEN)
			tap_h_data = TapCHData(EncoderDecoder.bytes_to_utf8str(padding_bytes), None, EncoderDecoder.bytes_to_utf8str(p), None)

		else:
			k = bytearray(os.urandom(CryptoConstants.KEY_LEN))
			m1 = message[0:CryptoConstants.PK_ENC_LEN - CryptoConstants.PK_PAD_LEN - CryptoConstants.KEY_LEN]
			m2 = message[CryptoConstants.PK_ENC_LEN - CryptoConstants.PK_PAD_LEN - CryptoConstants.KEY_LEN:]
			p1 = pk.encrypt(bytes(k + m1),
							padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

			nonce = bytes(CryptoConstants.KEY_LEN)  # all bytes are 0, nonce is the IV
			cipher = Cipher(algorithms.AES(k), modes.CTR(nonce), backend=default_backend())
			encryptor = cipher.encryptor()
			p2 = encryptor.update(m2) + encryptor.finalize()

			tap_h_data = TapCHData(EncoderDecoder.bytes_to_utf8str(nonce), EncoderDecoder.bytes_to_utf8str(k), EncoderDecoder.bytes_to_utf8str(p1), EncoderDecoder.bytes_to_utf8str(p2))

		return tap_h_data

	@staticmethod
	def hybrid_decrypt(h_data, pk: rsa.RSAPrivateKey) -> bytes:
		"""
		This method is the hybrid decrypt outlined in the Tor spec 0.4 section
		:param h_data: The handshake data object of type TapCHData
		:param pk: The RSA private key to decrypt the message with
		:return: The decrypted message in bytes
		"""

		if h_data.SYMKEY is None:
			return_message = "hi"  # pk.decrypt(x["GX1"], padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
			#                          algorithm=hashes.SHA256(), label=None))
		else:
			# Get the params of in bytes form
			gx1 = EncoderDecoder.utf8str_to_bytes(h_data.GX1)
			gx2 = EncoderDecoder.utf8str_to_bytes(h_data.GX2)
			sym_key = EncoderDecoder.utf8str_to_bytes(h_data.SYMKEY)
			padding_bytes = EncoderDecoder.utf8str_to_bytes(h_data.PADDING)

			# Decryption begins
			km1 = pk.decrypt(gx1,
							padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
							label=None))
			m1 = km1[len(sym_key):]

			cipher = Cipher(algorithms.AES(sym_key), modes.CTR(padding_bytes), backend=default_backend())
			decryptor = cipher.decryptor()
			m2 = decryptor.update(gx2) + decryptor.finalize()

			# Return the concatenated message
			return_message = m1 + m2
		return return_message

	@staticmethod
	def kdf_tor(message: bytes) -> dict:
		"""
		This method is the key derivative outlined in the Tor spec section 5.2.1
		:param message: The message to be used to carry out KDF
		:return: The kdf dict
		"""

		hkdf = HKDF(
			algorithm=hashes.SHA256(),
			length=CryptoConstants.KEY_LEN * 2 + CryptoConstants.HASH_LEN * 3,
			salt=None,
			info=None,
			backend=default_backend()
		)

		key = hkdf.derive(message)

		kdf_tor_dict = {
			'KH': str(key[:CryptoConstants.HASH_LEN]),
			'Df': str(key[CryptoConstants.HASH_LEN:(2 * CryptoConstants.HASH_LEN)]),
			'Db': str(key[(2 * CryptoConstants.HASH_LEN):(3 * CryptoConstants.HASH_LEN)]),
			'Kf': str(key[(3 * CryptoConstants.HASH_LEN):((3 * CryptoConstants.HASH_LEN) + CryptoConstants.KEY_LEN)]),
			'Kb': str(key[((3 * CryptoConstants.HASH_LEN) + CryptoConstants.KEY_LEN):(
						(3 * CryptoConstants.HASH_LEN) + (2 * CryptoConstants.KEY_LEN))])
		}

		# As of now, the function returns a dictionary due to certain problems with
		# converting byte object to python strings. This needs to be fixed in the future

		return kdf_tor_dict


class CoreCryptoDH:
	# Setting the generator according to the spec
	DH_GENERATOR = 2
	g = DH_GENERATOR

	# Setting the prime p modulo. Taken from spec
	p = int(
		"0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A4"
		"31B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B"
		"1FE649286651ECE65381FFFFFFFFFFFFFFFF",
		16)

	# Setting the key size according to spec
	KEY_SIZE = CryptoConstants.DH_SEC_LEN * 8

	# Creating the params object
	parameter_numbers = dh.DHParameterNumbers(p, g)
	dh_parameters = parameter_numbers.parameters(default_backend())

	@staticmethod
	def generate_dh_priv_key() -> (dh.DHPrivateKey, bytes, dh.DHPublicKey, bytes):
		"""
		Generates a private and public key pair for DH based on the DH Params defined
		above according to the spec
		:return: A 4-tuple <private_key, private_key_bytes, public_key, public_key_bytes>
		"""
		# Generate the private key ==> x
		x = CoreCryptoDH.dh_parameters.generate_private_key()
		x_bytes = x.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
								encryption_algorithm=serialization.NoEncryption())

		# Also create the public key ==> gx
		gx = x.public_key()
		gx_bytes = gx.public_bytes(encoding=serialization.Encoding.PEM,
									format=serialization.PublicFormat.SubjectPublicKeyInfo)

		return x, x_bytes, gx, gx_bytes

	@staticmethod
	def compute_dh_shared_key(gy_bytes: bytes, x_bytes: bytes) -> bytes:
		"""
		Compute the shared Diffie hellman key
		:param gy_bytes: The bytes representation of public key of the other node
		:param x_bytes: The bytes representation of the private key of node itself
		:return: Returns shared_key as bytes
		"""
		gy = serialization.load_pem_public_key(gy_bytes, backend=default_backend())
		x = serialization.load_pem_private_key(x_bytes, backend=default_backend(), password=None)
		shared_key = x.exchange(gy)

		return shared_key


class CoreCryptoMisc:

	@staticmethod
	def calculate_digest(message_dict):
		digest_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
		for data in message_dict.values():
			str_data = str(data)
			digest_obj.update(str_data.encode())
		digest = digest_obj.finalize()
		return digest
