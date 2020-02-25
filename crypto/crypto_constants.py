class CryptoConstants:
	"""
	The class with all the crypto constants from the Spec
	"""
	KEY_LEN = 16  # The length of the stream cipher's key, in bytes
	DH_LEN = 350  # The number of bytes used to represent a member of Diffie Hellman group. 128 is default but we use 350 here because for 128 DH_SEC_LEN, this is the required DH_LEN
	DH_SEC_LEN = 128  # The number of bytes used in a Diffie-Hellman private key (x). The spec suggests 40 bytes but
	# the crypto library we use requires min 64 bytes = 512 bits and default 128 bytes = 1024 bits
	PK_ENC_LEN = 128  # The length of a public-key encrypted message, in bytes.
	PK_PAD_LEN = 42  # The number of bytes added in padding for public-key
	# encryption, in bytes. (The largest number of bytes that can be encrypted
	# in a single public-key operation is therefore PK_ENC_LEN-PK_PAD_LEN.)
	HASH_LEN = 20  # The length of the hash function's output, in bytes
