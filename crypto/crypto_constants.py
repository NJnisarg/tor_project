class CryptoConstants:
	KEY_LEN = 16  # The length of the stream cipher's key, in bytes
	DH_LEN = 128  # The number of bytes used to represent a member of Diffie Hellman group
	DH_SEC_LEN = 40  # The number of bytes used in a Diffie-Hellman private key (x)
	PK_ENC_LEN = 128  # The length of a public-key encrypted message, in bytes.
	PK_PAD_LEN = 42  # The number of bytes added in padding for public-key
	# encryption, in bytes. (The largest number of bytes that can be encrypted
	# in a single public-key operation is therefore PK_ENC_LEN-PK_PAD_LEN.)
	HASH_LEN = 20  # The length of the hash function's output, in bytes