import json
import base64


class ComplexEncoder(json.JSONEncoder):
	"""
	The class used for recursively allowing JSON conversion
	"""
	def default(self, obj):
		if hasattr(obj, 'reprJSON'):
			return obj.reprJSON()
		else:
			return json.JSONEncoder.default(self, obj)


class Serialize:
	"""
	The class used to convert objects to JSON or Python Dict
	"""
	@staticmethod
	def obj_to_dict(obj):
		return json.loads(Serialize.obj_to_json(obj))

	@staticmethod
	def obj_to_json(obj):
		return json.dumps(obj.reprJSON(), cls=ComplexEncoder)


class Deserialize:
	"""
	The class used to convert JSON to Python Dict
	"""
	@staticmethod
	def json_to_dict(json_str):
		return json.loads(json_str)


class EncoderDecoder:
	"""
	1.) The class using for base64 encoding and decoding byte objects
	to and from strings
	2.) The methods bytes_to_utf8str and utf8str_to_bytes are used externally,
	other methods are used internally by those methods
	"""
	@staticmethod
	def bytes_to_b64bytes(b: bytes) -> bytes:
		return base64.b64encode(b)

	@staticmethod
	def b64bytes_to_utf8str(b64: bytes) -> str:
		return b64.decode('utf-8')

	@staticmethod
	def utf8str_to_b64bytes(s: str) -> bytes:
		return s.encode('utf-8')

	@staticmethod
	def b64bytes_to_bytes(b64: bytes) -> bytes:
		return base64.b64decode(b64)

	@staticmethod
	def bytes_to_utf8str(b: bytes) -> str:
		return EncoderDecoder.b64bytes_to_utf8str(EncoderDecoder.bytes_to_b64bytes(b))

	@staticmethod
	def utf8str_to_bytes(s: str) -> bytes:
		return EncoderDecoder.b64bytes_to_bytes(EncoderDecoder.utf8str_to_b64bytes(s))

