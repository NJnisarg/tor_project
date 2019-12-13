import json


class ComplexEncoder(json.JSONEncoder):
	def default(self, obj):
		if hasattr(obj, 'reprJSON'):
			return obj.reprJSON()
		else:
			return json.JSONEncoder.default(self, obj)


class Serialize:

	@staticmethod
	def obj_to_dict(obj):
		return json.loads(Serialize.obj_to_json(obj))

	@staticmethod
	def obj_to_json(obj):
		return json.loads(json.dumps(obj.reprJSON(), cls=ComplexEncoder))


class Deserialize:

	@staticmethod
	def json_to_dict(json_str):
		return json.loads(json_str)
