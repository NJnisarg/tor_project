import struct


class ComplexStructEncoder:

	@staticmethod
	def encode(obj):
		fmt = obj.FORMAT_STR
		fmt_len = len(obj.FORMAT_STR_ARR)
		args = []
		for i in range(fmt_len):
			val = getattr(obj, obj.FORMAT_STR_ARR[i])
			if hasattr(val, 'reprJSON'):
				val = ComplexStructEncoder.encode(val)
			args.append(val)

		return struct.pack(fmt, *args)
