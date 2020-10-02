import json
import re

class InterceptTarget:
	def __init__(self):
		self.dsthost = None
		self.dstport = None
		self.srchost = None
		self.srcport = None
		self.proto = None
		self.ssl = None

	def to_dict(self):
		return {
			'dsthost' : self.dsthost.pattern if self.dsthost is not None else None,
			'dstport' : self.dstport,
			'srchost' : self.srchost.pattern if self.srchost is not None else None,
			'srcport' : self.srcport,
			'proto' : self.proto,
			'ssl' : self.ssl,
		}

	@staticmethod
	def from_dict(d):
		it = InterceptTarget()
		it.dsthost = re.compile(d['dsthost']) if d.get('dsthost') is not None else None
		it.dstport = int(d['dstport']) if d.get('dstport') is not None else None
		it.srchost = re.compile(d['srchost']) if d.get('srchost') is not None else None
		it.srcport = int(d['srcport']) if d.get('srcport') is not None else None
		it.proto = d['proto']
		it.ssl = d['ssl']
		return it

	@staticmethod
	def from_json(jdata):
		return InterceptTarget.from_dict(json.loads(jdata))

	def to_json(self):
		return json.dumps(self.to_dict())

	def get_proto_for_monitor(self, monitor):
		if self.check_intercept(monitor) is True:
			return self.ssl, self.proto
		return None, None
	
	def check_intercept(self, monitor):
		if self.dsthost is not None:
			if self.dsthost.match(monitor.dst_ip) is None:
				return False

		if self.dstport is not None:
			if self.dstport != monitor.dst_port:
				return False

		if self.srchost is not None:
			if self.srchost.match(monitor.client_ip) is None:
				return False

		if self.srcport is not None:
			if self.srcport != monitor.client_port:
				return False

		return True