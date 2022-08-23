

import asyncio
import ipaddress
import uuid

class UniCredentialGen:
	def __init__(self):
		self.usernames = {}
		self.passwords = {}
		self.credentials = [] # fixed user,password pairs
		self.domain = None

	def add_credential(self, username, password):
		if password is None:
			password = ''
		self.credentials.append((username, password))

	def add_credential_tuple(self, t):
		username, password = t.split(':')
		self.add_credential(username, password)

	def add_credential_file(self, fname):
		with open(fname, 'r') as f:
			for line in f:
				line=line.strip()
				self.add_credential_tuple(line)
	
	def add_users_file(self, fname):
		with open(fname, 'r') as f:
			for line in f:
				line=line.strip()
				self.add_username(line)
	
	def add_passwords_file(self, fname):
		with open(fname, 'r') as f:
			for line in f:
				line=line.strip()
				self.add_password(line)

	def add_username(self, username):
		self.usernames[username] = 1
	
	def add_password(self, password):
		if password is None:
			password = ''
		self.passwords[password] = 1

	def get_total(self):
		return len(self.credentials) + (len(self.usernames) * len(self.passwords))

	async def run(self):
		for username in self.usernames:
			for password in self.passwords:
				yield(username, password)
		for username, password in self.credentials:
			yield(username, password)


class UniTargetGen:
	def __init__(self):
		self.targets = []
	
	@staticmethod
	def from_list(tl):
		targetgen = UniTargetGen()
		targetgen.add_list(tl)
		return targetgen
	
	def add_list(self, targetlist):
		for t in targetlist:
			try:
				self.add_ip(t)
			except:
				try:
					self.add_file(t)
				except:
					self.add_hostname(t)

	def add_ip(self, ip):
		uids = []
		try:
			ipaddress.ip_address(ip)
			uid = str(uuid.uuid4())
			uids.append(uid)
			self.targets.append((uid, ip))
		except:
			for t in ipaddress.ip_network(ip,strict=False):
				uid = str(uuid.uuid4())
				uids.append(uid)
				self.targets.append((uid, str(t)))
		return uids

	def add_file(self, fname):
		uids = []
		with open(fname, 'r') as f:
			for line in f:
				line=line.strip()
				try:
					uids += self.add_ip(line)
				except:
					uids += self.add_hostname(line)
		return uids
	
	def add_hostname(self, hosntame):
		uid = str(uuid.uuid4())
		self.targets.append((uid, str(hosntame)))
		return [uid]
	
	def get_total(self):
		return len(self.targets)

	async def run(self):
		for tid, target in self.targets:
			yield (tid, target)

class UniTargetPortGen:
	def __init__(self):
		self.targets = []
		self.ports = {}
	
	@staticmethod
	def from_list(tl):
		targetgen = UniTargetGen()
		targetgen.add_list(tl)
		return targetgen
	
	def add_port_list(self, portranges):
		def calc_range(x):
			if x.find('-') != -1:
				start,end = x.split('-')
				for i in range(int(start), int(end)):
					self.ports[int(i)] = None
			else:
				self.ports[int(x)] = None

		for prange in portranges:
			if prange.find(',') != -1:
				for port in prange.split(','):
					calc_range(port)
			else:
				calc_range(prange)

	
	def add_list(self, targetlist):
		for t in targetlist:
			try:
				self.add_ip(t)
			except:
				try:
					self.add_file(t)
				except:
					self.add_hostname(t)

	def add_ip(self, ip):
		uids = []
		try:
			ipaddress.ip_address(ip)
			uid = str(uuid.uuid4())
			uids.append(uid)
			self.targets.append((uid, ip))
		except:
			for t in ipaddress.ip_network(ip,strict=False):
				uid = str(uuid.uuid4())
				uids.append(uid)
				self.targets.append((uid, str(t)))
		return uids

	def add_file(self, fname):
		uids = []
		with open(fname, 'r') as f:
			for line in f:
				line=line.strip()
				try:
					uids += self.add_ip(line)
				except:
					uids += self.add_hostname(line)
		return uids
	
	def add_hostname(self, hosntame):
		uid = str(uuid.uuid4())
		self.targets.append((uid, str(hosntame)))
		return [uid]
	
	def get_total(self):
		return len(self.targets)*len(self.ports)

	async def run(self):
		for tid, target in self.targets:
			for port in self.ports:
				yield (tid, (target,port))