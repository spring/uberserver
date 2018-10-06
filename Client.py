import socket, time, sys, ip2country, errno

from collections import defaultdict
from BaseClient import BaseClient
from BridgedClient import BridgedClient

class Client(BaseClient):
	'this object represents one server-side connected client'

	def __init__(self, root, address, session_id):
		'initial setup for the connected client'
		self._root = root
		now = time.time()

		# detects if the connection is from this computer
		if address[0].startswith('127.'):
			if root.online_ip:
				address = (root.online_ip, address[1])
			elif root.local_ip:
				address = (root.local_ip, address[1])

		self.ip_address = address[0]
		self.local_ip = address[0]
		self.port = address[1]

		# fields also in user db
		self.user_id = -1 # db user object has a .id attr instead
		self.set_user_pwrd_salt("", ("", "")) # inits self.username, self.password self.randsalt 
		self.register_date = now	
		self.last_login = now
		self.last_ip = self.ip_address
		self.last_id = 0
		self.ingame_time = 0
		self.access = 'fresh'
		self.email = ''
		self.bot = 0
			
		# session
		self.session_id = session_id
		self.debug = False
		self.static = False
		self.sendError = False
	
		self.compat = defaultdict(lambda: False) # holds compatibility flags 

		self.country_code = '??'
		self.setFlagByIP(self.ip_address)
		self.status = 12
		self.accesslevels = ['fresh','everyone']

		# note: this NEVER becomes false after LOGIN!
		self.logged_in = False
		self.failed_logins = 0

		# server<->client comms
		self.buffersend = False # if True, write all sends to a buffer (must not be used when a client is logging in but didn't yet receive full server state!)
		self.buffer = ""
		self.msg_id = ''
		self.msg_sendbuffer = []
		self.sendingmessage = ''
		self.msg_length_history = {}

		# channels
		self.channels = set()
		self.ignored = {}
		self.lastsaid = {}

		# perhaps these are unused?
		self.cpu = 0
		self.data = '' 
		self.lastdata = now

		# time-stamps for encrypted data
		self.incoming_msg_ctr = 0
		self.outgoing_msg_ctr = 1

		# battle stuff
		self.is_ingame = False
		self.scriptPassword = None
		self.scriptPassword = None

		self.battle_bots = {}
		self.current_battle = None
		self.battle_bans = []
		self.went_ingame = 0
		self.spectator = False
		self.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
		self.teamcolor = '0'

		self.hostport = None
		self.udpport = 0
		
		self.floodlimit = { #fixme: this should be a property of the server, not the client!
			'fresh':{'msglength':1024*32, 'bytespersecond':1024*32, 'seconds':2},
			'user':{'msglength':1024*32, 'bytespersecond':1024*32, 'seconds':10},
			'bot':{'msglength':1024, 'bytespersecond':10000, 'seconds':5},
			'mod':{'msglength':10000, 'bytespersecond':10000, 'seconds':10},
			'admin':{'msglength':10000, 'bytespersecond':100000, 'seconds':10},
		}

		self.debug = False
		self.data = ''

		# holds compatibility flags - will be set by Protocol as necessary
		self.compat = defaultdict(lambda: False)
		self.scriptPassword = None

		self.email = ''

		now = time.time()
		self.last_login = now
		self.failed_logins = 0
		self.register_date = now
		self.lastdata = now
		self.last_id = 0
		self.buffersend = False # write all sends to a buffer (used when a client is logging in but didn't receive full server state)
		self.buffer = ""

		self.ignored = {}
		self.channels = set()
		
		self.bridged_clients = {}

	def set_msg_id(self, msg):
		self.msg_id = ""

		if (not msg.startswith('#')):
			return msg

		test = msg.split(' ')[0][1:]

		if (not test.isdigit()):
			return msg

		self.msg_id = '#%s ' % test
		return (' '.join(msg.split(' ')[1:]))

	def setFlagByIP(self, ip, force=True):
		cc = ip2country.lookup(ip)
		if force or cc != '??':
			self.country_code = cc

	##
	## handle data from client
	##
	def Handle(self, data):
		print("< " + data)
		if (self.access in self.floodlimit):
			msg_limits = self.floodlimit[self.access]
		else:
			msg_limits = self.floodlimit['user']

		now = int(time.time())
		self.lastdata = now # data received, store time to detect disconnects

		bytespersecond = msg_limits['bytespersecond']
		seconds = msg_limits['seconds']

		if (now in self.msg_length_history):
			self.msg_length_history[now] += len(data)
		else:
			self.msg_length_history[now] = len(data)

		total = 0

		for iter in dict(self.msg_length_history):
			if (iter < now - (seconds - 1)):
				del self.msg_length_history[iter]
			else:
				total += self.msg_length_history[iter]

		if total > (bytespersecond * seconds):
			if not self.access in ('admin', 'mod'):
				if (self.bot != 1):
					# FIXME: no flood limit for these atm, need to do server-side shaping/bandwith limiting
					self.Send('SERVERMSG No flooding (over %s per second for %s seconds)' % (bytespersecond, seconds))
					self.Remove('Kicked for flooding (%s)' % (self.access))
					return

		## keep appending until we see at least one newline
		self.data += data

		## if too much data has accumulated without a newline, clear
		if (len(self.data) > (msg_limits['msglength'] * 32)):
			del self.data; self.data = ""; return
		if (self.data.count('\n') == 0):
			return

		self.HandleProtocolCommands(self.data.split("\n"), msg_limits)

	def HandleProtocolCommand(self, cmd):
		## probably caused by trailing newline ("abc\n".split("\n") == ["abc", ""])
		if (len(cmd) < 1):
			return
		self._root.protocol._handle(self, cmd)

	def HandleProtocolCommands(self, split_data, msg_limits):
		assert(type(split_data) == list)
		assert(type(split_data[-1]) == str)

		msg_length_limit = msg_limits['msglength']
		check_msg_limits = (not ('disabled' in msg_limits))

		## either a list of commands, or a list of encrypted data
		## blobs which may contain embedded (post-decryption) NLs
		##
		## note: will be empty if len(split_data) == 1
		raw_data_blobs = split_data[: len(split_data) - 1]

		## will be a single newline in most cases, or an incomplete
		## command which should be saved for a later time when more
		## data is in buffer
		self.data = split_data[-1]

		commands_buffer = []

		def check_message_timestamp(msg):
			ctr = str_to_int32(msg)

			if (ctr <= self.incoming_msg_ctr):
				return False

			self.incoming_msg_ctr = ctr
			return True

		for raw_data_blob in raw_data_blobs:
			if (len(raw_data_blob) == 0):
				continue

			## strips leading spaces and trailing carriage returns
			strip_commands = [(raw_data_blob.rstrip('\r')).lstrip(' ')]

			commands_buffer += strip_commands

		for command in commands_buffer:
			if (check_msg_limits and (len(command) > msg_length_limit)):
				self.Send('SERVERMSG message-length limit (%d) exceeded: command \"%s...\" dropped.' % (msg_length_limit, command[0: 8]))
			else:
				self.HandleProtocolCommand(command)

	##
	## send data to client
	##
	def RealSend(self, data):
		## don't append new data to buffer when client gets removed
		if not data:
			return
		print("> " + data)
		self.transport.write(data.encode("utf-8") + b"\n")

	def Send(self, data):
		if self.msg_id:
			data = self.msg_id + data
		if self.buffersend:
			self.buffer += data + "\n"
		else:
			self.RealSend(data)

	def flushBuffer(self):
		self.transport.write(self.buffer.encode("utf-8"))
		self.buffer = ""
		self.buffersend = False

	def isAdmin(self):
		return ('admin' in self.accesslevels)

	def isMod(self):
		return self.isAdmin() or ('mod' in self.accesslevels) # maybe cache these

	def addBridgedClient(self, location, external_id, external_username):
		bridgedClient = BridgedClient(self, location, external_id, external_username)
		self.bridged_clients[bridgedClient.bridged_id] = bridgedClient
		
	def removeBridgedClient(self, bridgedClient):
		bridgedClient_channels = bridgedClient.channels.copy() # avoid modifying dict while iterating
		for channame in bridgedClient_channels:
			channel = self._root.channels[channame]
			channel.removeBridgedUser(self, bridgedClient)
		del self.bridged_clients[bridgedClient.bridged_id]
		