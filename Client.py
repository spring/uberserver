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
		self.bot = False

		# session
		self.session_id = session_id
		self.debug = False
		self.static = False
		self.sendError = False

		self.compat = set() # holds compatibility flags

		self.country_code = '??'
		self.lobby_id = ""
		self.setFlagByIP(self.ip_address)
		self.status = 12
		self.accesslevels = ['fresh','everyone']

		# note: this NEVER becomes false after LOGIN!
		self.logged_in = False

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
		
		# for if we are a bridge bot
		self.bridge = {} #location->{external_id->bridged_id}
		
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

		self.battle_bots = {}
		self.current_battle = None # battle_id
		self.went_ingame = 0
		self.spectator = False
		self.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
		self.teamcolor = '0'

		self.hostport = None
		self.udpport = 0

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
		if (self.access in self._root.flood_limits):
			flood_limits = self._root.flood_limits[self.access]
		else:
			flood_limits = self._root.flood_limits['fresh']
		#print("< [" + self.username +"] " + data) # uncomment for debugging

		now = int(time.time())
		self.lastdata = now # data received, store time to detect disconnects

		bytespersecond = flood_limits['bytespersecond']
		seconds = flood_limits['seconds']

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
			self.Send('SERVERMSG No flooding (over %s per second for %s seconds)' % (bytespersecond, seconds))
			self.ReportFloodBreach("flood limit", total)
			self.Remove('Kicked for flooding (%s)' % (self.access))
			return

		# keep appending until we see at least one newline
		self.data += data

		# if far too much data has accumulated without hitting flood limits and without a newline, just clear it
		if (self.data.count('\n') == 0):
			if (len(self.data) > (flood_limits['msglength'])*16):
				del self.data
				self.data = ""
				self.Send('SERVERMSG Max client data cache was exceeded, some of your data was dropped by the server')
				self.ReportFloodBreach("max client data cache ", len(self.data))
			return

		self.HandleProtocolCommands(self.data.split("\n"), flood_limits)

	def HandleProtocolCommand(self, cmd):
		# probably caused by trailing newline ("abc\n".split("\n") == ["abc", ""])
		if (len(cmd) < 1):
			return
		self._root.protocol._handle(self, cmd)

	def HandleProtocolCommands(self, split_data, flood_limits):
		assert(type(split_data) == list)
		assert(type(split_data[-1]) == str)

		# either a list of commands, or a list of encrypted data
		# blobs which may contain embedded (post-decryption) NLs
		# note: will be empty if len(split_data) == 1
		raw_data_blobs = split_data[: len(split_data) - 1]

		# will be a single newline in most cases, or an incomplete
		# command which should be saved for a later time when more
		# data is in buffer
		self.data = split_data[-1]

		commands_buffer = []

		for raw_data_blob in raw_data_blobs:
			if (len(raw_data_blob) == 0):
				continue

			strip_commands = [(raw_data_blob.rstrip('\r')).lstrip(' ')]
			commands_buffer += strip_commands

		for command in commands_buffer:
			if len(command) > flood_limits['msglength']:
				self.Send('SERVERMSG message length limit of %i chars was exceeded: command \"%s...\" dropped.' % (msg_length_limit, command[0: 16]))
				self.ReportFloodBreach("max message length (cmd=\%s...\)" % command[0: 16], len(command))
				continue
			self.HandleProtocolCommand(command)

	def ReportFloodBreach(self, type, bytes):
		if hasattr(self, "username"):
			user_details = "<%s>, session_id: %i" % (self.uisername, self.session_id)
		else:
			user_details = "session_id: %i" % self.session_id
		err_msg = "%s for '%s' breached by %s, had %i bytes" % (type, self.access, user_details, bytes)
		self._root.protocol.broadcast_Moderator(err_msg)
		logging.info(err_msg)

	##
	## send data to client
	##
	def RealSend(self, data):
		## don't append new data to buffer when client gets removed
		if not data:
			return
		#print("> [" + self.username +"] " + data) # uncomment for debugging
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
		
	def isHosting(self):
		return self.current_battle and self._root.battles[self.current_battle].host == self.session_id
		