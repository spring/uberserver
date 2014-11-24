import socket, time, sys, thread, ip2country, errno
from collections import defaultdict

from BaseClient import BaseClient
from CryptoHandler import aes_cipher
from CryptoHandler import safe_base64_decode as SAFE_DECODE_FUNC
from CryptoHandler import DATA_MARKER_BYTE
from CryptoHandler import DATA_PARTIT_BYTE
from CryptoHandler import UNICODE_ENCODING

class Client(BaseClient):
	'this object represents one server-side connected client'

	def __init__(self, root, connection, address, session_id):
		'initial setup for the connected client'
		self._root = root
		self.conn = connection

		# detects if the connection is from this computer
		if address[0].startswith('127.'):
			if root.online_ip:
				address = (root.online_ip, address[1])
			elif root.local_ip:
				address = (root.local_ip, address[1])
		
		self.ip_address = address[0]
		self.local_ip = address[0]
		self.port = address[1]
		
		self.setFlagByIP(self.ip_address)
		
		self.session_id = session_id
		self.db_id = session_id
		
		self.handler = None
		self.static = False
		self._protocol = None
		self.removing = False
		self.sendError = False
		self.msg_id = ''
		self.msg_sendbuffer = []
		self.enc_sendbuffer = []
		self.sendingmessage = ''

		## note: this NEVER becomes false after LOGIN!
		self.logged_in = False

		self.status = '12'
		self.is_ingame = False
		self.cpu = 0
		self.access = 'fresh'
		self.accesslevels = ['fresh','everyone']
		self.channels = []
		
		self.battle_bots = {}
		self.current_battle = None
		self.battle_bans = []
		self.ingame_time = 0
		self.went_ingame = 0
		self.spectator = False
		self.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
		self.teamcolor = '0'

		## copies of the DB User values, set on successful LOGIN
		self.set_user_pwrd_salt("", ("", ""))

		self.email = ''
		self.hostport = None
		self.udpport = 0
		self.bot = 0
		self.floodlimit = {
			'fresh':{'msglength':1024*32, 'bytespersecond':1024*32, 'seconds':2},
			'user':{'msglength':1024*32, 'bytespersecond':1024*32, 'seconds':10},
			'bot':{'msglength':1024, 'bytespersecond':10000, 'seconds':5},
			'mod':{'msglength':10000, 'bytespersecond':10000, 'seconds':10},
			'admin':{'msglength':10000, 'bytespersecond':100000, 'seconds':10},
		}
		self.msglengthhistory = {}
		self.lastsaid = {}
		self.current_channel = ''
		
		self.tokenized = False
		self.hashpw = False
		self.debug = False
		self.data = ''

		# holds compatibility flags - will be set by Protocol as necessary
		self.compat = defaultdict(lambda: False)
		self.scriptPassword = None
		
		now = time.time()
		self.last_login = now
		self.failed_logins = 0
		self.register_date = now
		self.lastdata = now
		self.last_id = 0
		
		self.users = set([]) # session_id
		self.battles = set([]) # [battle_id] = [user1, user2, user3, etc]

		self.ignored = {}
		
		self._root.console_write('Client connected from %s:%s, session ID %s.' % (self.ip_address, self.port, session_id))

		## start with the NULL-key
		self.set_aes_cipher_obj(aes_cipher(""))
		self.set_session_key("")

		self.set_session_key_received_ack(False)



	## AES cipher used for encrypted protocol communication
	## (obviously with a different instance and key for each
	## connected client)
	def set_aes_cipher_obj(self, obj): self.aes_cipher_obj = obj
	def get_aes_cipher_obj(self): return self.aes_cipher_obj

	def set_session_key_received_ack(self, b): self.session_key_received_ack = b
	def get_session_key_received_ack(self): return self.session_key_received_ack

	def set_session_key(self, key): self.aes_cipher_obj.set_key(key)
	def get_session_key(self): return (self.aes_cipher_obj.get_key())

	## NOTE:
	##   only for in-memory clients, not DB User instances
	##   when true, aes_cipher_obj always contains a valid
	##   key
	def use_secure_session(self):
		return (len(self.get_session_key()) != 0)


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

	def Bind(self, handler=None, protocol=None):
		if handler:	self.handler = handler
		if protocol:
			if not self._protocol:
				protocol._new(self)
			self._protocol = protocol


	##
	## handle data from client
	##
	def Handle(self, data):
		if (self.access in self.floodlimit):
			msg_limits = self.floodlimit[self.access]
		else:
			msg_limits = self.floodlimit['user']

		now = int(time.time())
		self.lastdata = now # data received, store time to detect disconnects

		bytespersecond = msg_limits['bytespersecond']
		seconds = msg_limits['seconds']

		if (now in self.msglengthhistory):
			self.msglengthhistory[now] += len(data)
		else:
			self.msglengthhistory[now] = len(data)

		total = 0

		for iter in dict(self.msglengthhistory):
			if (iter < now - (seconds - 1)):
				del self.msglengthhistory[iter]
			else:
				total += self.msglengthhistory[iter]

		if total > (bytespersecond * seconds):
			if not self.access in ('admin', 'mod'):
				if (self.bot != 1):
					# FIXME: no flood limit for these atm, need to rewrite flood limit to server-side shaping/bandwith limiting
					self.Send('SERVERMSG No flooding (over %s per second for %s seconds)' % (bytespersecond, seconds))
					self.Remove('Kicked for flooding (%s)' % (self.access))
					return

		## keep appending until we see at least one newline
		self.data += data

		if (self.data.count('\n') == 0):
			return

		self.HandleProtocolCommands(self.data.split(DATA_PARTIT_BYTE), msg_limits)


	def HandleProtocolCommands(self, split_data, msg_limits):
		assert(type(split_data) == list)

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

		assert(type(self.data) == str)

		commands_buffer = []

		for raw_data_blob in raw_data_blobs:
			is_encrypted_blob = (raw_data_blob[0] == DATA_MARKER_BYTE)

			if (is_encrypted_blob):
				assert(self.use_secure_session())

				## handle an encrypted client command, using the AES session key
				## previously exchanged between client and server by SETSHAREDKEY
				## (this includes LOGIN and REGISTER, key can be set before login)
				##
				## this assumes (!) a client message to be of the form
				##   ENCODE(ENCRYPT_AES("CMD ARG1 ARG2 ...", AES_KEY))
				## where ENCODE is the standard base64 encoding scheme
				##
				## if this is not the case (e.g. if a command was sent UNENCRYPTED
				## by client after session-key exchange) the decryption will yield
				## garbage and command will be rejected (or maybe crash the server)
				##
				## NOTE:
				##   blocks of encrypted data are always base64-encoded and will be
				##   separated by newlines, but after decryption might contain more
				##   embedded newlines themselves (e.g. if encryption was performed
				##   over *batches* of plaintext commands)
				##
				##   client -->   C=ENCODE(ENCRYPT("CMD1 ARG11 ARG12 ...\nCMD2 ARG21 ...\n"))
				##   server --> DECRYPT(DECODE(C))="CMD1 ARG11 ARG12 ...\nCMD2 ARG21 ...\n"
				##
				## make sure decryption deals with a standard string
				## (there should not be any encoding on top of base64
				## blobs in the first place since the b64 alphabet is
				## ASCII)
				enc_data_blob = raw_data_blob[1: ]
				dec_data_blob = self.aes_cipher_obj.decode_decrypt_bytes_utf8(enc_data_blob, SAFE_DECODE_FUNC)

				split_commands = dec_data_blob.split(DATA_PARTIT_BYTE)
				strip_commands = [(cmd.rstrip('\r')).lstrip(' ') for cmd in split_commands]
			else:
				## strips leading spaces and trailing carriage returns
				strip_commands = [(raw_data_blob.rstrip('\r')).lstrip(' ')]

			commands_buffer += strip_commands

		for command in commands_buffer:
			if (check_msg_limits and (len(command) > msg_length_limit)):
				self.Send('SERVERMSG message-length limit (%d) exceeded: command \"%s...\" dropped.' % (msg_length_limit, command[0: 8]))
			else:
				self.HandleProtocolCommand(command)

	def HandleProtocolCommand(self, cmd):
		## probably caused by trailing newline ("abc\n".split("\n") == ["abc", ""])
		if (len(cmd) <= 1):
			return

		self._protocol._handle(self, cmd)


	def Remove(self, reason='Quit'):
		while self.msg_sendbuffer:
			self.FlushBuffer()
		self.handler.finishRemove(self, reason)

	##
	## send data to client
	##
	def Send(self, msg, binary = False):
		## don't append new data to buffer when client gets removed
		if ((not msg) or self.removing):
			return

		if (self.handler.thread == thread.get_ident()):
			msg = self.msg_id + msg


		if (self.use_secure_session()):
			## apply server-to-client encryption
			##
			## add marker byte so client does not have to guess
			## if data is of the form ENCODE(ENCRYPTED(...)) or
			## in plaintext, as well as the current session key
			## identifier byte
			##
			hdr = DATA_MARKER_BYTE
			pay = self.aes_cipher_obj.encrypt_encode_bytes_utf8(msg + DATA_PARTIT_BYTE)
			msg = hdr + pay

			if (not self.get_session_key_received_ack()):
				## buffer encrypted data until we get client ACK
				## (the most recent message will be at the back)
				##
				## note: should not normally contain anything of
				## value, server has little to send before LOGIN
				self.enc_sendbuffer.append(msg)
				return
			else:
				## reverse so message order is newest to oldest
				self.enc_sendbuffer.reverse()

				## pop from back so client receives in the proper
				## order, with <msg> itself after the queued data
				while (len(self.enc_sendbuffer) > 0):
					self.msg_sendbuffer.append(self.enc_sendbuffer.pop())

			## send the output as-is (base64 is all ASCII)
			binary = True

		if (binary):
			self.msg_sendbuffer.append(msg + DATA_PARTIT_BYTE)
		else:
			self.msg_sendbuffer.append(msg.encode(UNICODE_ENCODING) + DATA_PARTIT_BYTE)

		self.handler.poller.setoutput(self.conn, True)


	def FlushBuffer(self):
		# client gets removed, delete buffers
		if self.removing:
			self.msg_sendbuffer = []
			self.sendingmessage = None
			return
		if not self.sendingmessage:
			message = ''
			while not message:
				if not self.msg_sendbuffer: # just in case, since it returns before going to the end...
					self.handler.poller.setoutput(self.conn, False)
					return
				message = self.msg_sendbuffer.pop(0)
			self.sendingmessage = message
		senddata = self.sendingmessage# [:64] # smaller chunks interpolate better, maybe base this off of number of clients?
		try:
			sent = self.conn.send(senddata)
			self.sendingmessage = self.sendingmessage[sent:] # only removes the number of bytes sent
		except UnicodeDecodeError:
			self.sendingmessage = None
			self._root.console_write('Error sending unicode string, message dropped.')
		except socket.error, e:
			if e == errno.EAGAIN:
				return
			self.msg_sendbuffer = []
			self.sendingmessage = None
		
		self.handler.poller.setoutput(self.conn, bool(self.msg_sendbuffer or self.sendingmessage))
	
	# Queuing
	
	def AddUser(self, user):
		if type(user) in (str, unicode):
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users: return
		self.users.add(session_id)
		self._protocol.client_AddUser(self, user)
	
	def RemoveUser(self, user):
		if type(user) in (str, unicode):
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users:
			self.users.remove(session_id)
			self._protocol.client_RemoveUser(self, user)
	
	def SendUser(self, user, data):
		if type(user) in (str, unicode):
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users:
			self.Send(data)
	
	def AddBattle(self, battle):
		battle_id = battle.id
		if battle_id in self.battles: return
		self.battles.add(battle_id)
		self._protocol.client_AddBattle(self, battle)
	
	def RemoveBattle(self, battle):
		battle_id = battle.id
		if battle_id in self.battles:
			self.battles.remove(battle_id)
			self._protocol.client_RemoveBattle(self, battle)
	
	def SendBattle(self, battle, data):
		battle_id = battle.id
		if battle_id in self.battles:
			self.Send(data)
	
	def isAdmin(self):
		return ('admin' in self.accesslevels)
	
	def isMod(self):
		return self.isAdmin() or ('mod' in self.accesslevels) # maybe cache these

