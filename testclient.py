#!/usr/bin/env python
# coding=utf-8

import socket, inspect
import time
import threading
import traceback

from CryptoHandler import aes_cipher
from CryptoHandler import rsa_cipher
from CryptoHandler import MD5LEG_HASH_FUNC as LEGACY_HASH_FUNC
from CryptoHandler import SHA256_HASH_FUNC as SECURE_HASH_FUNC
from CryptoHandler import GLOBAL_RAND_POOL
import CryptoHandler

from base64 import b64encode as ENCODE_FUNC
from base64 import b64decode as DECODE_FUNC

NUM_THREADS = 1
DATA_SEPAR = "\n"

HOST_SERVER = ("localhost", 8200)
MAIN_SERVER = ("lobby.springrts.com", 8200)
TEST_SERVER = ("lobby.springrts.com", 7000)
BACKUP_SERVERS = [
	("lobby1.springlobby.info", 8200),
	("lobby2.springlobby.info", 8200),
]

## commands that are allowed to be sent unencrypted
## (after session key is established, any subsequent
## SETSHAREDKEY commands will be encrypted entirely)
ALLOWED_OPEN_COMMANDS = ["GETPUBLICKEY", "SETSHAREDKEY", "EXIT"]

class LobbyClient:
	def __init__(self, server_addr, username):
		self.socket = None

		try:
			self.socket = socket.create_connection(server_addr, 5)
		except socket.error as msg:
			print(msg)
			print(traceback.format_exc())

		self.lastping = time.time()
		self.pingsamples = 0
		self.maxping = 0
		self.minping = 100
		self.average = 0
		self.count = 0
		self.iters = 0

		self.username = username
		self.password = "Keep it secret. Keep it safe."

		self.requested_authentication = False
		self.requested_registration = True
		self.accepted_authentication = False
		self.accepted_registration = True

		self.aes_cipher_obj = None
		self.rsa_cipher_obj = rsa_cipher("")

		self.want_secure_session = True
		self.requested_public_key = False
		self.received_public_key = False
		self.sent_shared_key = False
		self.valid_shared_key = False
		self.acked_shared_key = False

	def use_secure_session(self):
		return (self.aes_cipher_obj != None)

	def Send(self, data):
		assert(type(data) == str)
		print("[Send][time=%d::iter=%d] data=%s" % (time.time(), self.iters, data))

		if (self.acked_shared_key):
			assert(self.use_secure_session())

			data = self.aes_cipher_obj.encrypt_encode_bytes(data)
			data = data.encode("utf-8") ## unneeded

			self.socket.send(data + DATA_SEPAR)
		else:
			sentence = data.split()
			command = sentence[0]

			if (command in ALLOWED_OPEN_COMMANDS):
				self.socket.send(data.encode("utf-8") + DATA_SEPAR)


	def handle(self, msg):
		## probably caused by trailing newline ("abc\n".split("\n") == ["abc", ""])
		if (len(msg) <= 1):
			return True

		numspaces = msg.count(' ')

		if (numspaces > 0):
			command, args = msg.split(' ', 1)
		else:
			command = msg

		command = command.upper()

		funcname = 'in_%s' % command
		function = getattr(self, funcname)
		function_info = inspect.getargspec(function)
		total_args = len(function_info[0]) - 1
		optional_args = 0

		if (function_info[3]):
			optional_args = len(function_info[3])
		required_args = total_args - optional_args

		if (required_args == 0 and numspaces == 0):
			function()
			return True


		## bunch the last words together if there are too many of them
		if (numspaces > total_args - 1):
			arguments = args.split(' ', total_args - 1)
		else:
			arguments = args.split(' ')

		try:
			function(*(arguments))
			return True
		except Exception, e:
			print("Error handling: \"%s\" %s" % (msg, e))
			print(traceback.format_exc())
			return False



	def out_LOGIN(self):
		print("[LOGIN][time=%d::iter=%d]" % (time.time(), self.iters))

		if (self.use_secure_session()):
			self.Send("LOGIN %s %s" % (self.username, self.password))
		else:
			self.Send("LOGIN %s %s" % (self.username, ENCODE_FUNC(MD5LEG_HASH_FUNC(self.username).digest())))

		self.requested_authentication = True

	def out_REGISTER(self, protocolVersion, springVersion, udpPort, serverMode):
		print("[REGISTER][time=%d::iter=%d]" % (time.time(), self.iters))

		if (self.use_secure_session()):
			self.send("REGISTER %s %s" % (self.username, self.password))
		else:
			## print("%s %s %s %s" % (protocolVersion, springVersion, udpPort, serverMode))
			self.Send("REGISTER %s %s" % (self.username, ENCODE_FUNC(MD5LEG_HASH_FUNC(self.username).digest())))

		self.requested_registration = True


	def out_GETPUBLICKEY(self):
		assert(not self.received_public_key)
		assert(not self.sent_shared_key)
		assert(not self.valid_shared_key)
		assert(not self.acked_shared_key)

		print("[GETPUBLICKEY][time=%d::iter=%d]" % (time.time(), self.iters))

		self.Send("GETPUBLICKEY")
		self.requested_public_key = True

	def out_SETSHAREDKEY(self):
		assert(self.received_public_key)
		assert(not self.sent_shared_key)
		assert(not self.valid_shared_key)
		assert(not self.acked_shared_key)

		## note: server will use HASH(RAW) as key and echo back HASH(HASH(RAW))
		## hence we send ENCODE(ENCRYPT(RAW)) and use HASH(RAW) on our side too
		aes_key_raw = GLOBAL_RAND_POOL.read(CryptoHandler.MIN_AES_KEY_SIZE * 2)
		aes_key_sig = SECURE_HASH_FUNC(aes_key_raw)
		aes_key_str = self.rsa_cipher_obj.encrypt_encode_bytes(aes_key_raw)

		if (self.aes_cipher_obj == None):
			self.aes_cipher_obj = aes_cipher("")

		## start using the key immediately, server will
		## encrypt response with it (if key is accepted)
		self.aes_cipher_obj.set_key(aes_key_sig.digest())

		print("[SETSHAREDKEY][time=%d::iter=%d] sha(raw)=%s aes(raw)=%s" % (time.time(), self.iters, self.aes_cipher_obj.get_key(), aes_key_str))

		## ENCODE(ENCRYPT_RSA(AES_KEY, RSA_PUB_KEY))
		self.Send("SETSHAREDKEY %s" % aes_key_str)
		self.sent_shared_key = True

	def out_ACKSHAREDKEY(self):
		assert(self.received_public_key)
		assert(self.sent_shared_key)
		assert(not self.valid_shared_key)
		assert(not self.acked_shared_key)

		print("[ACKSHAREDKEY][time=%d::iter=%d]" % (time.time(), self.iters))

		self.Send("ACKSHAREDKEY")
		self.acked_shared_key = True



	## "PUBLICKEY %s" % (ENCODE("PEM(PUB_KEY)"))
	def in_PUBLICKEY(self, arg):
		assert(not self.received_public_key)
		assert(not self.sent_shared_key)
		assert(not self.valid_shared_key)
		assert(not self.acked_shared_key)

		rsa_pub_key_str = DECODE_FUNC(arg)
		rsa_pub_key_obj = self.rsa_cipher_obj.import_key(rsa_pub_key_str)

		## note: private key will be useless hereafter, but WDC
		self.rsa_cipher_obj.set_pub_key(rsa_pub_key_obj)
		## can not do this explicitly (scheme.new() will fail)
		## self.rsa_cipher_obj.set_pri_key(None)

		## these should be equal to the server-side schemes
		self.rsa_cipher_obj.set_pad_scheme(CryptoHandler.RSA_PAD_SCHEME)
		self.rsa_cipher_obj.set_sgn_scheme(CryptoHandler.RSA_SGN_SCHEME)

		print("[PUBLICKEY][time=%d::iter=%d] %s" % (time.time(), self.iters, rsa_pub_key_str))

		self.received_public_key = True
		self.out_SETSHAREDKEY()

	## "SHAREDKEY %s %s" % ("STATUS", "DATA")
	def in_SHAREDKEY(self, arg0, arg1):
		assert(self.use_secure_session())
		assert(self.received_public_key)
		assert(self.sent_shared_key)
		assert(not self.valid_shared_key)
		assert(not self.acked_shared_key)

		print("[SHAREDKEY][time=%d::iter=%d] %s %s" % (time.time(), self.iters, arg0, arg1))

		can_send_ack_shared_key = False

		if (arg0 == "ACCEPTED"):
			server_key_sig = DECODE_FUNC(arg1)
			client_key_sha = SECURE_HASH_FUNC(self.aes_cipher_obj.get_key())
			client_key_sig = client_key_sha.digest()

			print("\tserver_key_sig=%s client_key_sig=%s" % (server_key_sig, client_key_sig))

			## server considers key valid and has accepted it
			self.valid_shared_key = True

			## now check for data manipulation or corruption
			can_send_ack_shared_key = (server_key_sig == client_key_sig)
		else:
			## rejected as invalid or cleared
			pass

		if (not can_send_ack_shared_key):
			self.sent_session_key = False
			self.valid_shared_key = False
			self.acked_shared_key = False

			## try again with a new key
			self.out_SETSHAREDKEY()
		else:
			## let server know it can begin sending secure data
			self.out_ACKSHAREDKEY()




	def in_TASSERVER(self, protocolVersion, springVersion, udpPort, serverMode):
		print("[TASSERVER][time=%d::iter=%d] proto=%s spring=%s udp=%s mode=%s" % (time.time(), self.iters, protocolVersion, springVersion, udpPort, serverMode))

	def in_SERVERMSG(self, msg):
		print("[SERVERMSG][time=%d::iter=%d] %s" % (time.time(), self.iters, msg))

	def in_REGISTRATIONDENIED(self, msg):
		pass ## self.out_LOGIN()

	def in_AGREEMENT(self, msg):
		pass
	def in_AGREEMENTEND(self):
		self.Send("CONFIRMAGREEMENT")


	def in_REGISTRATIONACCEPTED(self):
		print("[REGISTRATIONACCEPTED][time=%d::iter=%d]" % (time.time(), self.iters))

		self.accepted_registration = True
		self.out_LOGIN()

	def in_ACCEPTED(self, msg):
		print("[LOGINACCEPTED][time=%d::iter=%d]" % (time.time(), self.iters))

		self.accepted_authentication = True


	def in_MOTD(self, msg):
		pass
	def in_ADDUSER(self, msg):
		print(msg)
	def in_BATTLEOPENED(self, msg):
		print(msg)
	def in_UPDATEBATTLEINFO(self, msg):
		print(msg)
	def in_JOINEDBATTLE(self, msg):
		print(msg)
	def in_CLIENTSTATUS(self, msg):
		pass
		#print(msg)
	def in_LOGININFOEND(self):
		# do stuff
		#self.Send("PING")
		#self.Send("JOIN bla")
		pass
	def in_BATTLECLOSED(self, msg):
		print(msg)
	def in_REMOVEUSER(self, msg):
		print(msg)
	def in_LEFTBATTLE(self, msg):
		print(msg)

	def in_PONG(self):
		if self.count > 1000:
			print("max %0.3f min %0.3f average %0.3f" %(self.maxping, self.minping, (self.average / self.pingsamples)))
			self.Send("EXIT")
			return
		if self.lastping:
			diff = time.time() - self.lastping
			if diff>self.maxping:
				self.maxping = diff
			if diff<self.minping:
				self.minping = diff
			self.average = self.average + diff
			self.pingsamples = self.pingsamples +1
			print("%0.3f" %(diff))
		self.lastping = time.time()
		self.Send("PING")
		self.count = self.count + 1

	def in_JOIN(self, msg):
		print(msg)
	def in_CLIENTS(self, msg):
		print(msg)
	def in_JOINED(self, msg):
		print(msg)
	def in_LEFT(self, msg):
		print(msg)


	def run(self):
		if not self.socket:
			return

		sdata = ""

		if (self.want_secure_session):
			## initialize key-exchange sequence
			self.out_GETPUBLICKEY()

		while (True):
			self.iters += 1

			if (False and self.iters > 5):
				self.socket.close()
				return

			## create an account for us and hop on with it
			if (self.acked_shared_key):
				if (not self.requested_registration):
					self.out_REGISTER()
				if (self.accepted_registration and (not self.requested_authentication)):
					self.out_LOGIN()

			try:
				sdata += self.socket.recv(4096)

				if (sdata.count(DATA_SEPAR) == 0):
					continue

				data = sdata.split(DATA_SEPAR)
				datas = data[: len(data) - 1  ]
				sdata = data[  len(data) - 1: ][0]

				for data in datas:
					## strips leading spaces and trailing carriage return
					raw_command = (data.rstrip('\r')).lstrip(' ')
					raw_command = raw_command.encode("utf-8")

					if (self.use_secure_session()):
						## after decryption dec_command might represent a
						## batch of commands separated by newlines, which
						## all need to be handled successfully
						try:
							dec_command = self.aes_cipher_obj.decode_decrypt_bytes(raw_command)
						except:
							print("Can't decrypt %s: " % (raw_command))
							return
						dec_commands = dec_command.split(DATA_SEPAR)
						dec_commands = [(cmd.rstrip('\r')).lstrip(' ') for cmd in dec_commands]
						num_handled = 0

						for dec_command in dec_commands:
							num_handled += int(self.handle(dec_command))

						## if decryption produced garbage (e.g. because
						## raw_command was sent as plaintext: SHAREDKEY
						## INVALID) and caused handle() to fail, try to
						## interpret the raw bytes
						if (num_handled < len(dec_commands)):
							self.handle(raw_command)
					else:
						self.handle(raw_command)

			except socket.timeout:
				pass

			threading._sleep(0.05)

	def in_CHANNELTOPIC(self, msg):
		print(msg)
	def in_DENIED(self, msg):
		print(msg)


def runclient(i):
	print("Running client %d" % (i))
	user_name = "ubertest" + str(i)
	client = LobbyClient(HOST_SERVER, user_name)
	client.run()
	print("finished: " + user_name)

threads = []

for x in xrange(NUM_THREADS):
	clientthread = threading.Thread(target = runclient, args = (x, ))
	clientthread.start()
	threads.append(clientthread)

for t in threads:
	t.join()

