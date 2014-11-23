#!/usr/bin/env python
# coding=utf-8

import socket, inspect
import time
import threading
import traceback

import CryptoHandler
from CryptoHandler import aes_cipher
from CryptoHandler import rsa_cipher
from CryptoHandler import MD5LEG_HASH_FUNC as LEGACY_HASH_FUNC
from CryptoHandler import SHA256_HASH_FUNC as SECURE_HASH_FUNC
from CryptoHandler import GLOBAL_RAND_POOL

from CryptoHandler import safe_base64_decode as SAFE_DECODE_FUNC
from CryptoHandler import DATA_MARKER_BYTE
from CryptoHandler import DATA_PARTIT_BYTE
from CryptoHandler import UNICODE_ENCODING
from CryptoHandler import NUM_SESSION_KEYS

from base64 import b64encode as ENCODE_FUNC
from base64 import b64decode as DECODE_FUNC

NUM_THREADS = 1

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
			## non-blocking so we do not have to wait on server
			self.socket = socket.create_connection(server_addr, 5)
			self.socket.setblocking(0)
		except socket.error as msg:
			print(msg)
			print(traceback.format_exc())

		self.lastping = 0.0
		self.pingsamples = 0
		self.maxping = 0
		self.minping = 100
		self.average = 0
		self.count = 0
		self.iters = 0

		self.username = username
		self.password = "KeepItSecret.KeepItSafe."

		self.aes_cipher_obj = None
		self.rsa_cipher_obj = rsa_cipher(None)

		## ring-buffer of exchanged keys
		self.session_keys = [""] * NUM_SESSION_KEYS
		self.session_key_id = 0

		self.server_info = ("", "", "", "")

		self.requested_registration = False
		self.requested_authentication = False
		self.accepted_registration = False
		self.accepted_authentication = False

		self.want_secure_session = True
		self.requested_public_key = False
		self.received_public_key = False
		self.sent_shared_key = False
		self.valid_shared_key = False
		self.acked_shared_key = False

	def use_secure_session(self):
		return (self.aes_cipher_obj != None)


	def Send(self, data):
		## test-client never tries to send unicode strings, so
		## we do not need to add encode(UNICODE_ENCODING) calls
		assert(type(data) == str)
		print("[Send][time=%d::iter=%d] data=%s" % (time.time(), self.iters, data))

		if (self.acked_shared_key):
			assert(self.use_secure_session())

			## add marker byte so server does not have to guess
			## if data is of the form ENCODE(ENCRYPTED(...)) or
			## in plaintext
			head = DATA_MARKER_BYTE + chr(self.session_key_id)
			data = self.aes_cipher_obj.encrypt_encode_bytes(data)
			data = head + data + DATA_PARTIT_BYTE

			self.socket.send(data)
		else:
			sentence = data.split()
			command = sentence[0]

			if ((not self.want_secure_session) or (command in ALLOWED_OPEN_COMMANDS)):
				self.socket.send(data + DATA_PARTIT_BYTE)
			else:
				print("\tcan not send command \"%s\" unencrypted, wait for SHAREDKEY!" % command)

	def Recv(self, cur_socket_data):
		try:
			nxt_socket_data = self.socket.recv(4096)
			cur_socket_data += nxt_socket_data

			if (len(nxt_socket_data) == 0):
				return cur_socket_data
		except:
			return cur_socket_data

		if (cur_socket_data.count(DATA_PARTIT_BYTE) == 0):
			return cur_socket_data

		split_data = cur_socket_data.split(DATA_PARTIT_BYTE)
		data_blobs = split_data[: len(split_data) - 1  ]
		final_blob = split_data[  len(split_data) - 1: ][0]

		for raw_data_blob in data_blobs:
			is_encrypted_blob = (raw_data_blob[0] == DATA_MARKER_BYTE)

			if (self.use_secure_session() and is_encrypted_blob):
				self.session_key_id = ord(raw_data_blob[1])
				self.aes_cipher_obj.set_key(self.session_keys[self.session_key_id])

				## after decryption dec_command might represent a batch of
				## commands separated by newlines, all of which need to be
				## handled successfully
				enc_command = raw_data_blob[2: ]
				dec_command = self.aes_cipher_obj.decode_decrypt_bytes_utf8(enc_command, SAFE_DECODE_FUNC)
				dec_commands = dec_command.split(DATA_PARTIT_BYTE)
				dec_commands = [(cmd.rstrip('\r')).lstrip(' ') for cmd in dec_commands]

				for dec_command in dec_commands:
					self.Handle(dec_command)
			else:
				## strips leading spaces and trailing carriage return
				self.Handle((raw_data_blob.rstrip('\r')).lstrip(' '))

		return final_blob

	def Handle(self, msg):
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
			self.Send("LOGIN %s %s" % (self.username, ENCODE_FUNC(LEGACY_HASH_FUNC(self.password).digest())))

		self.requested_authentication = True

	def out_REGISTER(self):
		print("[REGISTER][time=%d::iter=%d]" % (time.time(), self.iters))

		if (self.use_secure_session()):
			self.Send("REGISTER %s %s" % (self.username, self.password))
		else:
			self.Send("REGISTER %s %s" % (self.username, ENCODE_FUNC(LEGACY_HASH_FUNC(self.password).digest())))

		self.requested_registration = True


	def out_PING(self):
		print("[PING][time=%d::iters=%d]" % (time.time(), self.iters))

		self.Send("PING")


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
		aes_key_enc = self.rsa_cipher_obj.encrypt_encode_bytes(aes_key_raw)

		if (self.aes_cipher_obj == None):
			self.aes_cipher_obj = aes_cipher("")
			self.aes_cipher_obj.set_key("")

		## make a copy of the previous key (if any) since
		## we might need it to decrypt SHAREDKEY REJECTED
		## (if already in a secure session)
		self.session_keys[(self.session_key_id + 0) % NUM_SESSION_KEYS] = self.aes_cipher_obj.get_key()
		self.session_keys[(self.session_key_id + 1) % NUM_SESSION_KEYS] = aes_key_sig.digest()

		## wrap around when we reach the largest allowed id
		## only two elements (id % N) and ((id + 1) % N) are
		## technically ever needed, N > 2 is redundant
		self.session_key_id += 1
		self.session_key_id %= NUM_SESSION_KEYS

		## start using new key immediately, server will
		## encrypt response with it (if key is accepted)
		self.aes_cipher_obj.set_key(self.session_keys[self.session_key_id])

		print("[SETSHAREDKEY][time=%d::iter=%d] sha(raw)=%s enc(raw)=%s..." % (time.time(), self.iters, aes_key_sig.digest(), aes_key_enc[0: 8]))

		## ENCODE(ENCRYPT_RSA(AES_KEY, RSA_PUB_KEY))
		self.Send("SETSHAREDKEY %s" % aes_key_enc)
		self.sent_shared_key = True

	def out_ACKSHAREDKEY(self):
		assert(self.received_public_key)
		assert(self.sent_shared_key)
		assert(self.valid_shared_key)
		assert(not self.acked_shared_key)

		print("[ACKSHAREDKEY][time=%d::iter=%d]" % (time.time(), self.iters))

		## needs to be set before the call, otherwise the message gets
		## dropped (since ACKSHAREDKEY is not in ALLOWED_OPEN_COMMANDS)
		self.acked_shared_key = True
		self.Send("ACKSHAREDKEY")



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
		self.rsa_cipher_obj.set_pri_key(CryptoHandler.RSA_NULL_KEY_OBJ)

		## these should be equal to the server-side schemes
		self.rsa_cipher_obj.set_pad_scheme(CryptoHandler.RSA_PAD_SCHEME)
		self.rsa_cipher_obj.set_sgn_scheme(CryptoHandler.RSA_SGN_SCHEME)

		print("[PUBLICKEY][time=%d::iter=%d] %s" % (time.time(), self.iters, rsa_pub_key_str))

		self.received_public_key = True
		self.out_SETSHAREDKEY()

	## "SHAREDKEY %s %s" % ("STATUS", "DATA")
	def in_SHAREDKEY(self, arg0, arg1 = ""):
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
			## REJECTED, ENFORCED, or DISABLED
			pass

		if (not can_send_ack_shared_key):
			self.sent_session_key = False
			self.valid_shared_key = False
			self.acked_shared_key = False

			## try again with a new session key
			self.out_SETSHAREDKEY()
		else:
			## let server know it can begin sending secure data
			self.out_ACKSHAREDKEY()




	def in_TASSERVER(self, protocolVersion, springVersion, udpPort, serverMode):
		print("[TASSERVER][time=%d::iter=%d] proto=%s spring=%s udp=%s mode=%s" % (time.time(), self.iters, protocolVersion, springVersion, udpPort, serverMode))
		self.server_info = (protocolVersion, springVersion, udpPort, serverMode)

	def in_SERVERMSG(self, msg):
		print("[SERVERMSG][time=%d::iter=%d] %s" % (time.time(), self.iters, msg))

	def in_REGISTRATIONDENIED(self, msg):
		print("[REGISTRATIONDENIED][time=%d::iter=%d] %s" % (time.time(), self.iters, msg))
		## user account maybe already exists, try to login (done in Run)
		self.accepted_registration = True
		self.requested_authentication = False

	def in_AGREEMENT(self, msg):
		pass
	def in_AGREEMENTEND(self):
		print("[AGREEMENDEND][time=%d::iter=%d]" % (time.time(), self.iters))
		self.Send("CONFIRMAGREEMENT")


	def in_REGISTRATIONACCEPTED(self):
		print("[REGISTRATIONACCEPTED][time=%d::iter=%d]" % (time.time(), self.iters))

		self.accepted_registration = True

	def in_ACCEPTED(self, msg):
		print("[LOGINACCEPTED][time=%d::iter=%d]" % (time.time(), self.iters))
		## if we get here, everything checks out
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
	def in_LOGININFOEND(self):
		## do stuff here (e.g. "JOIN channel")
		pass
	def in_BATTLECLOSED(self, msg):
		print(msg)
	def in_REMOVEUSER(self, msg):
		print(msg)
	def in_LEFTBATTLE(self, msg):
		print(msg)

	def in_PONG(self):
		if (False and self.count > 1000):
			print("max %0.3f min %0.3f average %0.3f" % (self.maxping, self.minping, (self.average / self.pingsamples)))
			self.Send("EXIT")
			return

		if (self.lastping != 0.0):
			diff = time.time() - self.lastping

			self.minping = min(diff, self.minping)
			self.maxping = max(diff, self.maxping)

			self.average = self.average + diff
			self.pingsamples = self.pingsamples + 1
			print("%0.3f" %(diff))

		self.lastping = time.time()
		self.count = self.count + 1
		self.out_PING()

	def in_JOIN(self, msg):
		print(msg)
	def in_CLIENTS(self, msg):
		print(msg)
	def in_JOINED(self, msg):
		print(msg)
	def in_LEFT(self, msg):
		print(msg)


	def Run(self):
		if not self.socket:
			return

		socket_data = ""

		## initialize key-exchange sequence (ends with ACKSHAREDKEY)
		if (self.want_secure_session):
			self.out_GETPUBLICKEY()

		while (True):
			self.iters += 1

			if (False and self.iters > 5):
				self.socket.close()
				return

			## create an account for us securely and hop on with it
			if (self.acked_shared_key or (not self.want_secure_session)):
				if (not self.requested_registration):
					self.out_REGISTER()
				if (self.accepted_registration and (not self.requested_authentication)):
					self.out_LOGIN()

			## periodically re-negotiate the session key (every
			## 500*0.05=25.0s; models an ultra-paranoid client)
			if (self.want_secure_session and self.use_secure_session()):
				if ((self.iters % 500) == 0):
					self.sent_shared_key = False
					self.valid_shared_key = False
					self.acked_shared_key = False
					self.out_SETSHAREDKEY()

			socket_data = self.Recv(socket_data)
			threading._sleep(0.05)

	def in_CHANNELTOPIC(self, msg):
		print(msg)
	def in_DENIED(self, msg):
		print(msg)


def runclient(i):
	print("Running client %d" % (i))
	user_name = "ubertest" + str(i)
	client = LobbyClient(HOST_SERVER, user_name)
	client.Run()
	print("finished: " + user_name)

threads = []

if NUM_THREADS == 1:
	runclient(1)
else:
	for x in xrange(NUM_THREADS):
		clientthread = threading.Thread(target = runclient, args = (x, ))
		clientthread.start()
		threads.append(clientthread)
	for t in threads:
		t.join()

