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

NUM_CLIENTS = 1
NUM_UPDATES = 10000
USE_THREADS = False
CLIENT_NAME = "ubertest%02d"
CLIENT_PWRD = "KeepItSecretKeepItSafe%02d"
MAGIC_WORDS = "SqueamishOssifrage"

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
ALLOWED_OPEN_COMMANDS = ["GETPUBLICKEY", "GETSIGNEDMSG", "SETSHAREDKEY", "EXIT"]

class LobbyClient:
	def __init__(self, server_addr, username, password):
		self.host_socket = None
		self.socket_data = ""

		self.username = username
		self.password = password

		self.OpenSocket(server_addr)
		self.Init()

	def OpenSocket(self, server_addr):
		while (self.host_socket == None):
			try:
				## non-blocking so we do not have to wait on server
				self.host_socket = socket.create_connection(server_addr, 5)
				self.host_socket.setblocking(0)
			except socket.error as msg:
				print("[OpenSocket] %s" % msg)
				## print(traceback.format_exc())
				threading._sleep(0.5)

	def Init(self):
		self.lastping = 0.0
		self.pingsamples = 0
		self.maxping = 0
		self.minping = 100
		self.average = 0
		self.iters = 0

		self.aes_cipher_obj = aes_cipher("")
		self.rsa_cipher_obj = rsa_cipher(None)

		## start with a NULL session-key
		self.set_session_key("")

		## ring-buffer of exchanged session keys
		self.session_keys = [""] * NUM_SESSION_KEYS
		self.session_key_id = 0

		self.data_send_queue = []

		self.server_info = ("", "", "", "")

		self.requested_registration   = False ## set on out_REGISTER
		self.requested_authentication = False ## set on out_LOGIN
		self.accepted_registration    = False ## set on in_REGISTRATIONACCEPTED
		self.rejected_registration    = False ## set on in_REGISTRATIONDENIED
		self.accepted_authentication  = False ## set on in_ACCEPTED

		self.want_secure_session = True
		self.received_public_key = False

		self.reset_session_state()

		## initialize key-exchange sequence (ends with ACKSHAREDKEY)
		## needed even if (for some reason) we do not want a secure
		## session to discover the server force_secure_{auths,comms}
		## settings
		self.out_GETPUBLICKEY()


	def set_session_key(self, key): self.aes_cipher_obj.set_key(key)
	def get_session_key(self): return (self.aes_cipher_obj.get_key())

	def use_secure_session(self): return (len(self.get_session_key()) != 0)

	def reset_session_state(self):
		self.sent_unacked_shared_key = False
		self.server_valid_shared_key = False
		self.client_acked_shared_key = False


	def Send(self, data, flush = True):
		## test-client never tries to send unicode strings, so
		## we do not need to add encode(UNICODE_ENCODING) calls
		assert(type(data) == str)
		print("[Send][time=%d::iter=%d] data=\"%s\" sec_sess=%d key_acked=%d flush=%d" % (time.time(), self.iters, data, self.use_secure_session(), self.client_acked_shared_key, flush))

		"""
		if (not flush):
			self.data_send_queue.append((self.get_session_key(), self.client_acked_shared_key, self.want_secure_session, data))
			return

		self.data_send_queue.reverse()

		while (len(self.data_send_queue) > 0):
			(key, ack, sec, msg) = data_send_queue.pop()

			if (len(key) != 0):
				self.set_session_key(key)

				hdr = DATA_MARKER_BYTE
				pay = self.aes_cipher_obj.encrypt_encode_bytes(msg + DATA_PARTIT_BYTE)
				msg = hdr + pay

				if (ack):
					self.host_socket.send(msg + DATA_PARTIT_BYTE)
					self.host_socket.send(data + DATA_PARTIT_BYTE)
				else:
					print("\tblocked sending \"%s\": session-key unacknowledged!" % command)
			else:
				cmd = data.split()
				cmd = sentence[0]

				if ((not sec) or (cmd in ALLOWED_OPEN_COMMANDS)):
					self.host_socket.send(msg + DATA_PARTIT_BYTE)
		"""

		if (self.client_acked_shared_key):
			assert(self.use_secure_session())

			## add marker byte so server does not have to guess
			## if data is of the form ENCODE(ENCRYPTED(...)) or
			## in plaintext
			##
			## TODO:
			##   queue up and concatenate a small random number
			##   of commands before encrypting them, but always
			##   force a flush when command is SETSHAREDKEY (or
			##   if a command needs immediate attention)
			hdr = DATA_MARKER_BYTE
			pay = self.aes_cipher_obj.encrypt_encode_bytes(data + DATA_PARTIT_BYTE)
			msg = hdr + pay

			self.host_socket.send(msg + DATA_PARTIT_BYTE)
		else:
			cmd = data.split()
			cmd = cmd[0]

			if ((not self.want_secure_session) or (cmd in ALLOWED_OPEN_COMMANDS)):
				self.host_socket.send(data + DATA_PARTIT_BYTE)
			else:
				print("\tblocked sending \"%s\": session-key unacknowledged!" % cmd)

	def Recv(self):
		num_received_bytes = len(self.socket_data)

		try:
			self.socket_data += self.host_socket.recv(4096)
		except:
			return

		if (len(self.socket_data) == num_received_bytes):
			return
		if (self.socket_data.count(DATA_PARTIT_BYTE) == 0):
			return

		split_data = self.socket_data.split(DATA_PARTIT_BYTE)
		data_blobs = split_data[: len(split_data) - 1  ]
		final_blob = split_data[  len(split_data) - 1: ][0]

		for raw_data_blob in data_blobs:
			if (self.use_secure_session()):
				if (raw_data_blob[0] != DATA_MARKER_BYTE):
					continue

				## after decryption dec_command might represent a batch of
				## commands separated by newlines, all of which need to be
				## handled successfully
				enc_command = raw_data_blob[1: ]
				dec_command = self.aes_cipher_obj.decode_decrypt_bytes_utf8(enc_command, SAFE_DECODE_FUNC)
				dec_commands = dec_command.split(DATA_PARTIT_BYTE)
				dec_commands = [(cmd.rstrip('\r')).lstrip(' ') for cmd in dec_commands]

				for dec_command in dec_commands:
					self.Handle(dec_command)
			else:
				if (raw_data_blob[0] == DATA_MARKER_BYTE):
					continue

				## strips leading spaces and trailing carriage return
				self.Handle((raw_data_blob.rstrip('\r')).lstrip(' '))

		self.socket_data = final_blob

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
		print("[LOGIN][time=%d::iter=%d] sec_sess=%d" % (time.time(), self.iters, self.use_secure_session()))

		if (self.use_secure_session()):
			self.Send("LOGIN %s %s" % (self.username, ENCODE_FUNC(self.password)))
		else:
			self.Send("LOGIN %s %s" % (self.username, ENCODE_FUNC(LEGACY_HASH_FUNC(self.password).digest())))

		self.requested_authentication = True

	def out_REGISTER(self):
		print("[REGISTER][time=%d::iter=%d] sec_sess=%d" % (time.time(), self.iters, self.use_secure_session()))

		if (self.use_secure_session()):
			self.Send("REGISTER %s %s" % (self.username, ENCODE_FUNC(self.password)))
		else:
			self.Send("REGISTER %s %s" % (self.username, ENCODE_FUNC(LEGACY_HASH_FUNC(self.password).digest())))

		self.requested_registration = True

	def out_CONFIRMAGREEMENT(self):
		print("[CONFIRMAGREEMENT][time=%d::iter=%d] sec_sess=%d" % (time.time(), self.iters, self.use_secure_session()))
		self.Send("CONFIRMAGREEMENT")


	def out_PING(self):
		print("[PING][time=%d::iters=%d]" % (time.time(), self.iters))

		self.Send("PING")

	def out_EXIT(self):
		self.host_socket.close()


	def out_GETPUBLICKEY(self):
		assert(not self.received_public_key)
		assert(not self.sent_unacked_shared_key)
		assert(not self.server_valid_shared_key)
		assert(not self.client_acked_shared_key)

		print("[GETPUBLICKEY][time=%d::iter=%d]" % (time.time(), self.iters))

		self.Send("GETPUBLICKEY")

	def out_GETSIGNEDMSG(self):
		assert(self.received_public_key)
		assert(not self.sent_unacked_shared_key)
		assert(not self.server_valid_shared_key)
		assert(not self.client_acked_shared_key)

		print("[GETSIGNEDMSG][time=%d::iter=%d]" % (time.time(), self.iters))

		self.Send("GETSIGNEDMSG %s" % ENCODE_FUNC(MAGIC_WORDS))

	def out_SETSHAREDKEY(self):
		assert(self.received_public_key)
		assert(not self.sent_unacked_shared_key)
		assert(not self.server_valid_shared_key)
		assert(not self.client_acked_shared_key)

		## note: server will use HASH(RAW) as key and echo back HASH(HASH(RAW))
		## hence we send ENCODE(ENCRYPT(RAW)) and use HASH(RAW) on our side too
		aes_key_raw = GLOBAL_RAND_POOL.read(CryptoHandler.MIN_AES_KEY_SIZE * 2)
		aes_key_sig = SECURE_HASH_FUNC(aes_key_raw)
		aes_key_enc = self.rsa_cipher_obj.encrypt_encode_bytes(aes_key_raw)

		## make a copy of the previous key (if any) since
		## we still need it to decrypt SHAREDKEY response
		## etc
		self.session_keys[(self.session_key_id + 0) % NUM_SESSION_KEYS] = self.aes_cipher_obj.get_key()
		self.session_keys[(self.session_key_id + 1) % NUM_SESSION_KEYS] = aes_key_sig.digest()

		## wrap around when we reach the largest allowed id
		self.session_key_id += 1
		self.session_key_id %= NUM_SESSION_KEYS

		print("[SETSHAREDKEY][time=%d::iter=%d] sha(raw)=%s enc(raw)=%s..." % (time.time(), self.iters, aes_key_sig.digest(), ENCODE_FUNC(aes_key_enc[0: 8])))

		## when re-negotiating a key during an established session,
		## reset_session_state() makes this false but we need it to
		## be true temporarily to get the message out
		self.client_acked_shared_key = self.use_secure_session()

		## ENCODE(ENCRYPT_RSA(AES_KEY, RSA_PUB_KEY))
		self.Send("SETSHAREDKEY %s" % aes_key_enc)

		self.client_acked_shared_key = False
		self.sent_unacked_shared_key = True

	def out_ACKSHAREDKEY(self):
		assert(self.received_public_key)
		assert(self.sent_unacked_shared_key)
		assert(self.server_valid_shared_key)
		assert(not self.client_acked_shared_key)

		print("[ACKSHAREDKEY][time=%d::iter=%d]" % (time.time(), self.iters))

		## start using a new key after verification; server will have
		## already switched to it so our ACKSHAREDKEY can be decrypted
		##
		## NOTE:
		##   during the SETSHAREDKEY --> SHAREDKEY interval a client
		##   should NOT send any messages since it does not yet know
		##   whether the server has properly received the session key
		##   THIS INCLUDES *NEW* SETSHAREDKEY COMMANDS!
		self.set_session_key(self.session_keys[self.session_key_id])

		## needs to be set before the Send, otherwise the message gets
		## dropped (since ACKSHAREDKEY is not in ALLOWED_OPEN_COMMANDS)
		self.client_acked_shared_key = True

		self.Send("ACKSHAREDKEY")



	##
	## "PUBLICKEY %s" % (ENCODE("PEM(PUB_KEY)", force_sec_auths, force_sec_comms))
	##
	def in_PUBLICKEY(self, enc_pem_pub_key, force_sec_auths, force_sec_comms):
		assert(not self.received_public_key)
		assert(not self.sent_unacked_shared_key)
		assert(not self.server_valid_shared_key)
		assert(not self.client_acked_shared_key)

		rsa_pub_key_str = DECODE_FUNC(enc_pem_pub_key)
		rsa_pub_key_obj = self.rsa_cipher_obj.import_key(rsa_pub_key_str)

		## note: private key is never used, but it can not be None
		self.rsa_cipher_obj.set_pub_key(rsa_pub_key_obj)
		self.rsa_cipher_obj.set_pri_key(CryptoHandler.RSA_NULL_KEY_OBJ)

		## these should be equal to the server-side schemes
		self.rsa_cipher_obj.set_pad_scheme(CryptoHandler.RSA_PAD_SCHEME)
		self.rsa_cipher_obj.set_sgn_scheme(CryptoHandler.RSA_SGN_SCHEME)

		print("[PUBLICKEY][time=%d::iter=%d] pub_key=%s" % (time.time(), self.iters, rsa_pub_key_str))

		## client should never want to connect insecurely,
		## but in case it does the server's say is *FINAL*
		if (not self.want_secure_session):
			try:
				self.want_secure_session = (int(force_sec_auths) != 0) or (int(force_sec_comms) != 0)
			except:
				pass

		self.received_public_key = True

		if (not self.want_secure_session):
			return

		self.out_GETSIGNEDMSG()
		self.out_SETSHAREDKEY()

	##
	## "SIGNEDMSG %s" % (ENCODE("123456L"=SIGN(HASH(MSG))))
	##
	def in_SIGNEDMSG(self, msg_sig):
		print("[SIGNEDMSG][time=%d::iter=%d] msg_sig=%s" % (time.time(), self.iters, msg_sig))
		assert(self.received_public_key)
		assert(self.rsa_cipher_obj.auth_bytes(MAGIC_WORDS, DECODE_FUNC(msg_sig)))

	##
	## "SHAREDKEY %s %s %s" % (KEYSTATUS={"ACCEPTED", "REJECTED", "ENFORCED", "DISABLED"}, "KEYDIGEST" [, "EXTRADATA"])
	##
	def in_SHAREDKEY(self, key_status, key_digest, extra_data = ""):
		assert(self.received_public_key)
		assert(self.sent_unacked_shared_key)
		assert(not self.server_valid_shared_key)
		assert(not self.client_acked_shared_key)

		print("[SHAREDKEY][time=%d::iter=%d] %s %s %s" % (time.time(), self.iters, key_status, key_digest, extra_data))

		can_send_ack_shared_key = False

		if (key_status == "INITSESS"):
			## special case during first session-key exchange
			assert(not self.use_secure_session())
			assert(len(self.session_keys[self.session_key_id]) != 0)

			self.set_session_key(self.session_keys[self.session_key_id])
			return

		elif (key_status == "ACCEPTED"):
			server_key_sig = DECODE_FUNC(key_digest)
			client_key_sha = SECURE_HASH_FUNC(self.session_keys[self.session_key_id])
			client_key_sig = client_key_sha.digest()

			print("\tserver_key_sig=%s\n\tclient_key_sig=%s" % (ENCODE_FUNC(server_key_sig), ENCODE_FUNC(client_key_sig)))

			## server considers key valid and has accepted it
			## now check for data manipulation or corruption
			## before sending back our final acknowledgement
			self.server_valid_shared_key = True

			can_send_ack_shared_key = (server_key_sig == client_key_sig)
		elif (key_status == "DISABLED"):
			self.reset_session_state()
			self.set_session_key("")

			## never sent, no longer supported by server
			assert(False)
			return

		if (not can_send_ack_shared_key):
			self.sent_unacked_shared_key = False
			self.server_valid_shared_key = False
			self.client_acked_shared_key = False

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


	def in_AGREEMENT(self, msg):
		pass

	def in_AGREEMENTEND(self):
		print("[AGREEMENDEND][time=%d::iter=%d]" % (time.time(), self.iters))
		assert(self.accepted_registration)
		assert(not self.accepted_authentication)

		self.out_CONFIRMAGREEMENT()
		self.out_LOGIN()


	def in_REGISTRATIONACCEPTED(self):
		print("[REGISTRATIONACCEPTED][time=%d::iter=%d]" % (time.time(), self.iters))

		## account did not exist and was created
		self.accepted_registration = True

		## trigger in_AGREEMENT{END}, second LOGIN there will trigger ACCEPTED
		self.out_LOGIN()

	def in_REGISTRATIONDENIED(self, msg):
		print("[REGISTRATIONDENIED][time=%d::iter=%d] %s" % (time.time(), self.iters, msg))

		self.rejected_registration = True


	def in_ACCEPTED(self, msg):
		print("[LOGINACCEPTED][time=%d::iter=%d]" % (time.time(), self.iters))

		## if we get here, everything checks out
		self.accepted_authentication = True

	def in_DENIED(self, msg):
		print("[DENIED][time=%d::iter=%d] %s" % (time.time(), self.iters, msg))

		## login denied, try to register first
		## nothing we can do if that also fails
		self.out_REGISTER()


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

	def in_CHANNELTOPIC(self, msg):
		print(msg)
	def in_BATTLECLOSED(self, msg):
		print(msg)
	def in_REMOVEUSER(self, msg):
		print(msg)
	def in_LEFTBATTLE(self, msg):
		print(msg)

	def in_PONG(self):
		diff = time.time() - self.lastping

		self.minping = min(diff, self.minping)
		self.maxping = max(diff, self.maxping)

		self.average = self.average + diff
		self.pingsamples = self.pingsamples + 1

		if (self.lastping != 0.0):
			print("[PONG] max=%0.3f min=%0.3f avg=%0.3f" % (self.maxping, self.minping, (self.average / self.pingsamples)))

		self.lastping = time.time()

	def in_JOIN(self, msg):
		print(msg)
	def in_CLIENTS(self, msg):
		print(msg)
	def in_JOINED(self, msg):
		print(msg)
	def in_LEFT(self, msg):
		print(msg)


	def Update(self):
		assert(self.host_socket != None)

		self.iters += 1

		## securely connect to server with existing or new account
		##   c:LOGIN -> {s:LOGACCEPT,s:LOGDENIED}
		##     if s:LOGACCEPT -> done
		##     if s:LOGDENIED -> c:REGISTER
		##     c:REGISTER -> {s:REGACCEPT,s:REGDENIED}
		##       if s:REGACCEPT -> c:LOGIN -> s:AGREEMENT -> (c:CONFAGREE, c:LOGIN) -> s:LOGACCEPT
		##       if s:REGDENIED -> exit
		if (self.client_acked_shared_key or (not self.want_secure_session)):
			if (not self.requested_authentication):
				self.out_LOGIN()

		## periodically re-negotiate the session key (every
		## 500*0.05=25.0s; models an ultra-paranoid client)
		if (self.client_acked_shared_key and self.want_secure_session and self.use_secure_session()):
			if ((self.iters % 500) == 0):
				self.reset_session_state()
				self.out_SETSHAREDKEY()

		if ((self.iters % 300) == 0):
			self.out_PING()

		threading._sleep(0.05)

		## eat through received data
		self.Recv()

	def Run(self, num_iters):
		while (self.iters < num_iters):
			self.Update()

		## say goodbye and close our socket
		self.out_EXIT()


def RunClients(num_clients, num_updates):
	clients = [None] * num_clients

	for i in xrange(num_clients):
		clients[i] = LobbyClient(HOST_SERVER, (CLIENT_NAME % i), (CLIENT_PWRD % i))

	for j in xrange(num_updates):
		for i in xrange(num_clients):
			clients[i].Update()

	for i in xrange(num_clients):
		clients[i].out_EXIT()


def RunClientThread(i, k):
	client = LobbyClient(HOST_SERVER, (CLIENT_NAME % i), (CLIENT_PWRD % i))

	print("[RunClientThread] running client %s" % client.username)
	client.Run(k)
	print("[RunClientThread] client %s finished" % client.username)

def RunClientThreads(num_clients, num_updates):
	threads = [None] * num_clients

	for i in xrange(num_clients):
		threads[i] = threading.Thread(target = RunClientThread, args = (i, num_updates, ))
		threads[i].start()
	for t in threads:
		t.join()


def main():
	if (not USE_THREADS):
		RunClients(NUM_CLIENTS, NUM_UPDATES)
	else:
		RunClientThreads(NUM_CLIENTS, NUM_UPDATES)

main()

