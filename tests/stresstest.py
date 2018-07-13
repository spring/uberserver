#!/usr/bin/env python3
# coding=utf-8
# This file is part of the uberserver (GPL v2 or later), see LICENSE

import socket, inspect
import time
import threading
import traceback
import random
import sys

from hashlib import md5

from base64 import b64decode as SAFE_DECODE_FUNC

import base64

NUM_CLIENTS = 1
NUM_UPDATES = 10000000
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

class LobbyClient:

	def __init__(self, server_addr, username, password):
		self.host_socket = None
		self.socket_data = ""

		self.username = username
		self.password = password
		self.password = base64.b64encode(md5(password.encode("utf-8")).digest()).decode("utf-8")
		assert(type(self.password) == str)

		self.OpenSocket(server_addr)
		self.Init()
		self.state = 0
		self.nextstep = random.randint(0, 200)
		self.users = {}
		self.battles = {}
		self.channels = {}
		self.battleid = 0
		self.running = True

	def OpenSocket(self, server_addr):
		while (self.host_socket == None):
			try:
				## non-blocking so we do not have to wait on server
				self.host_socket = socket.create_connection(server_addr, 5)
				self.host_socket.setblocking(0)
			except socket.error as msg:
				print("[OpenSocket] %s" % msg)
				## print(traceback.format_exc())
				time.sleep(0.5)

	def Init(self):
		self.prv_ping_time = time.time()
		self.num_ping_msgs =     0
		self.max_ping_time =   0.0
		self.min_ping_time = 100.0
		self.sum_ping_time =   0.0
		self.iters = 0

		self.data_send_queue = []

		self.server_info = ("", "", "", "")

		self.requested_registration   = False ## set on out_REGISTER
		self.requested_authentication = False ## set on out_LOGIN
		self.accepted_registration    = False ## set on in_REGISTRATIONACCEPTED
		self.rejected_registration    = False ## set on in_REGISTRATIONDENIED
		self.accepted_authentication  = False ## set on in_ACCEPTED

		self.out_LOGIN()


	def Send(self, data, batch = True):
		## test-client never tries to send unicode strings, so
		## we do not need to add encode(UNICODE_ENCODING) calls
		##
		## print("[Send][time=%d::iter=%d] data=\"%s\" queue=%s batch=%d" % (time.time(), self.iters, data, self.data_send_queue, batch))
		assert(type(data) == str)

		if (len(data) == 0):
			return

		self.host_socket.send(data.encode("utf-8") + b"\n")

	def Recv(self):
		num_received_bytes = len(self.socket_data)

		try:
			self.socket_data += self.host_socket.recv(4096).decode("utf-8")
		except BlockingIOError as e:
			if e.errno == 11: # Resource temporarily unavailable
				return
			raise(e)

		if (len(self.socket_data) == num_received_bytes):
			return

		split_data = self.socket_data.split("\n")
		data_blobs = split_data[: len(split_data) - 1  ]
		final_blob = split_data[  len(split_data) - 1: ][0]

		for raw_data_blob in data_blobs:
			if (len(raw_data_blob) == 0):
				continue

			## strips leading spaces and trailing carriage return
			self.Handle((raw_data_blob.rstrip('\r')).lstrip(' '))

		self.socket_data = final_blob

	def Handle(self, msg):
		## probably caused by trailing newline ("abc\n".split("\n") == ["abc", ""])
		if (len(msg) <= 1):
			return True

		assert(type(msg) == str)

		numspaces = msg.count(' ')

		if (numspaces > 0):
			command, args = msg.split(' ', 1)
		else:
			command = msg
			args = ""

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
		except Exception as e:
			print("Error handling: \"%s\" %s" % (msg, e))
			print(traceback.format_exc())
			return False


	def out_LOGIN(self):
		self.Send("LOGIN %s %s 0 *\tstresstester client\t0\tsp cl p" % (self.username, self.password))

		self.requested_authentication = True

	def out_REGISTER(self):
		print("[REGISTER][time=%d::iter=%d]" % (time.time(), self.iters))
		self.Send("REGISTER %s %s" % (self.username, self.password))
		self.requested_registration = True

	def out_CONFIRMAGREEMENT(self):
		print("[CONFIRMAGREEMENT][time=%d::iter=%d]" % (time.time(), self.iters))
		self.Send("CONFIRMAGREEMENT")


	def out_PING(self):
		#print("[PING][time=%d::iters=%d]" % (time.time(), self.iters))

		self.Send("PING")
	def out_JOIN(self, chan):
		self.Send("JOIN " + chan)
	def out_LEAVE(self, chan):
		self.Send("LEAVE " + chan)
	def out_SAY(self, chan, msg):
		self.Send("SAY %s %s" %(chan, msg))

	def out_EXIT(self):
		self.host_socket.close()

	def out_SAYPRIVATE(self, user, msg):
		self.Send("SAYPRIVATE %s %s" % (user, msg))

	def in_OPENBATTLE(self, msg):
		print("%s Created battle %d" %(self.username, int(msg)))
		self.battleid = int(msg)

	def in_REQUESTBATTLESTATUS(self, msg):
		pass

	def out_OPENBATTLE(self, type, natType, password, port, maxPlayers, gameHash, rank, mapHash, engineName, engineVersion, map, title, gameName):
		self.Send("OPENBATTLE %d %d %s %d %d %d %d %d %s\t%s\t%s\t%s\t%s" %
			(type, natType, password, port, maxPlayers, gameHash, rank, mapHash, engineName, engineVersion, map, title, gameName))

	def in_TASSERVER(self, protocolVersion, springVersion, udpPort, serverMode):
		#print("[TASSERVER][time=%d::iter=%d] proto=%s spring=%s udp=%s mode=%s" % (time.time(), self.iters, protocolVersion, springVersion, udpPort, serverMode))
		self.server_info = (protocolVersion, springVersion, udpPort, serverMode)

	def in_SERVERMSG(self, msg):
		print("[SERVERMSG][time=%d::iter=%d] %s" % (time.time(), self.iters, msg))


	def in_AGREEMENT(self, msg):
		pass

	def in_AGREEMENTEND(self):
		print("[AGREEMENDEND][time=%d::iter=%d]" % (time.time(), self.iters))
		#assert(self.accepted_registration)
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
		#print("[LOGINACCEPTED][time=%d::iter=%d]" % (time.time(), self.iters))

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
		user = msg.split(" ")
		self.users[user[0]] = user[1:]
	def in_BATTLEOPENED(self, msg):
		battle = msg.split(" ")
		battleid = int(battle[0])
		#print("BATTLEOPENED received %d %s" %(battleid, self.username))
		if battleid in self.battles:
			print("Inconsistence detected: BATTLEOPENED %d" %(battleid))
			print("Battles: " + str(self.battles))
			print(msg)
			print(self.username)
			sys.exit(1)
		self.battles[battleid] = battle[1:]
	def in_UPDATEBATTLEINFO(self, msg):
		#print(msg)
		pass
	def in_JOINBATTLE(self, msg):
		#print(msg)
		pass
	def in_JOINEDBATTLE(self, msg):
		#print(msg)
		pass
	def in_CLIENTSTATUS(self, msg):
		pass
	def in_LOGININFOEND(self):
		## do stuff here (e.g. "JOIN channel")
		pass
	def in_CHANNELTOPIC(self, msg):
		print("CHANNELTOPIC %s"%msg)
	def in_BATTLECLOSED(self, msg):
		battleid = int(msg)
		#print("BATTLECLOSED received %d %s" %(battleid, self.username))
		try:
			del self.battles[battleid]
		except:
			print("Inconsistence detected: BATTLECLOSED " + str(battleid))
			print("Battles: " + str(self.battles))
			print(self.username)
			sys.exit(1)
	def in_REMOVEUSER(self, msg):
		print("REMOVEUSER %s" % msg)
	def in_LEFTBATTLE(self, msg):
		print("LEFTBATTLE %s" % msg)

	def in_PONG(self):
		diff = time.time() - self.prv_ping_time

		self.min_ping_time = min(diff, self.min_ping_time)
		self.max_ping_time = max(diff, self.max_ping_time)
		self.sum_ping_time += diff
		self.num_ping_msgs += 1

		if (False and self.prv_ping_time != 0.0):
			print("[PONG] max=%0.3fs min=%0.3fs avg=%0.3fs" % (self.max_ping_time, self.min_ping_time, (self.sum_ping_time / self.num_ping_msgs)))

		self.prv_ping_time = time.time()

	def in_JOIN(self, msg):
		print("JOIN %s" % msg)
	def in_CLIENTS(self, msg):
		print("CLIENTS %s"% msg)
	def in_JOINED(self, msg):
		print("JOINED %s"% msg)
	def in_LEFT(self, msg):
		print("LEFT %s" % msg)
	def in_SAID(self, msg):
		print("SAID %s" %msg)
	def in_SAIDPRIVATE(self, msg):
		user, msg = msg.split(" ")
		self.out_SAYPRIVATE(user,"You said: " + msg)

	def in_SAYPRIVATE(self, msg):
		print("SAYPRIVATE " +  msg)
	def in_OPENBATTLEFAILED(self, msg):
		pass
	def in_CLIENTBATTLESTATUS(self, msg):
		print("CLIENTBATTLESTATUS " +msg)
	def in_FAILED(self, msg):
		print("FAILED " + msg)

	def JoinBattle(self): # open or join a battle
		#print(self.username + " is trying to create a battle...")
		self.out_OPENBATTLE(0, 0, '*', 1234, 10, 0x1234, 0, 0x1234, "spring", "103.0", "DeltaSiegeDry", "Game %d" %(self.iters), "Balanced Annihilation V9.54")
	def PlayInBattle(self): # start game or wait till game start
		pass
	def LeaveBattle(self): # leave battle
		pass
	def JoinChannel(self): # join channel
		self.out_JOIN("sy")
	def LeaveChannel(self): # leave channel
		self.out_LEAVE("sy")

	def Say(self):
		self.out_SAY("sy", "Hello World no. %d" %(self.iters))
	def Update(self):
		assert(self.host_socket != None)

		self.iters += 1

		if ((self.iters % 10) == 0):
			self.out_PING()


		if (self.iters > self.nextstep):
			self.nextstep = self.iters + random.randint(0, 800)
			self.state += 1
			
			if self.state == 1:
				self.JoinBattle()
			elif self.state == 2:
				self.PlayInBattle()
			elif self.state == 3:
				self.LeaveBattle()
			elif self.state == 4:
				self.JoinChannel()
			elif self.state == 5:
				self.Say()
			elif self.state == 6:
				self.LeaveChannel()
			else:
				self.state = 0
			#elif self.state == 5: # exit
			#	self.running = False


		## eat through received data
		self.Recv()

	def Run(self, iters):
		while (self.running):
			self.Update()

		## say goodbye and close our socket
		self.out_EXIT()


def RunClients(num_clients, num_updates):
	clients = [None] * num_clients

	for i in range(num_clients):
		clients[i] = LobbyClient(HOST_SERVER, (CLIENT_NAME % i), (CLIENT_PWRD % i))

	for j in range(num_updates):
		for i in range(num_clients):
			clients[i].Update()
		time.sleep(0.05)

	for i in range(num_clients):
		clients[i].out_EXIT()



def RunClientThread(i, k):
	client = LobbyClient(HOST_SERVER, (CLIENT_NAME % i), (CLIENT_PWRD % i))

	print("[RunClientThread] running client %s" % client.username)
	client.Run(k)
	print("[RunClientThread] client %s finished" % client.username)

def RunClientThreads(num_clients, num_updates):
	threads = [None] * num_clients

	for i in range(num_clients):
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

