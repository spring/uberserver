#!/usr/bin/env python
# coding=utf-8

import inspect, time, re, threading

import traceback, sys, os
import socket
import Channel
import Battle

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))

import CryptoHandler

from CryptoHandler import MD5LEG_HASH_FUNC as LEGACY_HASH_FUNC
from CryptoHandler import SHA256_HASH_FUNC as SECURE_HASH_FUNC

from CryptoHandler import safe_decode as SAFE_DECODE_FUNC
from CryptoHandler import UNICODE_ENCODING

from base64 import b64encode as ENCODE_FUNC
from base64 import b64decode as DECODE_FUNC



# see http://springrts.com/dl/LobbyProtocol/ProtocolDescription.html#MYSTATUS:client
# max. 8 ranks are possible (rank 0 isn't listed)
# rank, ingame time in hours
ranks = (5, 15, 30, 100, 300, 1000, 3000)

restricted = {
'disabled':set(),
'everyone':set([
	'EXIT',
	'PING',
	'LISTCOMPFLAGS',

	## encryption
	'GETPUBLICKEY',
	'GETSIGNEDMSG',
	'SETSHAREDKEY',
	'ACKSHAREDKEY',
	]),
'fresh':set([
	'LOGIN',
	'REGISTER'
	]),
'agreement':set([
	'CONFIRMAGREEMENT'
	]),
'user':set([
	########
	# battle
	'ADDBOT',
	'ADDSTARTRECT',
	'CHANGEEMAIL',
	'DISABLEUNITS',
	'ENABLEUNITS',
	'ENABLEALLUNITS',
	'FORCEALLYNO',
	'FORCESPECTATORMODE',
	'FORCETEAMCOLOR',
	'FORCETEAMNO',
	'FORCEJOINBATTLE',
	'FORCELEAVECHANNEL',
	'HANDICAP',
	'JOINBATTLE',
	'JOINBATTLEACCEPT',
	'JOINBATTLEDENY',
	'KICKFROMBATTLE',
	'LEAVEBATTLE',
	'MYBATTLESTATUS',
	'OPENBATTLE',
	'REMOVEBOT',
	'REMOVESCRIPTTAGS',
	'REMOVESTARTRECT',
	'RING',
	'SAYBATTLE',
	'SAYBATTLEEX',
	'SAYBATTLEPRIVATE',
	'SAYBATTLEPRIVATEEX',
	'SETSCRIPTTAGS',
	'UPDATEBATTLEINFO',
	'UPDATEBOT',
	#########
	# channel
	'CHANNELMESSAGE',
	'CHANNELS',
	'CHANNELTOPIC',
	'JOIN',
	'LEAVE',
	'MUTE',
	'MUTELIST',
	'SAY',
	'SAYEX',
	'SAYPRIVATE',
	'SAYPRIVATEEX',
	'SETCHANNELKEY',
	'UNMUTE',
	########
	# ignore
	'IGNORE',
	'UNIGNORE',
	'IGNORELIST',
	########
	# friend
	'FRIENDREQUEST',
	'ACCEPTFRIENDREQUEST',
	'DECLINEFRIENDREQUEST',
	'UNFRIEND',
	'FRIENDLIST',
	'FRIENDREQUESTLIST',
	########
	# channel subscriptions
	'SUBSCRIBE',
	'UNSUBSCRIBE',
	'LISTSUBSCRIPTIONS',
	########
	# meta
	'CHANGEPASSWORD',
	'GETINGAMETIME',
	'GETREGISTRATIONDATE',
	'MYSTATUS',
	'PORTTEST',
	'RENAMEACCOUNT',
	]),
'mod':set([
	'BAN',
	'BANIP',
	'UNBAN',
	'UNBANIP',
	'BANLIST',
	'CHANGEACCOUNTPASS',
	'KICKUSER',
	'FINDIP',
	'GETIP',
	'GETLASTLOGINTIME',
	'GETUSERID',
	'SETBOTMODE',
	'GETLOBBYVERSION',
	]),
'admin':set([
	#########
	# server
	'ADMINBROADCAST',
	'BROADCAST',
	'BROADCASTEX',
	'RELOAD',
	'CLEANUP',
	'SETLATESTSPRINGVERSION',
	#########
	# users
	'GETLASTLOGINTIME',
	'GETACCOUNTACCESS',
	'FORCEJOIN',
	'SETACCESS',
	]),
}

restricted_list = set()
for level in restricted:
	for cmd in restricted[level]:
		restricted_list.add(cmd)

ipRegex = r"^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$"
re_ip = re.compile(ipRegex)

def validateIP(ipAddress):
	return re_ip.match(ipAddress)

def int32(x):
	val = int(x)
	if val >  2147483647 : raise OverflowError
	if val < -2147483648 : raise OverflowError
	return val

def uint32(x):
	val = int(x)
	if val > 4294967296 : raise OverflowError
	if val < 0 : raise OverflowError
	return val

flag_map = {
	'a': 'accountIDs',       # send account IDs in ADDUSER
	'b': 'battleAuth',       # JOINBATTLEREQUEST/ACCEPT/DENY
	'sp': 'scriptPassword',  # scriptPassword in JOINEDBATTLE
	'et': 'sendEmptyTopic',  # send NOCHANNELTOPIC on join if channel has no topic
	'm': 'matchmaking',      # FORCEJOINBATTLE from battle hosts for matchmaking
	'cl': 'cleanupBattles',  # BATTLEOPENED / OPENBATTLE with support for engine/version
	'p':  'agreementPlain',  # AGREEMENT is plaintext
	'o': 'offlineChat',      # offline support for SAID/SAIDEX
}

class Protocol:
	def __init__(self, root):
		self._root = root
		self.userdb = root.getUserDB()
		self.SayHooks = root.SayHooks
		self.stats = {}

		## generates new keys if directory is empty, otherwise imports
		self.rsa_cipher_obj = CryptoHandler.rsa_cipher(root.crypto_key_dir)
		## no-op if keys are already present, otherwise just speeds up
		## server restarts (clients should NEVER cache the public key!)
		self.rsa_cipher_obj.export_keys(root.crypto_key_dir)

	def force_secure_auths(self): return (self._root.force_secure_client_auths)
	def force_secure_comms(self): return (self._root.force_secure_client_comms)
	def use_msg_auth_codes(self): return (self._root.use_message_authent_codes)

	def _new(self, client):
		login_string = ' '.join((self._root.server, str(self._root.server_version), self._root.latestspringversion, str(self._root.natport), '0'))
		if self._root.redirect:
			login_string += "\nREDIRECT " + self._root.redirect

		client.Send(login_string)

		if self._root.redirect:
			# this will make the server not accepting any commands
			# the client will be disconnected with "Connection timed out, didn't login"
			client.removing = True
		self._root.console_write('[%s] Client connected from %s:%s' % (client.session_id, client.ip_address, client.port))

	def _remove(self, client, reason='Quit'):
		if client.static: return # static clients don't disconnect
		self._root.console_write('[%s] disconnected from %s: %s'%(client.session_id, client.ip_address, reason))
		if not client.username in self._root.usernames: # client didn't full login
			return

		user = client.username
		del self._root.usernames[user]
		if client.db_id in self._root.db_ids:
			del self._root.db_ids[client.db_id]

		for chan in client.channels.copy():
			channel = self._root.channels[chan]
			self.in_LEAVE(client, chan, reason)

		if client.current_battle:
			self.in_LEAVEBATTLE(client)

		self.broadcast_RemoveUser(client)
		try:
			self.userdb.end_session(client.db_id)
		except Exception as e:
			self._root.console_write('[%s] <%s> Error writing to db in _remove: %s '%(client.session_id, client.username, e.message))



	def get_function_args(self, client, command, function, numspaces, args):
		function_info = inspect.getargspec(function)
		total_args = len(function_info[0]) - 2

		# if there are no arguments, just call the function
		# with client as its only arg: *([client]) = client
		if (total_args <= 0):
			return True, []

		# check for optional arguments
		optional_args = 0
		if function_info[3]:
			optional_args = len(function_info[3])

		# check if we've got enough words for filling the required args
		required_args = total_args - optional_args

		if (numspaces < required_args):
			self.out_SERVERMSG(client, '%s failed. Incorrect arguments.' % command)
			return False, []
		if (required_args == 0 and numspaces == 0):
			return True, []

		# bunch the last words together if there are too many of them
		if (numspaces > (total_args - 1)):
			arguments = args.split(' ', total_args - 1)
		else:
			arguments = args.split(' ')

		return True, arguments


	def _handle(self, client, msg):
		try:
			## protocol operates on unicode strings internally; this is
			## somewhat undesirable because it needs to be undone in the
			## SETSHAREDKEY and GETSIGNEDMSG handlers
			## message should not contain non-ASCII bytes since protocol
			## is specified as text-only, so decoding it *should* always
			## succeed
			msg = msg.decode(UNICODE_ENCODING)
		except:
			if (not client.use_secure_session()):
				out = "Invalid unicode-encoding received (should be %s), skipped message %s"
				err = ":".join("{:02x}".format(ord(c)) for c in msg)
				self.out_SERVERMSG(client, out % (UNICODE_ENCODING, err), True)
			return False

			
		# client.Send() prepends client.msg_id if the current thread
		# is the same thread as the client's handler.
		# this works because handling is done in order for each ClientHandler thread
		# so we can be sure client.Send() was performed in the client's own handling code.
		msg = client.set_msg_id(msg)
		numspaces = msg.count(' ')

		if (numspaces > 0):
			command, args = msg.split(' ', 1)
		else:
			args = None
			command = msg

		command = command.upper()
		allowed = False

		for level in client.accesslevels:
			if command in restricted[level]:
				allowed = True
				break

		if (not allowed):
			## do not leak information in secure context
			if (not client.use_secure_session()):
				if not command in restricted_list:
					self.out_SERVERMSG(client, '%s failed. Command does not exist.' % command, True)
				else:
					self.out_SERVERMSG(client, '%s failed. Insufficient rights.' % command, True)
			return False

		function = getattr(self, 'in_' + command)

		# update statistics
		if (not (command in self.stats)):
			self.stats[command] = 0
		self.stats[command] += 1


		ret_status, fun_args = self.get_function_args(client, command, function, numspaces, args)

		if (ret_status):
			## if fun_args is empty, this reduces to function(client)
			function(*([client] + fun_args))


		# TODO: check the exception line... if it's "function(*([client] + fun_args))"
		# then it was incorrect arguments. if not, log the error, as it was a code problem
		#try:
		#	function(*([client] + fun_args))
		#except TypeError:
		#	self.out_SERVERMSG(client, '%s failed. Incorrect arguments.'%command.partition('in_')[2])
		return True


	def _bin2dec(self, s):
		return int(s, 2)

	def _dec2bin(self, i, bits=None):
		i = int(i)
		b = ''
		while i > 0:
			j = i & 1
			b = str(j) + b
			i >>= 1
		if bits:
			b = b.rjust(bits,'0')
		return b

	def _udp_packet(self, username, ip, udpport):
		if username in self._root.usernames:
			client = self._root.usernames[username]
			if ip == client.local_ip or ip == client.ip_address:
				client.Send('UDPSOURCEPORT %i'%udpport)
				battle_id = client.current_battle
				if not battle_id in self._root.battles: return
				battle = self._root.battles[battle_id]
				if battle:
					client.udpport = udpport
					client.hostport = udpport
					host = battle.host
					if not host == client.session_id:
						self._root.usernames[host].SendBattle(battle, 'CLIENTIPPORT %s %s %s'%(username, ip, udpport))
				else:
					client.udpport = udpport
			else:
				self._root.admin_broadcast('NAT spoof from %s pretending to be <%s>'%(ip,username))

	def _calc_access_status(self, client):
		self._calc_access(client)
		self._calc_status(client, client.status)

	def _calc_access(self, client):
		userlevel = client.access
		inherit = {'mod':['user'], 'admin':['mod', 'user']}

		if userlevel in inherit:
			inherited = inherit[userlevel]
		else:
			inherited = [userlevel]
		if not client.access in inherited: inherited.append(client.access)
		client.accesslevels = inherited+['everyone']

	def _calc_status(self, client, _status):
		status = self._dec2bin(_status, 7)
		bot, access, rank1, rank2, rank3, away, ingame = status[-7:]
		rank1, rank2, rank3 = self._dec2bin(6, 3)
		accesslist = {'user':0, 'mod':1, 'admin':1}
		access = client.access
		if access in accesslist:
			access = accesslist[access]
		else:
			access = 0
		bot = int(client.bot)
		ingame_time = int(client.ingame_time)/60 # hours

		rank = 0
		for t in ranks:
			if ingame_time >= t:
				rank += 1
		rank1 = 0
		rank2 = 0
		rank3 = 0
		try:
			rank1, rank2, rank3 = self._dec2bin(rank, 3)
		except:
			self.out_SERVERMSG(client, "invalid status: %s: %s, decoded: %s" %(_status,rank, status), True)
		client.is_ingame = (ingame == '1')
		client.away = (away == '1')
		status = self._bin2dec('%s%s%s%s%s%s%s'%(bot, access, rank1, rank2, rank3, away, ingame))
		client.status = status

	def _calc_battlestatus(self, client):
		battlestatus = client.battlestatus
		status = self._bin2dec('0000%s%s0000%s%s%s%s%s0'%(battlestatus['side'],
								battlestatus['sync'], battlestatus['handicap'],
								battlestatus['mode'], battlestatus['ally'],
								battlestatus['id'], battlestatus['ready']))
		return status

	def _new_channel(self, chan, **kwargs):
		# any updates to channels from the SQL database from a web interface
		# would possibly need to call a RELOAD-type function
		# unless we want to do way more SQL lookups for channel info
		try:
			if not kwargs: raise KeyError
			channel = Channel.Channel(self._root, chan, **kwargs)
		except: channel = Channel.Channel(self._root, chan)
		return channel

	def _time_format(self, seconds):
		'given a duration in seconds, returns a human-readable relative time'
		minutesleft = float(seconds) / 60
		hoursleft = minutesleft / 60
		daysleft = hoursleft / 24
		if daysleft > 7:
			message = '%0.2f weeks' % (daysleft / 7)
		elif daysleft == 7:
			message = 'a week'
		elif daysleft > 1:
			message = '%0.2f days' % daysleft
		elif daysleft == 1:
			message = 'a day'
		elif hoursleft > 1:
			message = '%0.2f hours' % hoursleft
		elif hoursleft == 1:
			message = 'an hour'
		elif minutesleft > 1:
			message = '%0.1f minutes' % minutesleft
		elif minutesleft == 1:
			message = 'a minute'
		else:
			message = '%0.0f second(s)'%(float(seconds))
		return message

	def _time_until(self, timestamp):
		'given a future timestamp, as returned by time.time(), returns a human-readable relative time'
		now = time.time()
		seconds = timestamp - now
		if seconds <= 0:
			return 'forever'
		return self._time_format(seconds)

	def _time_since(self, timestamp):
		'given a past timestamp, as returned by time.time(), returns a readable relative time as a string'
		seconds = time.time() - timestamp
		return self._time_format(seconds)

	def _get_motd_string(self, client):
		motd_string = ""
		replace_vars = {
			"{USERNAME}": str(client.username),
			"{CLIENTS}" : str(len(self._root.clients)),
			"{CHANNELS}": str(len(self._root.channels)),
			"{BATTLES}" : str(len(self._root.battles)),
			"{UPTIME}"  : str(self._time_since(self._root.start_time))
		}

		if (self._root.motd):
			for line in self._root.motd:
				for key, value in replace_vars.iteritems():
					line = line.replace(key, value)

				motd_string += line
				motd_string += '\n'
		else:
			motd_string += "[MOTD]"

		return motd_string

	def _sendMotd(self, client, motd_string):
		'send the message of the day to client'
		motd_lines = motd_string.split('\n')

		for line in motd_lines:
			client.RealSend('MOTD %s' % line)

	def _checkCompat(self, client):
		missing_flags = ""
		'check the compatibility flags of client and report possible/upcoming problems to it'
		if not client.compat['sp']: # blocks protocol increase to 0.37
			client.RealSend("MOTD Your client doesn't support the 'sp' compatibility flag, please upgrade it!")
			client.RealSend("MOTD see http://springrts.com/dl/LobbyProtocol/ProtocolDescription.html#0.36")
			missing_flags += ' sp'
		if not client.compat['cl']: # cl should be used (bugfixed version of eb)
			client.RealSend("MOTD Your client doesn't support the 'cl' compatibility flag, please upgrade it!")
			client.RealSend("MOTD see http://springrts.com/dl/LobbyProtocol/ProtocolDescription.html#0.37")
			missing_flags += ' cl'
		if not client.compat['p']:
			client.RealSend("MOTD Your client doesn't support the 'p' compatibility flag, please upgrade it!")
			client.RealSend("MOTD see htpp://springrts.com/dl/LobbyProtocol/ProtocolDescription.html#0.37")
			missing_flags += ' p'
		if len(missing_flags) > 0:
			self._root.console_write('[%s] <%s> client "%s" missing compat flags:%s'%(client.session_id, client.username, client.lobby_id, missing_flags))



	def _validLegacyPasswordSyntax(self, password):
		'checks if an old-style password is correctly encoded'
		if (not password):
			return False, 'Empty passwords are not allowed.'

		## must be checked here too (not just in _validPasswordSyntax)
		## because both CHANGEACCOUNTPASS and TESTLOGIN might call us
		assert(type(password) == unicode)

		pwrd_hash_enc = password.encode(UNICODE_ENCODING)
		pwrd_hash_raw = SAFE_DECODE_FUNC(pwrd_hash_enc)

		if (pwrd_hash_enc == pwrd_hash_raw):
			return False, "Invalid base64-encoding."
		if (len(pwrd_hash_raw) != len(LEGACY_HASH_FUNC("").digest())):
			return False, "Invalid MD5-checksum."

		## assume (!) this is a valid legacy-hash checksum
		return True, ""

	## since new-style passwords are generously salted, we
	## require only a few characters and do not check their
	## entropy (strength)
	def _validSecurePasswordSyntax(self, password):
		assert(type(password) == unicode)

		## strip off the base64-encoding and check for illegal chars
		enc_password = password.encode(UNICODE_ENCODING)
		dec_password = SAFE_DECODE_FUNC(enc_password)

		if (dec_password == enc_password):
			return False, "Invalid base64-encoding."
		if (dec_password.count(" ") != 0):
			return False, "Password contains one or more WS characters."
		if (dec_password.count("\t") != 0):
			return False, "Password contains one or more WS characters."
		if (dec_password.count("\n") != 0):
			return False, "Password contains one or more LF characters."
		if (dec_password.count("\r") != 0):
			return False, "Password contains one or more CR characters."
		if (len(dec_password) < CryptoHandler.MIN_PASSWORD_LEN):
			return False, ("Password too short: %d or more characters required." % CryptoHandler.MIN_PASSWORD_LEN)

		return True, ""


	def _validPasswordSyntax(self, client, password):
		assert(type(password) == unicode)

		if (not password):
			return False, "Empty password."

		if (client.use_secure_session()):
			return (self._validSecurePasswordSyntax(password))
		else:
			return (self._validLegacyPasswordSyntax(password))



	def _validUsernameSyntax(self, username):
		'checks if usernames syntax is correct / doesn''t contain invalid chars'
		if not username:
			return False, 'Invalid username.'
		for char in username:
			if not char.lower() in 'abcdefghijklmnopqrstuvwzyx[]_1234567890':
				return False, 'Only ASCII chars, [], _, 0-9 are allowed in usernames.'
		if len(username) > 20:
			return False, 'Username is too long, max is 20 chars.'
		return True, ""

	def _validChannelSyntax(self, channel):
		'checks if usernames syntax is correct / doesn''t contain invalid chars'
		for char in channel:
			if not char.lower() in 'abcdefghijklmnopqrstuvwzyx[]_1234567890':
				return False, 'Only ASCII chars, [], _, 0-9 are allowed in channel names.'
		if len(channel) > 20:
			return False, 'Channelname is too long, max is 20 chars.'
		return True, ""



	def _parseTags(self, tagstring):
		'parses tags to a dict, for example user=bla\tcolor=123'
		tags = {}
		for tagpair in tagstring.split('\t'):
			if not '=' in tagpair:
				continue # this fails; tag isn't split by anything
			(tag, value) = tagpair.split('=',1)
			tags.update({tag:value})
		return tags

	def _dictToTags(self, dictionary):
		res = ""
		for key in dictionary:
			if res:
				res += "\t"
			res += key + "=" + dictionary[key]
		return res

	def _canForceBattle(self, client, username = None):
		' returns true when client can force sth. to a battle / username in current battle (=client is host & username is in battle)'
		battle_id = client.current_battle
		if not battle_id in self._root.battles:
			return False
		battle = self._root.battles[battle_id]
		if not client.session_id == battle.host:
			return False
		if username == None:
			return True
		if client.session_id in battle.users:
			return True
		return False

	def _informErrors(self, client):
		if client.lobby_id in ("SpringLobby 0.188 (win x32)", "SpringLobby 0.200 (win x32)"):
			client.Send("SAYPRIVATE ChanServ The autoupdater of SpringLobby 0.188 is broken, please manually update: http://springrts.com/phpbb/viewtopic.php?f=64&t=31224")
	def _getNextBattleId(self):
		self._root.nextbattle += 1 #FIXME: handle overflow (int32)
		id = self._root.nextbattle
		return id

	def clientFromID(self, db_id, fromdb = False):
		'given a user database id, returns a client object from memory or the database'
		assert(isinstance(db_id, int))
		user = self._root.clientFromID(db_id)
		if user: return user
		if not fromdb: return None
		return self.userdb.clientFromID(db_id)

	def clientFromSession(self, session_id):
		assert(isinstance(session_id, int))
		if session_id in self._root.clients:
			return self._root.clients[session_id]
		return None

	def clientFromUsername(self, username, fromdb = False):
		'given a username, returns a client object from memory or the database'
		client = self._root.clientFromUsername(username)
		if fromdb and not client:
			client = self.userdb.clientFromUsername(username)
			if client:
				client.db_id = client.id
				self._calc_access(client)
		return client

	def broadcast_AddBattle(self, battle):
		for client in self._root.usernames.itervalues():
			client.Send(self.client_AddBattle(client, battle))

	def broadcast_RemoveBattle(self, battle):
		for client in self._root.usernames.itervalues():
			client.Send('BATTLECLOSED %s' % battle.id)

	# the sourceClient is only sent for SAY*, and RING commands
	def broadcast_SendBattle(self, battle, data, sourceClient=None):
		for session_id in battle.users:
			client = self.clientFromSession(session_id)
			if sourceClient == None or not sourceClient.db_id in client.ignored:
				client.Send(data)

	def broadcast_AddUser(self, client):
		for name, receiver in self._root.usernames.iteritems():
			if client.session_id == receiver.session_id: # don't send ADDUSER to self
				continue
			receiver.Send(self.client_AddUser(receiver, client))

	def broadcast_RemoveUser(self, client):
		for name, receiver in self._root.usernames.iteritems():
			if not name == client.username:
				self.client_RemoveUser(receiver, client)

	def client_AddUser(self, receiver, user):
		'sends the protocol for adding a user'
		if receiver.compat['a']: #accountIDs
			return 'ADDUSER %s %s %s %s' % (user.username, user.country_code, user.cpu, user.db_id)
		else:
			return 'ADDUSER %s %s %s' % (user.username, user.country_code, user.cpu)

	def client_RemoveUser(self, client, user):
		'sends the protocol for removing a user'
		client.Send('REMOVEUSER %s' % user.username)

	def client_AddBattle(self, client, battle):
		'sends the protocol for adding a battle'
		ubattle = battle.copy()

		host = self._root.clients[battle.host]
		if host.ip_address == client.ip_address: # translates the ip to always be compatible with the client
			translated_ip = host.local_ip
		else:
			translated_ip = host.ip_address

		ubattle.update({'ip':translated_ip})
		ubattle['host'] = host.username # session_id -> username
		if client.compat['cl']: #supports cleanupBattles
			return 'BATTLEOPENED %(id)s %(type)s %(natType)s %(host)s %(ip)s %(port)s %(maxplayers)s %(passworded)s %(rank)s %(maphash)s %(engine)s\t%(version)s\t%(map)s\t%(title)s\t%(modname)s' % ubattle

		# give client without version support a hint, that this battle is incompatible to his version
		if not (battle.engine == 'spring' and (battle.version == self._root.latestspringversion or battle.version == self._root.latestspringversion + '.0')):
			ubattle['title'] = 'Incompatible (%(engine)s %(version)s) %(title)s' % ubattle
		return 'BATTLEOPENED %(id)s %(type)s %(natType)s %(host)s %(ip)s %(port)s %(maxplayers)s %(passworded)s %(rank)s %(maphash)s %(map)s\t%(title)s\t%(modname)s' % ubattle

	def is_ignored(self, client, ignoredClient):
		# verify that this is an online client (only those have an .ignored attr)
		if hasattr(client, "ignored"):
			return ignoredClient.db_id in client.ignored
		else:
			return self.userdb.is_ignored(client.db_id, ignoredClient.db_id)

	def ignore_user(self, client, ignoreClient, reason=None):
		self.userdb.ignore_user(client.db_id, ignoreClient.db_id, reason)
		client.ignored[ignoreClient.db_id] = True

	def unignore_user(self, client, unignoreClient):
		self.userdb.unignore_user(client.db_id, unignoreClient.db_id)
		client.ignored.pop(unignoreClient.db_id)


	def can_client_authenticate(self, client, username, in_login):
		if ((not client.use_secure_session()) and (self.force_secure_auths() or self.force_secure_comms())):
			if (in_login):
				self.out_DENIED(client, username, "Unencrypted logins are not allowed.")
			else:
				client.Send("REGISTRATIONDENIED %s" % ("Unencrypted registrations are not allowed."))

			return False

		if (client.use_secure_session() and (not client.get_session_key_received_ack())):
			if (in_login):
				self.out_DENIED(client, username, "Encrypted logins without prior key-acknowledgement are not allowed.")
			else:
				client.Send("REGISTRATIONDENIED %s" % ("Encrypted registrations without prior key-acknowledgement are not allowed."))

			return False

		return True



	# Begin incoming protocol section #
	#
	# any function definition beginning with in_ and ending with capital letters
	# is a definition of an incoming command.
	#
	# any text arguments passed by the client are automatically split and passed to the method
	# keyword arguments are treated as optional
	# this is done in the _handle() method above
	#
	# example (note, this is not the actual in_SAY method used in the server):
	#
	# def in_SAY(self, client, channel, message=None):
	#     if message:
	#         sendToChannel(channel, message)
	#     else:
	#         sendToChannel(channel, "I'm too cool to send a message")
	#
	# if the client sends "SAY foo bar", the server calls in_SAY(client, "foo", "bar")
	# if the client sends "SAY foo", the server will call in_SAY(client, "foo")
	#
	# however, if the client sends "SAY",
	# the server will notice the client didn't send enough text to fill the arguments
	# and return an error message to the client

	def in_PING(self, client, reply=None):
		'''
		Tell the server you are in fact still connected.
		The server will reply with PONG, useful for testing latency.

		@optional.str reply: Reply to send client
		'''
		if reply:
			client.Send('PONG %s'%reply)
		else:
			client.Send('PONG')

	def in_PORTTEST(self, client, port):
		'''
		Connect to client on specified UDP port and send the string 'Port testing...'


		@required.int port: UDP port to connect to for port testing
		'''
		host = client.ip_address
		port = int(port)
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.sendto('Port testing...', (host, port))


	def in_REGISTER(self, client, username, password):
		'''
		Register a new user in the account database.

		@required.str username: Username to register
		@required.str password: Password to use (old-style: BASE64(MD5(PWRD)), new-style: BASE64(PWRD))
		'''
		assert(type(password) == unicode)

		if (not self.can_client_authenticate(client, username, False)):
			return

		good, reason = self._validUsernameSyntax(username)

		if (not good):
			client.Send("REGISTRATIONDENIED %s" % (reason))
			return

		## test if password is well-formed
		good, reason = self._validPasswordSyntax(client, password)

		if (not good):
			client.Send("REGISTRATIONDENIED %s" % (reason))
			return


		if (client.use_secure_session()):
			good, reason = self.userdb.secure_register_user(username, password, client.ip_address, client.country_code)
		else:
			good, reason = self.userdb.legacy_register_user(username, password, client.ip_address, client.country_code)

		if (good):
			self._root.console_write('[%s] Successfully registered user <%s>.' % (client.session_id, username))

			client.Send('REGISTRATIONACCEPTED')

			newClient = self.clientFromUsername(username, True)
			newClient.access = 'agreement'
		else:
			self._root.console_write('[%s] Registration failed for user <%s>.' % (client.session_id, username))
			client.Send('REGISTRATIONDENIED %s' % reason)


	def in_LOGIN(self, client, username, password='', cpu='0', local_ip='', sentence_args=''):
		'''
		Attempt to login the active client.

		@required.str username: Username
		@required.str password: Password (old-style: BASE64(MD5(PWRD)), new-style: BASE64(PWRD))
		@optional.int cpu: CPU speed
		@optional.ip local_ip: LAN IP address, sent to clients when they have the same WAN IP as host
		@optional.sentence.str lobby_id: Lobby name and version
		@optional.sentence.int user_id: User ID provided by lobby
		@optional.sentence.str compat_flags: Compatibility flags, sent in space-separated form, as follows:

		flag: description
		-----------------
		a: Send account IDs as an additional parameter to ADDUSER. Account IDs persist across renames.
		b: If client is hosting a battle, prompts them with JOINBATTLEREQUEST when a user tries to join their battle
		sp: If client is hosting a battle, sends them other clients' script passwords as an additional argument to JOINEDBATTLE.
		et: When client joins a channel, sends NOCHANNELTOPIC if the channel has no topic.
		'''
		assert(type(password) == unicode)

		if (not self.can_client_authenticate(client, username, True)):
			return


		good, reason = self._validUsernameSyntax(username)

		if (not good):
			self.out_DENIED(client, username, reason)
			return

		try: int32(cpu)
		except: cpu = '0'

		user_id = 0
		## represents <client> after logging in
		user_or_error = None


		if not validateIP(local_ip):
			local_ip = client.ip_address

		if '\t' in sentence_args:
			lobby_id, user_id = sentence_args.split('\t',1)
			if '\t' in user_id:
				user_id, compFlags = user_id.split('\t', 1)

				flags = set()

				for flag in compFlags.split(' '):
					if flag in ('ab', 'ba'):
						flags.add('a')
						flags.add('b')
					else:
						flags.add(flag)

				unsupported = ""
				for flag in flags:
					client.compat[flag] = True
					if not flag in flag_map:
						unsupported +=  (" " + flag)

				if (len(unsupported) > 0):
					self.out_SERVERMSG(client, 'Unsupported/unknown compatibility flag(s) in LOGIN: %s' % (unsupported), True)
			try:
				client.last_id = uint32(user_id)
			except:
				self.out_SERVERMSG(client, 'Invalid userID specified: %s' % (user_id), True)
		else:
			lobby_id = sentence_args


		try:
			## no longer test if password is well-formed here
			## (the DB checks are sufficient and it allows an
			## old-style password to be converted seamlessly)
			if (client.use_secure_session()):
				good, user_or_error = self.userdb.secure_login_user(username, password, client.ip_address, lobby_id, user_id, cpu, local_ip, client.country_code)
			else:
				good, user_or_error = self.userdb.legacy_login_user(username, password, client.ip_address, lobby_id, user_id, cpu, local_ip, client.country_code)
		except Exception as e:
			self._root.console_write('[%s] <%s> Error reading from DB in in_LOGIN: %s ' % (client.session_id, client.username, e.message))
			## in this case DB return values are undefined
			good = False
			reason = "DB error"

		if (not good):
			if (type(user_or_error) == str):
				reason = user_or_error

			self.out_DENIED(client, username, reason)
			return

		if (client.failed_logins > 2):
			self.out_DENIED(client, username, "Too many failed logins.")
			return

		assert(user_or_error != None)
		assert(type(user_or_error) != str)

		# needs to be checked directly before it is added, to make it somelike atomic as we have no locking over threads
		if (username in self._root.usernames):
			self.out_DENIED(client, username, 'Already logged in.', False)
			return
		client.isloggingin = True
		client.buffersend = True # enqeue all sends to client made from other threads until server state is send
		#assert(not client.db_id in self._root.db_ids)
		self._root.db_ids[client.db_id] = client
		#assert(not user_or_error.username in self._root.usernames)
		self._root.usernames[user_or_error.username] = client


		## update local client fields from DB User values
		client.logged_in = True
		client.access = user_or_error.access
		self._calc_access(client)
		client.set_user_pwrd_salt(user_or_error.username, (user_or_error.password, user_or_error.randsalt))
		client.lobby_id = user_or_error.lobby_id
		client.bot = user_or_error.bot
		client.register_date = user_or_error.register_date
		client.last_login = user_or_error.last_login
		client.cpu = cpu

		## if not a secure authentication, the client should
		## still only be using an old-style unsalted password
		assert(client.use_secure_session() == (not client.has_legacy_password()))

		client.local_ip = None
		if local_ip.startswith('127.') or not validateIP(local_ip):
			client.local_ip = client.ip_address
		else:
			client.local_ip = local_ip

		client.ingame_time = user_or_error.ingame_time

		client.db_id = user_or_error.id
		assert(client.db_id >= 0)
		if client.ip_address in self._root.trusted_proxies:
			client.setFlagByIP(local_ip, False)

		if (client.access == 'agreement'):
			client.buffersend = False
			self._root.console_write('[%s] Sent user <%s> the terms of service on session.' % (client.session_id, user_or_error.username))
			for line in self._root.agreement:
				client.Send("AGREEMENT %s" %(line))
			client.Send('AGREEMENTEND')
			return

		self._root.console_write('[%s] Successfully logged in user <%s> (access=%s).' % (client.session_id, user_or_error.username, client.access))


		self._calc_status(client, 0)

		ignoreList = self.userdb.get_ignored_user_ids(client.db_id)
		client.ignored = {ignoredUserId:True for ignoredUserId in ignoreList}

		client.buffersend = False

		client.RealSend('ACCEPTED %s' % user_or_error.username)

		self._sendMotd(client, self._get_motd_string(client))
		self._checkCompat(client)

		for addclient in self._root.usernames.itervalues():
			client.RealSend(self.client_AddUser(client, addclient))
			if addclient.status != 0:
				client.RealSend('CLIENTSTATUS %s %d' % (addclient.username, addclient.status))

		for battle in self._root.battles.itervalues():
			client.RealSend(self.client_AddBattle(client, battle))
			ubattle = battle.copy()
			client.RealSend('UPDATEBATTLEINFO %(id)s %(spectators)i %(locked)i %(maphash)s %(map)s' % ubattle)
			for session_id in battle.users:
				battleclient = self.clientFromSession(session_id)
				if not battleclient.session_id == battle.host:
					client.RealSend('JOINEDBATTLE %s %s' % (battle.id, battleclient.name))

		if client.status != 0:
			self._root.broadcast('CLIENTSTATUS %s %d'%(client.username, client.status)) # broadcast current client status

		client.Send('LOGININFOEND')
		client.flushBuffer()
		self._informErrors(client)
		self.broadcast_AddUser(client) # send ADDUSER to all clients except self


	def in_CONFIRMAGREEMENT(self, client):
		'Confirm the terms of service as shown with the AGREEMENT commands. Users must accept the terms of service to use their account.'
		if client.access == 'agreement':
			client.access = 'user'
			self.userdb.save_user(client)
			client.access = 'fresh'
			self._calc_access_status(client)

	def in_SAY(self, client, chan, params):
		'''
		Send a message to all users in specified channel.
		The client must be in the channel to send it a message.

		@required.str channel: The target channel.
		@required.str message: The message to send.
		'''
		if not params: return
		if not chan in self._root.channels:
			return

		channel = self._root.channels[chan]

		if not client.session_id in channel.users:
			return

		action = False
		if client.compat['o']:
			params = self._parseTags(params)
			if not "msg" in params:
				return
			msg = params['msg']
			if "action" in params:
				action = True
		else:
			msg = params

		msg = self.SayHooks.hook_SAY(self, client, channel, msg)
		if not msg or not msg.strip(): return

		if channel.isMuted(client):
			client.Send('CHANNELMESSAGE %s You are %s.' % (chan, channel.getMuteMessage(client)))
			return

		# old style SAID
		oldout = 'SAID %s %s %s' % (chan, client.username, msg)

		# new style SAID
		outparams = {
				'chan': chan,
				'userName': client.username,
				#'timestamp': int(time.time()), # FIXME: returns localtime, should be UTC
				'msg': msg.replace("\t", "        "),
			}
		if action:
			outparams['action'] = 'yes'
		newout = 'SAID ' + self._dictToTags(outparams)

		for session_id in channel.users:
			user = self.clientFromSession(session_id)
			if not user:
				self._root.console_write('[%s] ERROR: <%s>: %s %s user not in channel: %s' % (client.session_id, client.username, chan, params, username))
				continue
			if user.compat['o']:
				user.Send(newout)
			else:
				user.Send(oldout)
		if channel.store_history:
			self.userdb.add_channel_message(channel.id, client.db_id, msg)

	def in_SAYEX(self, client, chan, msg):
		'''
		Send an action to all users in specified channel.
		The client must be in the channel to show an action.

		@required.str channel: The target channel.
		@required.str message: The action to send.
		'''
		if not msg: return
		if client.compat['o']:
			self.out_FAILED("SAYEX", "use SAY action=yes")
			return
		if chan in self._root.channels:
			channel = self._root.channels[chan]
			user  = client.username
			msg = self.SayHooks.hook_SAY(self, client, channel, msg)
			if not msg or not msg.strip(): return
			if client.session_id in channel.users:
				if channel.isMuted(client):
					client.Send('CHANNELMESSAGE %s You are %s.' % (chan, channel.getMuteMessage(client)))
				else:
					self._root.broadcast('SAIDEX %s %s %s' % (chan, client.username, msg), chan, [], client)


	def in_SAYPRIVATE(self, client, user, msg):
		'''
		Send a message in private to another user.

		@required.str user: The target user.
		@required.str message: The message to send.
		'''
		if not msg:
			return

		receiver = self.clientFromUsername(user)

		if not receiver:
			self._root.console_write('[%s] ERROR: <%s>: user to pm is not online: %s' % (client.session_id, client.username, user))
			return

		client.Send('SAYPRIVATE %s %s' % (user, msg))
		if not self.is_ignored(receiver, client):
			receiver.Send('SAIDPRIVATE %s %s' % (client.username, msg))

	def in_SAYPRIVATEEX(self, client, user, msg):
		'''
		Send an action in private to another user.

		@required.str user: The target user.
		@required.str message: The action to send.
		'''
		if not msg:
			return

		receiver = self.clientFromUsername(user)

		if receiver:
			client.Send('SAYPRIVATEEX %s %s' % (user, msg))

			if not self.is_ignored(receiver, client):
				receiver.Send('SAIDPRIVATEEX %s %s' % (client.username, msg))


	def in_MUTE(self, client, chan, user, duration=0):
		'''
		Mute target user in target channel.
		[operator]

		@required.str channel: The target channel.
		@required.str user: The user to mute.
		@optional.float duration: The duration for which to mute the user. Defaults to forever.
		'''
		if chan in self._root.channels:
			channel = self._root.channels[chan]
			if channel.isOp(client):
				target = self.clientFromUsername(user)
				if target:
					channel.muteUser(client, target, duration)

	def in_UNMUTE(self, client, chan, user):
		'''
		Unmute target user in target channel.
		[operator]

		@required.str channel: The target channel.
		@required.str user: The user to unmute.
		'''
		if chan in self._root.channels:
			channel = self._root.channels[chan]
			if channel.isOp(client):
				target = self.clientFromUsername(user)
				if target:
					channel.unmuteUser(client, target)

	def in_MUTELIST(self, client, chan): # maybe restrict to open channels and channels you are in - not locked
		'''
		Return the list of muted users in target channel.

		@required.str channel: The target channel.
		'''
		if chan in self._root.channels:
			channel = self._root.channels[chan]
			client.Send('MUTELISTBEGIN %s' % chan)
			for user in channel.mutelist:
				m = mutelist[user].copy()
				message = self._time_until(m['expires']) + (' by IP.' if m['ip'] else '.')
				user = self.clientFromID(user)
				if user:
					client.Send('MUTELIST %s, %s' % (user.username, message))
			client.Send('MUTELISTEND')

	def in_IGNORE(self, client, tags):
		'''
		Tells the server to add the user to the client's ignore list. Doing this will prevent any SAID*, SAYPRIVATE and RING commands to be received from the ignored user.

		@required.str username: The target user to ignore.
		@required.str reason: Reason for the ignore.
		'''
		tags = self._parseTags(tags)
		# should write a helper function for mandatory args..?
		username = tags.get("userName")
		if not username:
			self.out_SERVERMSG(client, "Missing userName argument.")
			return
		reason = tags.get("reason")

		ok, failReason = self._validUsernameSyntax(username)
		if not ok:
			self.out_SERVERMSG(client, "Invalid userName format.")
			return
		ignoreClient = self.clientFromUsername(username, True)
		if not ignoreClient:
			self.out_SERVERMSG(client, "No such user.")
			return
		if ignoreClient.access in ('mod', 'admin'):
			self.out_SERVERMSG(client, "Can't ignore a moderator.")
			return
		if username == client.username:
			self.out_SERVERMSG(client, "Can't ignore self.")
			return
		if self.is_ignored(client, ignoreClient):
			self.out_SERVERMSG(client, "User is already ignored.")
			return
		if len(client.ignored) >= 50:
			self.out_SERVERMSG(client, "Ignore list full (50 users).")
			return

		self.ignore_user(client, ignoreClient, reason)
		if not reason or not reason.strip(): 
			client.Send('IGNORE userName=%s' % (username))
		else:
			client.Send('IGNORE userName=%s\treason=%s' % (username, reason))

	def in_UNIGNORE(self, client, tags):
		'''
		Tells the server to add the user to the client's ignore list. Doing this will prevent any SAID*, SAYPRIVATE and RING commands to be received from the ignored user.

		@required.str username: The target user to unignore.
		'''
		tags = self._parseTags(tags)
		# should write a helper function for mandatory args..?
		username = tags.get("userName")
		if not username:
			self.out_SERVERMSG(client, "Missing userName argument.")
			return
		ok, reason = self._validUsernameSyntax(username)
		if not ok:
			self.out_SERVERMSG(client, "Invalid userName format.")
			return
		unignoreClient = self.clientFromUsername(username, True)
		if not unignoreClient:
			self.out_SERVERMSG(client, "No such user.")
			return
		if not self.is_ignored(client, unignoreClient):
			self.out_SERVERMSG(client, "User is not ignored.")
			return

		self.unignore_user(client, unignoreClient)
		client.Send('UNIGNORE userName=%s' % (username))

	def in_IGNORELIST(self, client):
		client.Send('IGNORELISTBEGIN')
		for (userId, reason) in self.userdb.get_ignore_list(client.db_id):
			ignoredClient = self.clientFromID(userId, True)
			username = ignoredClient.username
			if reason:
				client.Send('IGNORELIST userName=%s\treason=%s' % (username, reason))
			else:
				client.Send('IGNORELIST userName=%s' % (username))
		client.Send('IGNORELISTEND')

	# FIXME: there is currently no limit to the number of friend requests one user can send
	def in_FRIENDREQUEST(self, client, tags):
		tags = self._parseTags(tags)
		# should write a helper function for mandatory args..?
		username = tags.get("userName")
		if not username:
			self.out_SERVERMSG(client, "Missing userName argument.")
			return
		msg = tags.get("msg")

		ok, failReason = self._validUsernameSyntax(username)
		if not ok:
			self.out_SERVERMSG(client, "Invalid userName format.")
			return

		friendRequestClient = self.clientFromUsername(username, True)
		if not friendRequestClient:
			self.out_SERVERMSG(client, "No such user.")
			return
		if username == client.username:
			self.out_SERVERMSG(client, "Can't send friend request to self. Sorry :(")
			return
		if self.userdb.are_friends(client.db_id, friendRequestClient.db_id):
			self.out_SERVERMSG(client, "Already friends with user.")
			return
		if self.is_ignored(friendRequestClient, client):
			# don't send friend request if ignored
			return
		if self.userdb.has_friend_request(client.db_id, friendRequestClient.db_id):
			# don't inform the user that there is already a friend request (so they won't be able to tell if they are being ignored or not)
			return

		self.userdb.add_friend_request(client.db_id, friendRequestClient.db_id, msg)
		if self.clientFromID(friendRequestClient.db_id):
			if msg:
				friendRequestClient.Send('FRIENDREQUEST userName=%s\tmsg=%s' % (client.username, msg))
			else:
				friendRequestClient.Send('FRIENDREQUEST userName=%s' % client.username)


	def in_ACCEPTFRIENDREQUEST(self, client, tags):
		tags = self._parseTags(tags)
		# should write a helper function for mandatory args..?
		username = tags.get("userName")
		if not username:
			self.out_SERVERMSG(client, "Missing userName argument.")
			return

		ok, failReason = self._validUsernameSyntax(username)
		if not ok:
			self.out_SERVERMSG(client, "Invalid userName format.")
			return

		friendRequestClient = self.clientFromUsername(username, True)
		if not self.userdb.has_friend_request(friendRequestClient.db_id, client.db_id):
			self.out_SERVERMSG(client, "No such friend request.")
			return

		self.userdb.friend_users(client.db_id, friendRequestClient.db_id)
		self.userdb.remove_friend_request(friendRequestClient.db_id, client.db_id)

		client.Send('FRIEND userName=%s' % username)
		if self.clientFromID(friendRequestClient.db_id):
			friendRequestClient.Send('FRIEND userName=%s' % client.username)

	def in_DECLINEFRIENDREQUEST(self, client, tags):
		tags = self._parseTags(tags)
		# should write a helper function for mandatory args..?
		username = tags.get("userName")
		if not username:
			self.out_SERVERMSG(client, "Missing userName argument.")
			return
		ok, failReason = self._validUsernameSyntax(username)
		if not ok:
			self.out_SERVERMSG(client, "Invalid userName format.")
			return

		friendRequestClient = self.clientFromUsername(username, True)
		if not self.userdb.has_friend_request(friendRequestClient.db_id, client.db_id):
			self.out_SERVERMSG(client, "No such friend request.")
			return
		self.userdb.remove_friend_request(friendRequestClient.db_id, client.db_id)

	def in_UNFRIEND(self, client, tags):
		tags = self._parseTags(tags)
		# should write a helper function for mandatory args..?
		username = tags.get("userName")
		if not username:
			self.out_SERVERMSG(client, "Missing userName argument.")
			return
		ok, failReason = self._validUsernameSyntax(username)
		if not ok:
			self.out_SERVERMSG(client, "Invalid userName format.")
			return

		friendRequestClient = self.clientFromUsername(username, True)

		self.userdb.unfriend_users(client.db_id, friendRequestClient.db_id)

		client.Send('UNFRIEND userName=%s' % username)
		if self.clientFromID(friendRequestClient.db_id):
			friendRequestClient.Send('UNFRIEND userName=%s' % client.username)

	def in_FRIENDREQUESTLIST(self, client):
		client.Send('FRIENDREQUESTLISTBEGIN')
		for (userId, msg) in self.userdb.get_friend_request_list(client.db_id):
			friendRequestClient = self.clientFromID(userId, True)
			username = friendRequestClient.username
			if msg:
				client.Send('FRIENDREQUESTLIST userName=%s\tmsg=%s' % (username, msg))
			else:
				client.Send('FRIENDREQUESTLIST userName=%s' % (username))
		client.Send('FRIENDREQUESTLISTEND')

	def in_FRIENDLIST(self, client):
		client.Send('FRIENDLISTBEGIN')
		for userId in self.userdb.get_friend_user_ids(client.db_id):
			friendClient = self.clientFromID(userId, True)
			username = friendClient.username
			client.Send('FRIENDLIST userName=%s' % (username))
		client.Send('FRIENDLISTEND')


	def in_FORCEJOIN(self, client, user, chan, key=None):
		'''
		Force a user to join a channel.

		@required.str username: user to send to
		@required.str channel: target channel
		@optional.str password: channel password
		'''
		ok, reason = self._validChannelSyntax(chan)
		if not ok:
			self.out_SERVERMSG(client, '%s' % reason)
			return

		if chan in self._root.channels:
			channel = self._root.channels[chan]
			if user in channel.users:
				self.out_SERVERMSG(client, 'FORCEJOIN failed: %s Already in channel!' % chan)
				return

		if user in self._root.usernames:
			self._handle(self._root.usernames[user], "JOIN %s %s" % (chan, key))
		else:
			self.out_SERVERMSG(client, '%s user not found' % user)

	def in_JOIN(self, client, chan, key=None):
		'''
		Attempt to join target channel.

		@required.str channel: The target channel.
		@optional.str password: The password to use for joining if channel is locked.
		'''
		ok, reason = self._validChannelSyntax(chan)
		if not ok:
			client.Send('JOINFAILED %s' % reason)
			return

		user = client.username
		chan = chan.lstrip('#')

		# FIXME: unhardcode this
		if client.bot and chan in ("newbies", "ba") and client.username != "ChanServ":
			client.Send('JOINFAILED %s No bots allowed in #%s!' %(chan, chan))
			return

		if not chan: return
		if not chan in self._root.channels:
			channel = self._new_channel(chan)
			self._root.channels[chan] = channel
		else:
			channel = self._root.channels[chan]
		if client.session_id in channel.users:
			return
		if not channel.isFounder(client):
			if channel.key and not channel.key in (key, None, '*', ''):
				client.Send('JOINFAILED %s Invalid key' % chan)
				return
			elif channel.autokick == 'ban' and client.db_id in channel.ban:
				client.Send('JOINFAILED %s You are banned from the channel %s' % (chan, channel.ban[client.db_id]))
				return
			elif channel.autokick == 'allow' and client.db_id not in channel.allow:
				client.Send('JOINFAILED %s You are not allowed' % chan)
				return
		assert(chan not in client.channels)
		client.channels.add(chan)
		client.Send('JOIN %s'%chan)
		channel.addUser(client)
		assert(client.session_id in channel.users)
		clientlist = ""
		for session_id in channel.users:
			if clientlist:
				clientlist += " "
			channeluser = self.clientFromSession(session_id)
			assert(channeluser)
			clientlist += channeluser.username
		client.Send('CLIENTS %s %s'%(chan, clientlist))

		topic = channel.topic
		if topic:
			if client.compat['et']:
				topictime = int(topic['time'])
			else:
				topictime = int(topic['time'])*1000
			try:
				top = topic['text'].decode(UNICODE_ENCODING)
			except:
				top = "Invalid unicode-encoding (should be %s)" % UNICODE_ENCODING
				self._root.console_write("%s for channel topic: %s" %(top, chan))
			client.Send('CHANNELTOPIC %s %s %s %s'%(chan, topic['user'], topictime, top))
		elif client.compat['et']: # supports sendEmptyTopic
			client.Send('NOCHANNELTOPIC %s' % chan)

		msgs = self.userdb.get_channel_messages(client.db_id, channel.id, client.last_login)
		if client.compat['o']:
			for msg in msgs:
				client.Send("SAID " + self._dictToTags( { "chanName": chan, "time": msg[0].isoformat(), "userName": msg[1], "msg": msg[2]} ))
		else:
			for msg in msgs:
				client.Send("SAID %s %s %s" %(chan, msg[1], msg[2]))

		# disabled because irc bridge spams JOIN commands
		#
		# a user can rejoin a channel to get the topic while in it
		#topic = channel.topic
		#if topic and user in channel.users:
		#	client.Send('CHANNELTOPIC %s %s %s %s'%(chan, topic['user'], topic['time'], topic['text']))

	def in_SETCHANNELKEY(self, client, chan, key='*'):
		'''
		Lock target channel with a password, or unlocks target channel.

		@required.str channel: The target channel.
		@optional.str password: The password to set. To unlock a channel, leave this blank or set to '*'.
		'''
		if chan in self._root.channels:
			channel = self._root.channels[chan]
			if channel.isOp(client):
				channel.setKey(client, key)

	def in_LEAVE(self, client, chan, reason=None):
		'''
		Leave target channel.

		@required.str channel: The target channel.
		'''
		if not chan in self._root.channels:
			return
		channel = self._root.channels[chan]
		channel.removeUser(client, reason)
		assert(not client.session_id in channel.users)
		if len(self._root.channels[chan].users) == 0:
			del self._root.channels[chan]

	def in_OPENBATTLE(self, client, type, natType, password, port, maxplayers, hashcode, rank, maphash, sentence_args):
		'''
		Host a new battle with the arguments specified.

		@required.int type: The type of battle to host.
		#0: Battle
		#1: Hosted replay

		@required.int natType: The method of NAT transversal to use.
		#0: None
		#1: Hole punching
		#2: Fixed source ports

		@required.str password: The password to use, or "*" to use no password.
		@required.int port:
		@required.int maxplayers:
		@required.sint modhash: Mod hash, as returned by unitsync.dll.
		@required.int rank: Recommended minimum rank to join the battle. Current ranks range from 0-7.
		@required.sint maphash: Map hash, as returned by unitsync.dll.
		@required.sentence.str engine: The engine name, lowercase, with no spaces.
		@required.sentence.str version: The engine version.
		@required.sentence.str mapName: The map name.
		@required.sentence.str title: The battle's title.
		@required.sentence.str modName: The mod name.
		'''
		if client.current_battle:
			self.in_LEAVEBATTLE(client)

		engine = None
		version = None
		map = None
		title = None
		modname = None

		argcount = sentence_args.count('\t')
		if client.compat['cl'] and argcount == 4: #supports cleanupBattles
			engine, version, map, title, modname = sentence_args.split('\t', 4)
		elif not client.compat['cl'] and argcount == 2:
			map, title, modname = sentence_args.split('\t',2)
			engine = 'spring'
			version = self._root.latestspringversion
		else:
			self.out_OPENBATTLEFAILED(client, 'To few arguments: %d' %(argcount))
			return False

		title = self.SayHooks.hook_OPENBATTLE(self, client, title).strip()

		checkvars = [
			(engine, 'No engine specified.'),
			(version, 'No engine version specified.'),
			(map, "No map name specified"),
			(title, "invalid title"),
			(modname, "No game name specified")]

		for var, error in checkvars:
			if not var:
				self.out_OPENBATTLEFAILED(client, error)
				return

		battle_id = self._getNextBattleId()

		if password == '*':
			passworded = 0
		else:
			passworded = 1

		try:
			int(battle_id)
			int(type)
			int(natType)
			int(passworded)
			port = int(port)
			int32(maphash)
			int32(hashcode)
		except Exception as e:
			self.out_OPENBATTLEFAILED(client, 'Invalid argument type, send this to your lobby dev: id=%s type=%s natType=%s passworded=%s port=%s maphash=%s gamehash=%s - %s' %
						(battle_id, type, natType, passworded, port, maphash, hashcode, str(e).replace("\n", "")))
			return False

		if port < 1 or port > 65535:
			self.out_OPENBATTLEFAILED(client, 'Port is out of range: 1-65535: %d' % port)
			return

		client.current_battle = battle_id

		battle = Battle.Battle(
						root=self._root, id=battle_id, type=type, natType=int(natType),
						password=password, port=port, maxplayers=maxplayers, hashcode=hashcode,
						rank=rank, maphash=maphash, map=map, title=title, modname=modname,
						passworded=passworded, host=client.session_id, users={client.session_id},
						engine=engine, version=version
					)

		self._root.battles[battle_id] = battle
		self.broadcast_AddBattle(battle)
		client.Send('OPENBATTLE %s' % battle_id)
		client.Send('JOINBATTLE %s %s' % (battle_id, hashcode))
		client.Send('REQUESTBATTLESTATUS')

	def in_SAYBATTLE(self, client, msg):
		'''
		Send a message to all users in your current battle.

		@required.str message: The message to send.
		'''
		if not msg: return
		battle_id = client.current_battle
		battle = self._root.battles[battle_id]
		user = client.username
		self.broadcast_SendBattle(battle, 'SAIDBATTLE %s %s' % (user, msg), client)

	def in_SAYBATTLEEX(self, client, msg):
		'''
		Send an action to all users in your current battle.

		@required.str message: The action to send.
		'''
		battle_id = client.current_battle
		battle = self._root.battles[battle_id]
		self.broadcast_SendBattle(battle, 'SAIDBATTLEEX %s %s' % (client.username, msg), client)

	def in_SAYBATTLEPRIVATE(self, client, username, msg):
		'''
		Send a message to one target user in your current battle.
		[host]

		@required.str username: The user to receive your message.
		@required.str message: The message to send.
		'''
		battle_id = client.current_battle
		user = self.clientFromUsername(username)
		if not user:
			return
		battle = self._root.battles[battle_id]
		if client.session_id == battle.host and client.session_id in battle.users:
			if not self.is_ignored(user, client):
				user.Send('SAIDBATTLE %s %s' % (client.username, msg))

	def in_SAYBATTLEPRIVATEEX(self, client, username, msg):
		'''
		Send an action to one target user in your current battle.
		[host]

		@required.str username: The user to receive your action.
		@required.str message: The action to send.
		'''
		battle_id = client.current_battle
		if not user:
			return
		battle = self._root.battles[battle_id]
		if client.session_id == battle.host and username in battle.users:
			if not self.is_ignored(user, client):
				user.Send('SAIDBATTLEEX %s %s' % (client.username, msg))

	def in_FORCEJOINBATTLE(self, client, username, target_battle, password=None):
		'''
		Instruct a user in your battle to join another.
		[host]

		@required.str username: The target user.
		@required.int battle_id: The destination battle.
		@optional.str password: The battle's password, if required.
		'''

		if not username in self._root.usernames:
			client.Send("FORCEJOINBATTLEFAILED user %s not found!" %(username))
			return

		user = self.clientFromUsername(username)
		battle_id = user.current_battle

		if not 'mod' in client.accesslevels and not self._canForceBattle(client, username):
			client.Send('FORCEJOINBATTLEFAILED You are not allowed to force this user into battle.')
			return

		user = self._root.usernames[username]
		if not user.compat['m']:
			client.Send('FORCEJOINBATTLEFAILED This user does not subscribe to matchmaking.')
			return

		if not target_battle in self._root.battles:
			client.Send('FORCEJOINBATTLEFAILED Target battle does not exist.')
			return

		target = self._root.battles[target_battle]
		if target.passworded:
			if password == target.password:
				user.Send('FORCEJOINBATTLE %s %s' % (target_battle, password))
			else:
				client.Send('FORCEJOINBATTLEFAILED Incorrect password for target battle.')
			return

		user.Send('FORCEJOINBATTLE %s' % (target_battle))

	def in_JOINBATTLEACCEPT(self, client, username):
		'''
		Allow a user to join your battle, sent as a response to JOINBATTLEREQUEST.
		[host]

		@required.str username: The user to allow into your battle.
		'''
		battle_id = client.current_battle
		user = self.clientFromUsername(client.session_id)
		if not user:
			return
		battle = self._root.battles[battle_id]
		if not client.session_id == battle.host: return
		if username in battle.pending_users:
			battle.pending_users.remove(client.session_id)
			battle.authed_users.add(client.session_id)
			self.in_JOINBATTLE(user, battle_id)

	def in_JOINBATTLEDENY(self, client, username, reason=None):
		'''
		Deny a user from joining your battle, sent as a response to JOINBATTLEREQUEST.
		[host]

		@required.str username: The user to deny from joining your battle.
		@optional.str reason: The reason to provide to the user.
		'''
		user = self.clientFromUsername(username)
		if not user:
			return
		battle = self._root.battles[battle_id]
		if not client.username == battle.host: return
		if username in battle.pending_users:
			battle.pending_users.remove(username)
			user.Send('JOINBATTLEFAILED %s%s' % ('Denied by host', (' ('+reason+')' if reason else '')))

	def in_JOINBATTLE(self, client, battle_id, password=None, scriptPassword=None):
		'''
		Attempt to join target battle.

		@required.int battleID: The ID of the battle to join.
		@optional.str password: The password to use if the battle requires one.
		@optional.str scriptPassword: A password unique to your user, to verify users connecting to the actual game.
		'''
		if scriptPassword: client.scriptPassword = scriptPassword

		try:
			battle_id = int32(battle_id)
		except:
			client.Send('JOINBATTLEFAILED Invalid battle id: %s.' %(str(battle_id)))
			return

		username = client.username
		if client.current_battle in self._root.battles:
			client.Send('JOINBATTLEFAILED You are already in a battle.')
			return

		if battle_id not in self._root.battles:
			client.Send('JOINBATTLEFAILED Unable to join battle.')
			return
		battle = self._root.battles[battle_id]
		if client.session_id in battle.users: # user is already in battle
			return

		host = self.clientFromSession(battle.host)
		if battle.passworded == 1 and not battle.password == password:
			if not (host.compat['b'] and username in battle.authed_users): # supports battleAuth
				client.Send('JOINBATTLEFAILED Incorrect password.')
				return
		if battle.locked:
			client.Send('JOINBATTLEFAILED Battle is locked.')
			return
		if username in host.battle_bans: # TODO: make this depend on db_id instead
			client.Send('JOINBATTLEFAILED <%s> has banned you from their battles.' % host.username)
			return
		if host.compat['b'] and not username in battle.authed_users: # supports battleAuth
			battle.pending_users.add(username)
			if client.ip_address in self._root.trusted_proxies:
				client_ip = client.local_ip
			else:
				client_ip = client.ip_address
			host.Send('JOINBATTLEREQUEST %s %s' % (username, client_ip))
			return
		battle_users = battle.users
		battle_bots = battle.bots
		startrects = battle.startrects
		client.Send('JOINBATTLE %s %s' % (battle_id, battle.hashcode))
		battle.users.add(client.session_id)
		scripttags = []
		for tag, val in battle.script_tags.iteritems():
			scripttags.append('%s=%s'%(tag, val))
		client.Send('SETSCRIPTTAGS %s'%'\t'.join(scripttags))
		if battle.disabled_units:
			client.Send('DISABLEUNITS %s' % ' '.join(battle.disabled_units))
		self._root.broadcast('JOINEDBATTLE %s %s' % (battle_id, username), ignore=(battle.host, username))

		scriptPassword = client.scriptPassword
		if host.compat['sp'] and scriptPassword: # supports scriptPassword
			host.Send('JOINEDBATTLE %s %s %s' % (battle_id, username, scriptPassword))
			client.Send('JOINEDBATTLE %s %s %s' % (battle_id, username, scriptPassword))
		else:
			host.Send('JOINEDBATTLE %s %s' % (battle_id, username))
			client.Send('JOINEDBATTLE %s %s' % (battle_id, username))

		if battle.natType > 0:
			if battle.host == client.session_id:
				raise NameError('%s is having an identity crisis' % (client.name))
			if client.udpport:
				self._root.usernames[host].Send('CLIENTIPPORT %s %s %s' % (username, client.ip_address, client.udpport))

		specs = 0
		for sessionid in battle.users:
			battle_client = self.clientFromSession(sessionid)
			if battle_client and battle_client.battlestatus['mode'] == '0':
				specs += 1
			battlestatus = self._calc_battlestatus(battle_client)
			client.Send('CLIENTBATTLESTATUS %s %s %s' % (battle_client.username, battlestatus, battle_client.teamcolor))

		for iter in battle_bots:
			bot = battle_bots[iter]
			client.Send('ADDBOT %s %s' % (battle_id, iter)+' %(owner)s %(battlestatus)s %(teamcolor)s %(AIDLL)s' % (bot))
		for allyno in startrects:
			rect = startrects[allyno]
			client.Send('ADDSTARTRECT %s' % (allyno)+' %(left)s %(top)s %(right)s %(bottom)s' % (rect))
		client.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
		client.teamcolor = '0'
		client.current_battle = battle_id
		client.Send('REQUESTBATTLESTATUS')
		return

	def in_SETSCRIPTTAGS(self, client, scripttags):
		'''
		Set script tags and send them to all clients in your battle.

		@required.str scriptTags: A tab-separated list of key=value pairs.
		'''

		if not self._canForceBattle(client):
			self.out_FAILED(client, "SETSCRIPTTAGS", "You are not allowed to change settings as client in a game!", True)
			return

		setscripttags = self._parseTags(scripttags)
		scripttags = []
		for tag in setscripttags:
			scripttags.append('%s=%s'%(tag.lower(), setscripttags[tag]))
		if not scripttags:
			return
		self._root.battles[client.current_battle].script_tags.update(setscripttags)
		self._root.broadcast_battle('SETSCRIPTTAGS %s'%'\t'.join(scripttags), client.current_battle)

	def in_REMOVESCRIPTTAGS(self, client, tags):
		'''
		Remove script tags and send an update to all clients in your battle.

		@required.str tags: A space-separated list of tags.
		'''
		if not self._canForceBattle(client):
			return

		battle = self._root.battles[client.current_battle]
		rem = set()
		for tag in set(tags.split(' ')):
			try:
				# this means we only broadcast removed tags if they existed
				del battle.script_tags[tag]
				rem.add(tag)
			except KeyError:
				pass
		if not rem:
			return
		self._root.broadcast_battle('REMOVESCRIPTTAGS %s'%' '.join(rem), client.current_battle)

	def in_LEAVEBATTLE(self, client):
		'''
		Leave current battle.
		'''
		client.scriptPassword = None

		username = client.username
		battle_id = client.current_battle
		battle = self._root.battles[battle_id]
		if battle.host == client.session_id:
			self.broadcast_RemoveBattle(battle)
			client.hostport = None
			del self._root.battles[battle_id]
			client.current_battle = None
			return
		battle.users.remove(client.session_id)
		if username in battle.authed_users:
			battle.authed_users.remove(username)

		for bot in client.battle_bots:
			del client.battle_bots[bot]
			if bot in battle.bots:
				del battle.bots[bot]
				self._root.broadcast_battle('REMOVEBOT %s %s' % (battle_id, bot), battle_id)
		self._root.broadcast('LEFTBATTLE %s %s'%(battle_id, client.username))
		client.current_battle = None

		oldspecs = battle.spectators

		specs = 0
		for session_id in battle.users:
			user = self.clientFromSession(session_id)
			if user and user.battlestatus['mode'] == '0':
				specs += 1

		battle.spectators = specs
		if oldspecs != specs:
			self._root.broadcast('UPDATEBATTLEINFO %(id)s %(spectators)i %(locked)i %(maphash)s %(map)s' % battle.copy())

	def in_MYBATTLESTATUS(self, client, _battlestatus, _myteamcolor):
		'''
		Set your status in a battle.

		@required.int status: The status to set, formatted as an awesome bitfield.
		@required.sint teamColor: Teamcolor to set. Format is hex 0xBBGGRR represented as decimal.
		'''
		try:
			battlestatus = int32(_battlestatus)
		except:
			self.out_SERVERMSG(client, 'MYBATTLESTATUS failed - invalid status: %s.' % (_battlestatus), True)
			return

		if battlestatus < 0:
			battlestatus = battlestatus + 2147483648
			self.out_SERVERMSG(client, 'MYBATTLESTATUS failed - invalid status is below 0: %s. Please update your lobby!' % (_battlestatus), True)

		try:
			myteamcolor = int32(_myteamcolor)
		except:
			self.out_SERVERMSG(client, 'MYBATTLESTATUS failed - invalid teamcolor: %s.' % (myteamcolor), True)
			return

		battle_id = client.current_battle
		battle = self._root.battles[battle_id]
		spectating = (client.battlestatus['mode'] == '0')

		clients = (self.clientFromSession(name) for name in battle.users)
		spectators = len([user for user in clients if user and (user.battlestatus['mode'] == '0')])

		u, u, u, u, side1, side2, side3, side4, sync1, sync2, u, u, u, u, handicap1, handicap2, handicap3, handicap4, handicap5, handicap6, handicap7, mode, ally1, ally2, ally3, ally4, id1, id2, id3, id4, ready, u = self._dec2bin(battlestatus, 32)[-32:]
		# support more allies and ids.
		#u, u, u, u, side1, side2, side3, side4, sync1, sync2, u, u, u, u, handicap1, handicap2, handicap3, handicap4, handicap5, handicap6, handicap7, mode, ally1, ally2, ally3, ally4,ally5, ally6, ally7, ally8, id1, id2, id3, id4,id5, id6, id7, id8, ready, u = self._dec2bin(battlestatus, 40)[-40:]

		if spectating:
			if len(battle.users) - spectators >= int(battle.maxplayers):
				mode = '0'
			elif mode == '1':
				spectators -= 1
		elif mode == '0':
			spectators += 1

		oldstatus = self._calc_battlestatus(client)
		oldcolor = client.teamcolor
		client.battlestatus.update({'ready':ready, 'id':id1+id2+id3+id4, 'ally':ally1+ally2+ally3+ally4, 'mode':mode, 'sync':sync1+sync2, 'side':side1+side2+side3+side4})
		client.teamcolor = myteamcolor

		oldspecs = battle.spectators
		battle.spectators = spectators

		if oldspecs != spectators:
			self._root.broadcast('UPDATEBATTLEINFO %(id)s %(spectators)i %(locked)i %(maphash)s %(map)s' % battle.copy())

		newstatus = self._calc_battlestatus(client)
		statuscmd = 'CLIENTBATTLESTATUS %s %s %s'%(client.username, newstatus, myteamcolor)
		if oldstatus != newstatus or client.teamcolor != oldcolor:
			self._root.broadcast_battle(statuscmd, client.current_battle)
		else:
			client.Send(statuscmd) # in case we changed anything

	def in_UPDATEBATTLEINFO(self, client, SpectatorCount, locked, maphash, mapname):
		'''
		Update public properties of your battle.
		[host]

		@required.int spectators: The number of spectators in your battle.
		@required.int locked: A boolean (0 or 1) of whether battle is locked.
		@required.sint mapHash: A 32-bit signed hash of the current map as returned by unitsync.
		@required.str mapName: The name of the current map.
		'''
		battle_id = client.current_battle
		battle = self._root.battles[battle_id]
		if battle.host == client.session_id:
			try:
				maphash = int32(maphash)
			except:
				self.out_SERVERMSG(client, "UPDATEBATTLEINFO failed - Invalid map hash send: %s %s " %(str(mapname),str(maphash)), True)
				maphash = 0
				return

			if not mapname or "\t" in mapname:
				self.out_SERVERMSG(client, "UPDATEBATTLEINFO failed - invalid mapname send: %s" %(str(mapname)), True)
				return

			old = battle.copy()
			updated = {'id':battle_id, 'locked':int(locked), 'maphash':maphash, 'map':mapname}
			battle.update(**updated)

			oldstr = 'UPDATEBATTLEINFO %(id)s %(spectators)i %(locked)i %(maphash)s %(map)s' % old
			newstr = 'UPDATEBATTLEINFO %(id)s %(spectators)i %(locked)i %(maphash)s %(map)s' % battle.copy()
			if oldstr != newstr:
				self._root.broadcast(newstr)

	def in_MYSTATUS(self, client, _status):
		'''
		Set your client status, to be relayed to all other clients.

		@required.int status: A bitfield of your status. The server forces a few values itself, as well.
		'''
		try:
			status = int32(_status)
		except:
			self.out_SERVERMSG(client, 'MYSTATUS failed - invalid status %s'%(_status), True)
			return
		was_ingame = client.is_ingame
		self._calc_status(client, status)
		if client.is_ingame and not was_ingame:
			battle_id = client.current_battle
			battle = self._root.battles[battle_id]

			if len(battle.users) > 1:
				client.went_ingame = time.time()
			else:
				client.went_ingame = None
			if client.session_id == battle.host:
				if client.hostport:
					self._root.broadcast_battle('HOSTPORT %i' % client.hostport, battle_id, host)
		elif was_ingame and not client.is_ingame and client.went_ingame:
			ingame_time = (time.time() - client.went_ingame) / 60
			if ingame_time >= 1:
				client.ingame_time += int(ingame_time)
				self.userdb.save_user(client)
		if not client.username in self._root.usernames: return
		self._root.broadcast('CLIENTSTATUS %s %d'%(client.username, client.status))

	def in_CHANNELS(self, client):
		'''
		Return a listing of all channels on the server.
		'''
		channels = []
		for channel in self._root.channels.values():
			if channel.owner and not channel.key:
				channels.append(channel)

		if not channels:
			self.out_SERVERMSG(client, 'No channels are currently visible (they must be registered and unlocked).')
			return

		for channel in channels:
			topic = channel.topic
			if topic:
				try:
					top = topic['text'].decode(UNICODE_ENCODING)
				except:
					top = "Invalid unicode-encoding (should be %s)" % UNICODE_ENCODING
			client.Send('CHANNEL %s %d %s'% (channel.name, len(channel.users), top))
		client.Send('ENDOFCHANNELS')

	def in_CHANNELTOPIC(self, client, chan, topic):
		'''
		Set the topic in target channel.
		[operator]

		@required.str channel: The target channel.
		@required.str topic: The topic to set.
		'''
		if chan in self._root.channels:
			channel = self._root.channels[chan]
			if channel.isOp(client):
				channel.setTopic(client, topic)

	def in_CHANNELMESSAGE(self, client, chan, message):
		'''
		Send a server message to target channel.

		@required.str channel: The target channel.
		@required.str message: The message to send.
		'''
		if chan in self._root.channels:
			channel = self._root.channels[chan]
			if channel.isOp(client):
				channel.channelMessage(message)

	def in_FORCELEAVECHANNEL(self, client, chan, username, reason=''):
		'''
		Kick target user from target channel.

		@required.str channel: The target channel.
		@required.str username: The target user.
		@optional.str reason: A reason for kicking the user..
		'''
		if not chan in self._root.channels:
			self.out_SERVERMSG(client, 'channel <%s> does not exist!' % (chan))
			return
		channel = self._root.channels[chan]
		if not (channel.isOp(client) or 'mod' in client.accesslevels):
			self.out_SERVERMSG(client, 'access denied')
		target = self.clientFromUsername(username)
		if target and username in channel.users:
			channel.kickUser(client, target, reason)
			self.out_SERVERMSG(client, '<%s> kicked from channel #%s' % (username, chan))
		else:
			self.out_SERVERMSG(client, '<%s> not in channel #%s' % (username, chan))

	def in_RING(self, client, username):
		'''
		Send target user a ringing notification, normally used for idle users in battle.
		[host]

		@required.str username: The target user.
		'''
		user = self.clientFromUsername(username)

		if not user: return
		if not client.current_battle: return
		if not 'mod' in client.accesslevels:
			battle_id = client.current_battle
			battle = self._root.battles[battle_id]
			if not battle.host in (client.session_id, user.session_id):
				return
			if not client.session_id in battle.users:
				return

		if not self.is_ignored(user, client):
			user.Send('RING %s' % (client.username))


	def in_ADDSTARTRECT(self, client, allyno, left, top, right, bottom):
		'''
		Add a start rectangle for an ally team.
		[host]

		@required.int allyno: The ally number for the rectangle.
		@required.float left: The left side of the rectangle.
		@required.float top: The top side of the rectangle.
		@required.float right: The right side of the rectangle.
		@required.float bottom: The bottom side of the rectangle.
		'''
		if not self._canForceBattle(client):
			return
		battle = self._root.battles[client.current_battle]
		try:
			allyno = int32(allyno)
			rect = {
				'left':uint32(left),
				'top':uint32(top),
				'right':uint32(right),
				'bottom':uint32(bottom)
				}
		except:
			self.out_SERVERMSG(client, "invalid ADDSTARTRECT received")
			return
		battle.startrects[allyno] = rect
		self._root.broadcast_battle('ADDSTARTRECT %s' % (allyno)+' %(left)s %(top)s %(right)s %(bottom)s' %(rect), client.current_battle, [client.username])

	def in_REMOVESTARTRECT(self, client, allyno):
		'''
		Remove a start rectangle for an ally team.
		[host]

		@required.int allyno: The ally number for the rectangle.
		'''
		if not self._canForceBattle(client):
			return
		allyno = int32(allyno)
		battle = self._root.battles[client.current_battle]
		try:
			del battle.startrects[allyno]
		except:
			self.out_SERVERMSG(client, 'invalid rect removed: %d' % (allyno), True)
			return
		self._root.broadcast_battle('REMOVESTARTRECT %s' % allyno, client.current_battle, [client.username])

	def in_DISABLEUNITS(self, client, units):
		'''
		Add a list of units to disable.
		[host]

		@required.str units: A string-separated list of unit names to disable.
		'''
		if not self._canForceBattle(client):
			return
		units = units.split(' ')
		disabled_units = []
		battle = self._root.battles[client.current_battle]
		for unit in units:
			if not unit in battle.disabled_units:
				battle.disabled_units.append(unit)
				disabled_units.append(unit)
		if disabled_units:
			disabled_units = ' '.join(disabled_units)
			self._root.broadcast_battle('DISABLEUNITS %s'%disabled_units, client.current_battle, client.username)

	def in_ENABLEUNITS(self, client, units):
		'''
		Remove units from the disabled unit list.
		[host]

		@required.str units: A string-separated list of unit names to enable.
		'''
		if not self._canForceBattle(client, username):
			return
		units = units.split(' ')
		enabled_units = []
		battle = self._root.battles[client.current_battle]
		for unit in units:
			if unit in battle.disabled_units:
				battle.disabled_units.remove(unit)
				enabled_units.append(unit)
		if enabled_units:
			enabled_units = ' '.join(enabled_units)
			self._root.broadcast_battle('ENABLEUNITS %s'%enabled_units, battle_id, client.username)

	def in_ENABLEALLUNITS(self, client):
		'''
		Enable all units.
		[host]
		'''
		if not self._canForceBattle(client):
			return
		battle = self._root.battles[client.current_battle]
		battle.disabled_units = []
		self._root.broadcast_battle('ENABLEALLUNITS', client.current_battle, client.username)

	def in_HANDICAP(self, client, username, value):
		'''
		Change the handicap value for a player.
		[host]

		@required.str username: The player to handicap.
		@required.int handicap: The percentage of handicap to give (1-100).
		'''
		if not self._canForceBattle(client, username):
			return

		if not value.isdigit() or not int(value) in range(0, 101):
			return

		client = self._root.usernames[username]
		client.battlestatus['handicap'] = self._dec2bin(value, 7)
		self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), client.current_battle)

	def in_KICKFROMBATTLE(self, client, username):
		'''
		Kick a player from their battle.
		[host]

		@required.str username: The player to kick.
		'''
		if not self._canForceBattle(client, username):
			return
		kickuser = self._root.usernames[username]
		kickuser.Send('FORCEQUITBATTLE')
		battle = self._root.battles[client.current_battle]
		if client.session_id == battle.host:
			self.broadcast_RemoveBattle(battle)
			del self._root.battles[client.current_battle]
		else:
			self.in_LEAVEBATTLE(kickuser)


	def in_FORCETEAMNO(self, client, username, teamno):
		'''
		Force target player's team number.
		[host]

		@required.str username: The target player.
		@required.int teamno: The team to assign them.
		'''
		if not self._canForceBattle(client, username):
			return
		client = self._root.usernames[username]
		client.battlestatus['id'] = self._dec2bin(teamno, 4)
		self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), client.current_battle)

	def in_FORCEALLYNO(self, client, username, allyno):
		'''
		Force target player's ally team number.
		[host]

		@required.str username: The target player.
		@required.int teamno: The ally team to assign them.
		'''
		if not self._canForceBattle(client, username):
			return
		client = self._root.usernames[username]
		client.battlestatus['ally'] = self._dec2bin(allyno, 4)
		self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), client.current_battle)

	def in_FORCETEAMCOLOR(self, client, username, teamcolor):
		'''
		Force target player's team color.
		[host]

		@required.str username: The target player.
		@required.sint teamcolor: The color to assign, represented with hex 0xBBGGRR as a signed integer.
		'''
		if not self._canForceBattle(client, username):
			return
		client = self._root.usernames[username]
		client.teamcolor = teamcolor
		self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), client.current_battle)

	def in_FORCESPECTATORMODE(self, client, username):
		'''
		Force target player to become a spectator.
		[host]

		@required.str username: The target player.
		'''
		if not self._canForceBattle(client, username):
			return

		client = self._root.usernames[username]
		if client.battlestatus['mode'] == '1':
			battle = self._root.battles[client.current_battle]
			battle.spectators += 1
			client.battlestatus['mode'] = '0'
			self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), client.current_battle)
			self._root.broadcast('UPDATEBATTLEINFO %(id)s %(spectators)i %(locked)i %(maphash)s %(map)s' % battle.copy())

	def in_ADDBOT(self, client, name, battlestatus, teamcolor, AIDLL):
		'''
		Add a bot to the current battle.
		[battle]

		@required.str name: The name of the bot.
		@required.int battlestatus: The battle status of the bot.
		@required.sint teamcolor: The color to assign, represented with hex 0xBBGGRR as a signed integer.
		@required.str AIDLL: The name of the DLL loading the bot.
		'''
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			battle = self._root.battles[battle_id]
			if not name in battle.bots:
				client.battle_bots[name] = battle_id
				battle.bots[name] = {'owner':client.username, 'battlestatus':battlestatus, 'teamcolor':teamcolor, 'AIDLL':AIDLL}
				self._root.broadcast_battle('ADDBOT %s %s %s %s %s %s'%(battle_id, name, client.username, battlestatus, teamcolor, AIDLL), battle_id)

	def in_UPDATEBOT(self, client, name, battlestatus, teamcolor):
		'''
		Update battle status and teamcolor for a bot.
		[battle]

		@required.str name: The name of the bot.
		@required.int battlestatus: The battle status of the bot.
		@required.sint teamcolor: The color to assign, represented with hex 0xBBGGRR as a signed integer.
		'''
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			battle = self._root.battles[battle_id]
			if name in battle.bots:
				if client.username == battle.bots[name]['owner'] or client.session_id == battle.host:
					battle.bots[name].update({'battlestatus':battlestatus, 'teamcolor':teamcolor})
					self._root.broadcast_battle('UPDATEBOT %s %s %s %s'%(battle_id, name, battlestatus, teamcolor), battle_id)




	def in_REMOVEBOT(self, client, name):
		'''
		Remove a bot from the active battle.
		[battle]

		@required.str name: The name of the bot.
		'''
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			battle = self._root.battles[battle_id]
			if name in battle.bots:
				if client.username == battle.bots[name]['owner'] or client.session_id == battle.host:
					del self._root.usernames[battle.bots[name]['owner']].battle_bots[name]
					del battle.bots[name]
					self._root.broadcast_battle('REMOVEBOT %s %s'%(battle_id, name), battle_id)

	def in_GETINGAMETIME(self, client, username=None):
		'''
		Get the ingame time for yourself.
		[user]

		Get the ingame time for any user.
		[mod]

		@optional.str username: The target user. Defaults to yourself.
		'''
		if username and 'mod' in client.accesslevels:
			if username in self._root.usernames: # maybe abstract in the datahandler to automatically query SQL for users not logged in.
				ingame_time = int(self._root.usernames[username].ingame_time)
				self.out_SERVERMSG(client, '<%s> has an ingame time of %d minutes (%d hours).'%(username, ingame_time, ingame_time / 60))
			else:
				good, data = self.userdb.get_ingame_time(username)
				if good:
					ingame_time = int(data)
					self.out_SERVERMSG(client, '<%s> has an ingame time of %d minutes (%d hours).'%(username, ingame_time, ingame_time / 60))
				else: self.out_SERVERMSG(client, 'Database returned error when retrieving ingame time for <%s> (%s)' % (username, data))
		elif not username:
			ingame_time = int(client.ingame_time)
			self.out_SERVERMSG(client, 'Your ingame time is %d minutes (%d hours).'%(ingame_time, ingame_time / 60))
		else:
			self.out_SERVERMSG(client, 'You can\'t get the ingame time of other users.')

	def in_GETLASTLOGINTIME(self, client, username):
		'''
		Get the last login time of target user.

		@required.str username: The target user.
		'''
		if username:
			good, data = self.userdb.get_lastlogin(username)
			if good: self.out_SERVERMSG(client, '<%s> last logged in on %s.' % (username, data.isoformat()))
			else: self.out_SERVERMSG(client, 'Database returned error when retrieving last login time for <%s> (%s)' % (username, data))

	def in_GETREGISTRATIONDATE(self, client, username=None):
		'''
		Get the registration date of yourself.
		[user]

		Get the registration date of target user.
		[mod]

		@optional.str username: The target user. Defaults to yourself.
		'''
		if username and 'mod' in client.accesslevels:
			if username in self._root.usernames:
				reason = self._root.usernames[username].register_date
				good = True
			else: good, reason = self.userdb.get_registration_date(username)
		else:
			good = True
			username = client.username
			reason = client.register_date
		if good and reason:
			self.out_SERVERMSG(client, '<%s> registered on %s.' % (username, reason.isoformat()))
			return
		self.out_SERVERMSG(client, "Couldn't retrieve registration date for <%s> (%s)" % (username, reason))

	def in_GETUSERID(self, client, username):
		user = self.clientFromUsername(username, True)
		if user:
			self.out_SERVERMSG(client, 'The ID for <%s> is %s' % (username, user.last_id))
		else:
			self.out_SERVERMSG(client, 'User not found.')

	def in_GETACCOUNTACCESS(self, client, username):
		'''
		Get the account access bitfield for target user.
		[mod]

		@required.str username: The target user.
		'''
		good, data = self.userdb.get_account_access(username)
		if good:
			self.out_SERVERMSG(client, 'Account access for <%s>: %s' % (username, data))
		else:
			self.out_SERVERMSG(client, 'Database returned error when retrieving account access for <%s> (%s)' % (username, data))

	def in_FINDIP(self, client, address):
		'''
		Get all usernames associated with target IP address.

		@required.str address: The target IP address.
		'''
		results = self.userdb.find_ip(address)
		for entry in results:
			if entry.username in self._root.usernames:
				self.out_SERVERMSG(client, '<%s> is currently bound to %s.' % (entry.username, address))
			else:
				if entry.last_login:
					lastlogin = entry.last_login.isoformat()
				else:
					lastlogin = "Unknown"
				self.out_SERVERMSG(client, '<%s> was recently bound to %s at %s' % (entry.username, address, lastlogin))

	def in_GETLASTIP(self, client, username):
		'''
		An alias for GETIP.
		'''
		return self.in_GETIP(client, username)

	def in_GETIP(self, client, username):
		'''
		Get the current or last IP address for target user.

		@required.str username: The target user.
		'''
		if username in self._root.usernames:
			self.out_SERVERMSG(client, '<%s> is currently bound to %s' % (username, self._root.usernames[username].ip_address))
			return

		ip = self.userdb.get_ip(username)
		if ip:
			self.out_SERVERMSG(client, '<%s> was recently bound to %s' % (username, ip))

	def in_RENAMEACCOUNT(self, client, newname):
		'''
		Change the name of current user.

		@required.str username: The new username to apply.
		'''
		good, reason = self._validUsernameSyntax(newname)
		if not good:
			self.out_SERVERMSG(client, '%s' %(reason))
			return

		user = client.username
		if user == newname:
			self.out_SERVERMSG(client, 'You already have that username.')
			return
		good, reason = self.userdb.rename_user(user, newname)
		if good:
			self.out_SERVERMSG(client, 'Your account has been renamed to <%s>. Reconnect with the new username (you will now be automatically disconnected).' % newname)
			client.Remove('renaming')
		else:
			self.out_SERVERMSG(client, 'Failed to rename to <%s>: %s' % (newname, reason))


	def in_CHANGEPASSWORD(self, client, cur_password, new_password):
		'''
		Change the password of current user.

		@required.str cur_password: client's current password.
		@required.str new_password: client's desired password.
		'''
		if (cur_password == new_password):
			return

		good, reason = self._validPasswordSyntax(client, new_password)

		if (not good):
			self.out_SERVERMSG(client, '%s' % reason)
			return

		db_user = self.clientFromUsername(client.username, True)

		if (db_user == None):
			return

		if (client.use_secure_session()):
			## secure command (meaning we want our password salted, etc.)
			##
			## disallow converting old-style MD5 password to new-style if
			## command is not encrypted (for obvious reasons: it would be
			## sent in plaintext, unhashed)
			## check if the supplied current password is authentic
			if (not self.userdb.secure_test_user_pwrd(db_user, cur_password)):
				self.out_SERVERMSG(client, 'Incorrect old password.')
				return

			self.userdb.secure_update_user_pwrd(db_user, new_password)
			self.out_SERVERMSG(client, 'Password changed successfully! It will be used at the next login!')
		else:
			if (not self.userdb.legacy_test_user_pwrd(db_user, cur_password)):
				self.out_SERVERMSG(client, 'Incorrect old password.')
				return

			self.userdb.legacy_update_user_pwrd(db_user, new_password)
			self.out_SERVERMSG(client, 'Password changed successfully! It will be used at the next login!')


	def in_GETLOBBYVERSION(self, client, username):
		'''
		Get the lobby version of target user.

		@required.str username: The target user.
		'''
		user = self.clientFromUsername(username, True)
		if user and 'lobby_id' in dir(user):
			self.out_SERVERMSG(client, '<%s> is using %s'%(user.username, user.lobby_id))

	def in_SETBOTMODE(self, client, username, mode):
		'''
		Set the bot flag of target user.

		@required.str username: The target user.
		@required.bool mode: The resulting bot mode.
		'''
		online = False
		user = self.clientFromUsername(username)
		if user:
			online = True
		else: # not online, try to load from db
			user = self.clientFromUsername(username, True)
			if not user:
				return

		bot = (mode.lower() in ('true', 'yes', '1'))
		user.bot = bot
		self.userdb.save_user(user)
		if online:
			self._calc_status(client, client.status)
			self._root.broadcast('CLIENTSTATUS %s %d'%(client.username, client.status))
		self.out_SERVERMSG(client, 'Botmode for <%s> successfully changed to %s' % (username, bot))

	def in_CHANGEACCOUNTPASS(self, client, username, newpass):
		'''
		Set the password for target user.
		[mod]

		@required.str username: The target user.
		@required.str password: The new password.
		'''
		targetUser = self.clientFromUsername(username, True)

		if (not targetUser):
			return
		## if this user has created a secure account, disallow
		## anyone but himself to change his password (there are
		## better methods for account recovery)
		if (not targetUser.has_legacy_password()):
			self.out_SERVERMSG(client, "Password for user %s can not be changed." % username)
			return

		if targetUser.access in ('mod', 'admin') and not client.access == 'admin':
			self.out_SERVERMSG(client, 'You have insufficient access to change moderator passwords.')
			return

		res, reason = self._validLegacyPasswordSyntax(newpass)

		if (not res):
			self.out_SERVERMSG(client, "invalid password specified: %s" %(reason))
			return

		## !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		## THIS IS NOT AN ACTION ADMINS SHOULD BE ABLE TO TAKE
		## !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		self._root.console_write('<%s> changed password of <%s>.' % (client.username, username))
		self.userdb.legacy_update_user_pwrd(targetUser, newpass)
		self.out_SERVERMSG(client, 'Password for <%s> successfully changed to %s' % (username, newpass))



	def in_BROADCAST(self, client, msg):
		'''
		Broadcast a message.

		@required.str message: The message to broadcast.
		'''
		self._root.broadcast('BROADCAST %s'%msg)

	def in_BROADCASTEX(self, client, msg):
		'''
		Broadcast a message to be shown especially by lobby clients.

		@required.str message: The message to broadcast.
		'''
		self._root.broadcast('SERVERMSGBOX %s'%msg)

	def in_ADMINBROADCAST(self, client, msg):
		'''
		Broadcast a message to administrative users.

		@required.str message: The message to broadcast.
		'''
		self._root.admin_broadcast(msg)

	def in_SETLATESTSPRINGVERSION(self, client, version):
		'''
		Set a new version of Spring as the latest.

		@required.str version: The new version to apply.
		'''
		self._root.latestspringversion = version
		self.out_SERVERMSG(client, 'Latest spring version is now set to: %s' % version)

	def in_KICKUSER(self, client, user, reason=''):
		'''
		Kick target user from the server.

		@required.str username: The target user.
		@optional.str reason: The reason to be shown.
		'''
		if user in self._root.usernames:
			kickeduser = self._root.usernames[user]
			if reason: reason = ' (reason: %s)' % reason
			for chan in kickeduser.channels:
				self._root.broadcast('CHANNELMESSAGE %s <%s> kicked <%s> from the server%s'%(chan, client.username, user, reason),chan)
			self.out_SERVERMSG(client, 'You\'ve kicked <%s> from the server.' % user)
			self.out_SERVERMSG(kickeduser, 'You\'ve been kicked from server by <%s>%s' % (client.username, reason))
			kickeduser.Remove('was kicked from server by <%s>: %s' % (client.username, reason))


	def _testlogin(self, username, password):
		'''
		Test logging in as target user. [mod]

		@required.str username: The target user.
		@required.str password: The password to try.
		'''
		good, reason = self._validUsernameSyntax(username)

		if (not good):
			return False

		targetUser = self.clientFromUsername(username, True)

		if (not targetUser):
			return False

		## if this user has created a secure account, disallow
		## anyone but himself to login with it (password should
		## NEVER be shared by user to anyone, including admins)
		if (not targetUser.has_legacy_password()):
			return False

		good, reason = self._validLegacyPasswordSyntax(password)

		if (not good):
			return False

		if (self.userdb.legacy_test_user_pwrd(targetUser, password)):
			return True

		return False

	def in_EXIT(self, client, reason=('Exiting')):
		'''
		Disconnect from the server, with an optional reason.

		optional.str reason: The reason for exiting.
		'''
		if reason: reason = 'Quit: %s' % reason
		else: reason = 'Quit'
		client.Remove(reason)

	def in_LISTCOMPFLAGS(self, client):
		flags = ""
		for flag in flag_map:
			if len(flags)>0:
				flags += " " + flag
			else:
				flags = flag
		client.Send("COMPFLAGS %s" %(flags))

	def in_BAN(self, client, username, duration, reason):
		'''
		Ban target user from the server.

		@required.str username: The target user.
		@required.float duration: The duration in days.
		@required.str reason: The reason to be shown.
		'''
		try: duration = float(duration)
		except:
			self.out_SERVERMSG(client, 'Duration must be a float (the ban duration in days)')
			return
		response = self.userdb.ban_user(client, username, duration, reason)
		if response: self.out_SERVERMSG(client, '%s' % response)

	def in_UNBAN(self, client, username):
		'''
		Remove all bans for target user from the server.

		@required.str username: The target user.
		'''
		response = self.userdb.unban_user(username)
		if response: self.out_SERVERMSG(client, '%s' % response)

	def in_BANIP(self, client, ip, duration, reason):
		'''
		Ban an IP address from the server.

		@required.str ip: The IP address to ban.
		@required.float duration: The duration in days.
		@required.str reason: The reason to show.
		'''
		try: duration = float(duration)
		except:
			self.out_SERVERMSG(client, 'Duration must be a float (the ban duration in days)')
			return
		response = self.userdb.ban_ip(client, ip, duration, reason)
		if response: self.out_SERVERMSG(client, '%s' % response)

	def in_UNBANIP(self, client, ip):
		'''
		Remove all bans for target IP from the server.

		@required.str ip: The target IP.
		'''
		response = self.userdb.unban_ip(ip)
		if response: self.out_SERVERMSG(client, '%s' % response)

	def in_BANLIST(self, client):
		'''
		Retrieve a list of all bans currently active on the server.
		'''
		for entry in self.userdb.banlist():
			self.out_SERVERMSG(client, '%s' % entry)

	def in_SETACCESS(self, client, username, access):
		'''
		Set the access level of target user.

		@required.str username: The target user.
		@required.str access: The new access to apply.
		Access levels: user, mod, admin
		'''
		user = self.clientFromUsername(username, True)
		if not user:
			self.out_SERVERMSG(client, "User not found.")
			return
		if not access in ('user', 'mod', 'admin'):
			self.out_SERVERMSG(client, "Invalid access mode, only user, mod, admin is valid.")
			return
		user.access = access
		if username in self._root.usernames:
			self._calc_access_status(user)
			self._root.broadcast('CLIENTSTATUS %s %d' % (username, user.status))
		self.userdb.save_user(user)
		# remove the new mod/admin from everyones ignore list and notify affected users
		if access in ('mod', 'admin'):
			userIds = self.userdb.globally_unignore_user(user.db_id)
			for userId in userIds:
				userThatIgnored = self.clientFromID(userId)
				if userThatIgnored:
					userThatIgnored.ignored.pop(user.db_id)
					userThatIgnored.Send('UNIGNORE userName=%s' % (username))


	def in_RELOAD(self, client):
		'''
		Reload core parts of the server code from source. This also reparses motd, update list, and trusted proxy file.
		Do not use this for changes unless you are very confident in your ability to recover from a mistake.

		Parts reloaded:
		ChanServ.py
		Protocol.py
		SayHooks.py

		User databases reloaded:
		SQLUsers.py
		LanUsers.py
		'''
		if not 'admin' in client.accesslevels:
		    return
		self._root.reload()
		self._root.console_write("Stats of command usage:")
		for k,v in self.stats.iteritems():
			self._root.console_write("%s %d" % (k, v))

	def in_CLEANUP(self, client):
		nchan = 0
		nbattle = 0
		nuser = 0
		#cleanup battles
		tmpbattle = self._root.battles.copy()
		for battle in tmpbattle:
			for sessionid in self._root.battles[battle].users:
				if not sessionid in self._root.users:
					self._root.console_write("deleting user in battle %s" % user)
					self._root.battles[battle].users.remove(user)
					nuser = nuser + 1
			if not self._root.battles[battle].host in self._root.clients:
				self._root.console_write("deleting battle %s" % battle)
				del self._root.battles[battle]
				nbattle = nbattle + 1
				continue

		#cleanup channels
		tmpchannels = self._root.channels.copy()
		for channel in tmpchannels:
			for session_id in self._root.channels[channel].users:
				if not session_id in self._root.clients:
					self._root.console_write("deleting user %s from channel %s" %(session_id , channel))
					self._root.channels[channel].users.remove(session_id)
			if len(self._root.channels[channel].users) == 0:
				del self._root.channels[channel]
				self._root.console_write("deleting empty channel %s" % channel)
				nchan = nchan + 1

		self.userdb.clean_users()

		self.out_SERVERMSG(client, "deleted channels: %d battles: %d users: %d" %(nchan, nbattle, nuser))

	def in_CHANGEEMAIL(self, client, newmail = None, username = None):
		'''
		Set the email address of target user.

		@optional.str email: Email address to set. if empty current email address will be shown
		@optional.str username: username to set the email address
		'''
		if not client.compat['cl']:
			self.out_SERVERMSG(client, "compatibility flag cl needed")
			return

		if not newmail:
			self.out_SERVERMSG(client,"current email is %s" %(client.email))
			return
		if not username:
			client.email = newmail
			self.userdb.save_user(client)
			self.out_SERVERMSG(client,"changed email to %s"%(client.email))
			return
		user = self.clientFromUsername(username, True)
		if user.access in ('mod', 'admin') and not client.access == 'admin': #disallow mods to change other mods / admins email
			self.out_SERVERMSG(client,"access denied")
			return
		user.email = newmail
		self.userdb.save_user(user)
		self.out_SERVERMSG(client,"changed email to %s"%(user.email))

	##
	## send the server's public RSA key to a client (which
	## the client should use for SETSHAREDKEY iff it wants
	## all further communication encrypted)
	##
	def in_GETPUBLICKEY(self, client):
		## not useful to do this after key-exchange
		if (client.use_secure_session()):
			return

		rsa_pub_key_obj = self.rsa_cipher_obj.get_pub_key()
		rsa_pub_key_str = rsa_pub_key_obj.exportKey(CryptoHandler.RSA_KEY_FMT_NAME)

		session_flag_bits  = 0
		session_flag_bits |= (self.force_secure_auths() << 0)
		session_flag_bits |= (self.force_secure_comms() << 1)
		session_flag_bits |= (self.use_msg_auth_codes() << 2)

		## technically the key does not need to be encoded
		## (PEM is a text-format), but this keeps protocol
		## consistent
		client.Send("PUBLICKEY %s %d" % (ENCODE_FUNC(rsa_pub_key_str), session_flag_bits))

	##
	## sign a client text-message using server's private RSA key
	## the resulting signature is simply a (Python) long integer
	## (should be used by clients prior to LOGIN, to verify that
	## their encryption stack works and server is what it claims
	## to be)
	##
	## enc_msg = ENCODE(MSG)
	##
	def in_GETSIGNEDMSG(self, client, enc_msg = ""):
		assert(type(enc_msg) == unicode)

		if (client.use_secure_session()):
			return

		## grab the MOTD (also in unicode) if needed
		if (len(enc_msg) == 0):
			enc_msg = self._get_motd_string(client)

		enc_msg = enc_msg.encode(UNICODE_ENCODING)
		raw_msg = SAFE_DECODE_FUNC(enc_msg)
		msg_sig = self.rsa_cipher_obj.sign_bytes(raw_msg)

		client.Send("SIGNEDMSG %s" % ENCODE_FUNC(msg_sig))

	##
	## set the AES session key that *this* client and
	## server will use to encrypt all further traffic
	## (if not empty or too short)
	##
	## clients must DECODE(DECRYPT_AES(MSG, AES_KEY))
	## any subsequent server message MSG in case this
	## returns ACCEPTED, where DECODE is the standard
	## base64 decoding scheme
	##
	## enc_key = ENCODE(ENCRYPT_RSA(AES_KEY, RSA_PUB_KEY))
	##
	def in_SETSHAREDKEY(self, client, enc_key = ""):
		assert(type(enc_key) == unicode)

		old_key_str = client.get_session_key()
		old_key_sig = SECURE_HASH_FUNC(old_key_str).digest()
		new_key_str = ""
		new_key_sig = ""

		if (len(enc_key) == 0):
			if (not client.use_secure_session()):
				return
			## no longer allow clients to disable secure sessions
			if (True or self.force_secure_comms()):
				client.Send("SHAREDKEY ENFORCED %s" % ENCODE_FUNC(old_key_sig))
				return

			## take "" to mean the client no longer wants encryption
			## this will be the last encrypted message a client gets
			## (unless the server enforces secure communications, in
			## which case sending unencrypted data after key exchange
			## is pointless because server will always try to decrypt
			## it and be left with garbage in _handle)
			client.Send("SHAREDKEY DISABLED %s" % ENCODE_FUNC(old_key_sig))

			client.set_session_key("")
			client.set_session_key_received_ack(False)
			return

		## NOTE:
		##   the raw client key can be any binary or ASCII string
		##   however, the server will ALWAYS use a hashed version
		##   (the output of HASH(DECODE(DECRYPT_RSA(...)))) so as
		##   to ensure it has the proper length
		try:
			new_key_msg = self.rsa_cipher_obj.decode_decrypt_bytes_utf8(enc_key, SAFE_DECODE_FUNC)
			new_key_str = SECURE_HASH_FUNC(new_key_msg).digest()
			new_key_sig = SECURE_HASH_FUNC(new_key_str).digest()

			## too-short keys (before hashing) are not allowed
			if (len(new_key_msg) < CryptoHandler.MIN_AES_KEY_SIZE):
				client.Send("SHAREDKEY REJECTED %s %d" % (ENCODE_FUNC(new_key_sig), CryptoHandler.MIN_AES_KEY_SIZE))
				return

		except ValueError as val_err:
			client.Send("SHAREDKEY REJECTED %s %s" % (ENCODE_FUNC(new_key_sig), val_err))
			return

		## if this is the first established secure session, must
		## prepare the key a-priori since ACCEPTED should not be
		## sent openly (it includes the new key digest)
		if (not client.use_secure_session()):
			client.Send("SHAREDKEY INITSESS %s" % ENCODE_FUNC(old_key_sig))
			client.set_session_key(new_key_str)
			client.set_session_key_received_ack(True)

		## notify the client that key was accepted, this will be
		## the first encrypted message (client should do NOTHING
		## before it has received this message and verified that
		## the key signature matches that of the key sent to the
		## server, server can NOT communicate further until this
		## gets acknowledged by ENCODE(ENCRYPT_AES(ACKSHAREDKEY))
		## and will always wait for confirmation to use this key)
		##
		assert(client.use_secure_session())
		assert(client.get_session_key_received_ack())

		client.Send("SHAREDKEY ACCEPTED %s" % ENCODE_FUNC(new_key_sig))

		## set (or update) the client's session key a-posteriori
		## block outgoing messages encrypted with this *new* key
		## until ACKSHAREDKEY comes in
		## note: if a client sends *another* SETSHAREDKEY before
		## ACKSHAREDKEY (never a good idea) any buffered outgoing
		## messages will literally become undecipherable
		client.set_session_key(new_key_str)
		client.set_session_key_received_ack(False)

	def in_ACKSHAREDKEY(self, client):
		if (not client.use_secure_session()):
			return
		if (client.get_session_key_received_ack()):
			return

		## client has acknowledged our SHAREDKEY ACCEPTED response
		client.set_session_key_received_ack(True)

	def in_SUBSCRIBE(self, client, subscribeargs):
		args = self._parseTags(subscribeargs)
		if not 'chanName' in args:
			self.out_FAILED(client, "SUBSCRIBE", "chanName missing")
			return
		chan = args['chanName']
		good, reason = self._validChannelSyntax(chan)
		if not good:
			self.out_FAILED(client, "SUBSCRIBE", reason)
			return

		if chan not in self._root.channels:
			self.out_FAILED(client, "SUBSCRIBE", "Channel %s doesn't exist" %(chan))
			return

		channel = self._root.channels[chan]
		if not channel.store_history:
			self.out_FAILED(client, "SUBSCRIBE", "History for channel %s is disabled, can't subscribe!" %(chan))
			return
		good, reason = self.userdb.add_channelhistory_subscription(channel.id, client.db_id)
		if not good:
			self.out_FAILED(client, "SUBSCRIBE", reason)
			return
		self.out_OK(client, "SUBSCRIBE")

	def in_UNSUBSCRIBE(self, client, subscribeargs):
		args = self._parseTags(subscribeargs)
		if not 'chanName' in args:
			self.out_FAILED(client, "UNSUBSCRIBE", "chanName missing")
			return
		chan = args['chanName']
		good, reason = self._validChannelSyntax(chan)
		if not good:
			self.out_FAILED(client, "UNSUBSCRIBE", reason)
			return

		if chan not in self._root.channels:
			self.out_FAILED(client, "UNSUBSCRIBE", "Channel %s doesn't exist" %(chan))
			return

		channel = self._root.channels[chan]
		good, reason = self.userdb.remove_channelhistory_subscription(channel.id, client.db_id)
		if not good:
			self.out_FAILED(client, "UNSUBSCRIBE", reason)
			return
		self.out_OK(client, "UNSUBSCRIBE")

	def in_LISTSUBSCRIPTIONS(self, client):
		subscriptions = self.userdb.get_channel_subscriptions(client.db_id)
		client.Send("STARTLISTSUBSCRIPTION")
		for chan in subscriptions:
			client.Send("LISTSUBSCRIPTION chanName=%s" % (chan))
		client.Send("ENDLISTSUBSCRIPTION")

	# Begin outgoing protocol section #
	#
	# any function definition beginning with out_ and ending with capital letters
	# is a definition of an outgoing command.
	def out_DENIED(self, client, username, reason, inc = True):
		'''
			response to LOGIN
		'''
		if inc:
			client.failed_logins = client.failed_logins + 1

		client.Send("DENIED %s" %(reason))
		self._root.console_write('[%s] Failed to log in user <%s>: %s.'%(client.session_id, username, reason))

	def out_OPENBATTLEFAILED(self, client, reason):
		'''
			response to OPENBATTLE
		'''
		client.Send('OPENBATTLEFAILED %s' % (reason))
		self._root.console_write('[%s] <%s> OPENBATTLEFAILED: %s' % (client.session_id, client.username, reason))

	def out_SERVERMSG(self, client, message, log = False):
		'''
			send a message to the client
		'''
		client.Send('SERVERMSG %s' %(message))
		if log:
			self._root.console_write('[%s] <%s>: %s' % (client.session_id, client.username, message))

	def out_FAILED(self, client, cmd, message, log = False):
		'''
			send to a client when a command failed
		'''
		client.Send('FAILED ' + self._dictToTags({'msg':message, 'cmd':cmd}))
		if log:
			self._root.console_write('[%s] <%s>: %s %s' % (client.session_id, client.username, cmd, message))

	def out_OK(self, client, cmd):
		client.Send('OK ' + self._dictToTags({'cmd': cmd}))

def check_protocol_commands():
	for command in restricted_list:
		if 'in_' + command not in dir(Protocol):
			print("command not implemented: %s" % command)
			return False
	return True
assert(check_protocol_commands())

def make_docs():
	response = []
	cmdlist = dir(Protocol)
	for cmd in cmdlist:
		if cmd.find('in_') == 0:
			docstr = getattr(Protocol, cmd).__doc__ or ''
			cmd = cmd.split('_',1)[1]
			response.append('%s - %s' % (cmd, docstr))
	return response

if __name__ == '__main__':
	if not os.path.exists('docs'):
		os.mkdir('docs')
	f = open('docs/protocol.txt', 'w')
	f.write('\n'.join(make_docs()) + '\n')
	f.close()

	print('Protocol documentation written to docs/protocol.txt')

