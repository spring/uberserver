#!/usr/bin/env python3
# coding=utf-8

import inspect
import time
import re
import sys
import socket
import logging
import datetime
import base64
import json
import traceback

import urllib.request
import _thread as thread

import Channel
import Battle
import BridgedClient

# see https://springrts.com/dl/LobbyProtocol/ProtocolDescription.html#MYSTATUS:client
# max. 8 ranks are possible (rank 0 isn't listed)
# rank, ingame time in hours
ranks = (5, 15, 30, 100, 300, 1000, 3000)

restricted = {
'disabled':set(),
'everyone':set([
	'EXIT',
	'PING',
	'LISTCOMPFLAGS',
	########
	# account recovery / etc
	'RESENDVERIFICATION',
	'RESETPASSWORD',
	'RESETPASSWORDREQUEST',
	########
	# encryption
	'STARTTLS',
	'STLS',
	]),
'fresh':set([
	'LOGIN',
	'REGISTER',
	]),
'agreement':set([
	'CONFIRMAGREEMENT',
	]),
'user':set([
	########
	# battle
	'ADDBOT',
	'ADDSTARTRECT',
	'DISABLEUNITS',
	'ENABLEUNITS',
	'ENABLEALLUNITS',
	'FORCEALLYNO',
	'FORCESPECTATORMODE',
	'FORCETEAMCOLOR',
	'FORCETEAMNO',
	'HANDICAP',
	'JOINBATTLE',
	'JOINBATTLEACCEPT',
	'JOINBATTLEDENY',
	'KICKFROMBATTLE',
	'LEAVEBATTLE',
	'MYBATTLESTATUS',
	'BATTLEHOSTMSG',
	'OPENBATTLE',
	'REMOVEBOT',
	'REMOVESCRIPTTAGS',
	'REMOVESTARTRECT',
	'RING',
	'SETSCRIPTTAGS',
	'UPDATEBATTLEINFO',
	'UPDATEBOT',
	#########
	# channel
	'CHANNELS',
	'CHANNELTOPIC',
	'JOIN',
	'LEAVE',
	'SAY',
	'SAYEX',
	'SAYPRIVATE',
	'SAYPRIVATEEX',
	'GETCHANNELMESSAGES',
	########
	# account management
	'GETUSERINFO',
	'RENAMEACCOUNT',
	'CHANGEPASSWORD',
	'CHANGEEMAILREQUEST',
	'CHANGEEMAIL',
	'RESENDVERIFICATION',
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
	# meta
	'MYSTATUS',
	'PORTTEST',
	'JSON',
	########
	# bridge bots
	'BRIDGECLIENTFROM',
	'UNBRIDGECLIENTFROM',
	'JOINFROM',
	'LEAVEFROM',
	'SAYFROM',
	# deprecated
	########
	'MUTE',
	'MUTELIST',
	'SETCHANNELKEY',
	'UNMUTE',
	'SAYBATTLE',
	'SAYBATTLEEX',
	'SAYBATTLEPRIVATEEX',
	'FORCELEAVECHANNEL',
	'GETINGAMETIME',
	]),
'mod':set([
	# users
	'GETUSERID',
	'GETIP',
	'FINDIP',
	'SETBOTMODE',
	'CREATEBOTACCOUNT',
	'RESETUSERPASSWORD',
	# kick/ban/etc
	'KICK',
	'BAN',
	'BANSPECIFIC',
	'UNBAN',
	'BLACKLIST',
	'UNBLACKLIST',
	'LISTBANS',
	'LISTBLACKLIST',
	]),
'admin':set([
	#########
	# server
	'ADMINBROADCAST',
	'BROADCAST',
	'BROADCASTEX',
	'SETMINSPRINGVERSION',
	#########
	# users
	'SETACCESS',
	'DELETEACCOUNT',
	'LISTMODS',
	#########
	# dev
	'STATS',
	'RELOAD',
	'CLEANUP',
	]),
}

restricted_list = set()
for level in restricted:
	for cmd in restricted[level]:
		restricted_list.add(cmd)

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


# supported flags
flag_map = {
	'u':  'say2',            # SAYFROM, Battle<->Channel unification
	'sp': 'scriptPassword',  # scriptPassword in JOINEDBATTLE
	'b':  'battleAuth',      # JOINBATTLEACCEPT/JOINBATTLEDENIED (typically only sent by autohosts)
}
# optional flags
optional_flags = (
	'b', # only useful to autohosts -> permanently optional
)

# flags for functionality that is now either compulsory or was removed
deprecated_flags = (
	'cl',# BATTLEOPENED / OPENBATTLE with support for engine/version, now mandatory
	't', # CHANNELTOPIC without times, always sent and allowing empty topic string, now mandatory
	'l', # send account IDs and lobby IDs in ADDUSER (supersedes 'a'), now mandatory
	'a', # superceded by 'l'
	'm', # matchmaking, removed
	'p', # plain text user agreement, now mandatory
	'et', # NOCHANNELTOPIC, removed
)

class Protocol:
	def __init__(self, root):
		self._root = root

		self.userdb = root.getUserDB()
		self.verificationdb = root.getVerificationDB()
		self.bandb = root.getBanDB()
		self.contentdb = root.getContentDB()
		self.SayHooks = root.SayHooks

		self.restricted = restricted
		self.restricted_list = restricted_list
		
		self.ipRegex = r"^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$"
		self.ipRegex_compiled = re.compile(self.ipRegex)
		
	def _checkCompat(self, client):
		missing_TLS = not client.TLS

		missing_flags = ""
		for flag in flag_map:
			if not flag in optional_flags and not flag in client.compat:
				missing_flags += ' ' + flag

		deprec_flags = ""
		unknown_flags = ""
		for flag in client.compat:
			if flag in deprecated_flags:
				deprec_flags += ' ' + flag
				continue
			if not flag in flag_map:
				unknown_flags += ' ' + flag

		client.RealSend("MOTD Server version: %s" % self._root.server_version)
		
		compat_error = len(missing_flags)>0 or len(deprec_flags)>0 or len(unknown_flags)>0
		error = missing_TLS or compat_error
		if not error:
			return

		client.RealSend("MOTD  -- WARNING --")

		if missing_TLS:
			client.RealSend("MOTD Your client did not use TLS. Your connection is not secure.")
			client.RealSend("MOTD  -- -- - -- --")
			logging.info('[%s] <%s> client "%s" logged in without TLS' % (client.session_id, client.username, client.agent))

		if compat_error:
			client.RealSend("MOTD Your client has compatibility errors")
			if len(missing_flags)>0: client.RealSend("MOTD   missing flags:%s" % missing_flags)
			if len(deprec_flags)>0: client.RealSend("MOTD   deprecated flags:%s" % deprec_flags)
			if len(unknown_flags)>0: client.RealSend("MOTD   unknown flags:%s" % unknown_flags)
			client.RealSend("MOTD  -- -- - -- --")
			logging.info('[%s] <%s> client "%s" sent incorrect compat flags %s -- missing:%s, deprecated:%s, unknown:%s'%(client.session_id, client.username, client.agent, client.compat, missing_flags, deprec_flags, unknown_flags))

		client.RealSend("MOTD Please update your client / report these issues.")
		client.RealSend("MOTD  -- -- - -- --")

	def _new(self, client):
		login_string = ' '.join((self._root.server, str(self._root.server_version), '*', str(self._root.natport), '0'))
		if self._root.redirect:
			login_string += "\nREDIRECT " + self._root.redirect

		client.Send(login_string)

		if self._root.redirect:
			# this will make the server not accepting any commands
			# the client will be disconnected with "Connection timed out, didn't login"
			client.removing = True
		logging.info('[%s] Client connected from %s:%s' % (client.session_id, client.ip_address, client.port))

	def _remove(self, client, reason='Quit'):
		if client.static: return # static clients don't disconnect
		if not client.logged_in:
			logging.info('[%s] disconnected from %s: %s'%(client.session_id, client.ip_address, reason))
			return
		logging.info('[%s] <%s> disconnected from %s: %s'%(client.session_id, client.username, client.ip_address, reason))

		# remove all references related to the client
		bridge = client.bridge
		for location in bridge:
			for external_id in bridge[location].copy():
				bridged_id = bridge[location][external_id]
				bridgedClient = self._root.bridgedClientFromID(bridged_id)
				bridgedClient_channels = bridgedClient.channels.copy()
				for chan in bridgedClient_channels:
					self.in_LEAVEFROM(client, chan, bridgedClient.location, bridgedClient.external_id)
				self.in_UNBRIDGECLIENTFROM(client, bridgedClient.location, bridgedClient.external_id)
			del self._root.bridged_locations[location]

		self.removePendingBattle(client)
		if client.current_battle:
			self.in_LEAVEBATTLE(client)
		for chan in list(client.channels):
			channel = self._root.channels[chan]
			self.in_LEAVE(client, chan, 'disconnected')
			
		user = client.username
		if user in self._root.usernames:
			del self._root.usernames[user]
		if client.user_id in self._root.user_ids:
			del self._root.user_ids[client.user_id]
		#note: self._root.clients is managed by twistedserver.py

		self.userdb.end_session(client.user_id)

		# inform that the client left
		self.broadcast_RemoveUser(client)


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
		assert(type(msg) == str)

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

		if command not in self.restricted_list:
			if args and len(args)>64:
				args = args[:64] + "..."				
			self.out_SERVERMSG(client, "%s failed. Unknown command. (args='%s')" % (command, args), True)
			return False

		for level in client.accesslevels:
			if command in self.restricted[level]:
				allowed = True
				break

		if (not allowed):
			self.out_SERVERMSG(client, '%s failed. Insufficient rights.' % command, True)
			return False

		function = getattr(self, 'in_' + command)

		# update statistics
		self._root.inbound_command_stats[command] = self._root.inbound_command_stats.get(command, 0) + 1 # ignore when RealSend is used directly

		ret_status, fun_args = self.get_function_args(client, command, function, numspaces, args)
		
		if (ret_status):
			# if fun_args is empty, this reduces to function(client)
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
		client = self.clientFromUsername(username)
		if not client:
			return
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

	def clientFromID(self, user_id, fromdb=False):
		return self._root.clientFromID(user_id, fromdb)
	
	def clientFromUsername(self, username, fromdb=False):
		return self._root.clientFromUsername(username, fromdb)
	
	def clientFromSession(self, session_id):
		return self._root.clientFromSession(session_id)
	
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

	def _pretty_time_delta(self, duration):
		#given a timedelta, return a human readable time format
		days = duration.days
		hours, remainder = divmod(duration.seconds, 3600)
		minutes, seconds = divmod(remainder, 60)
		if days > 900:
			return 'a long time'
		pretty = ''
		if days > 0:
			pretty += '%d days ' % (days)
		if (days>0 and minutes>0) or hours > 0:
			pretty += '%d hours ' % (hours)
		if (days>0 and hours>0) or minutes > 0:
			pretty += '%d minutes ' % (minutes)
		if days == 0 and hours == 0 and minutes == 0:
			pretty += '%d seconds ' % (seconds)
		return pretty.strip()

	def _get_motd_string(self, client):
		motd_string = ""
		uptime_seconds = time.time() - self._root.start_time
		uptime = datetime.timedelta(seconds=uptime_seconds)
		replace_vars = {
			"{USERNAME}": str(client.username),
			"{CLIENTS}" : str(len(self._root.clients)),
			"{CHANNELS}": str(len(self._root.channels)),
			"{BATTLES}" : str(len(self._root.battles)),
			"{UPTIME}"  : str(self._pretty_time_delta(uptime)),
			"{MINSPRINGVERSION}" : str(self._root.min_spring_version),
		}
		if (self._root.motd):
			for line in self._root.motd:
				for key, value in replace_vars.items():
					line = line.replace(key, value)

				motd_string += line
				motd_string += '\n'
		else:
			motd_string += "[MOTD]"

		return motd_string

	def _sendMotd(self, client, motd_string):
		# send the message of the day to client
		motd_lines = motd_string.split('\n')

		for line in motd_lines:
			client.RealSend('MOTD %s' % line)
			
	def _versiontuple(self, version):
		assert(len(version) > 0)
		v = ""
		for c in version:
			if c not in "0123456789.":
				break
			v+=c
		version_tuple = tuple(map(int, (v.split("."))))
		if len(version_tuple) == 1:
			version_tuple += (0,)
		return version_tuple
	
	def _validEngineVersion(self, engine, version):
		if engine != "spring":
			return False
		minver = self._root.min_spring_version
		if minver == '*':
			return True
		if not version:
			return False
		return self._versiontuple(version) >= self._versiontuple(minver)

	def _validateIP(self, ipAddress):
		return self.ipRegex_compiled.match(ipAddress)
	
	def _validLegacyPasswordSyntax(self, password):
		# checks if an old-style password is correctly encoded
		if (not password):
			return False, 'Empty passwords are not allowed.'

		assert(type(password) == str)
		try:
			md5hash = base64.b64decode(password)
		except Exception as e:
			return False, "Invalid base64-encoding: %s" %(str(e))
		if (md5hash == password):
			return False, "Invalid base64-encoding."
		if (len(md5hash) != 16):
			return False, "Invalid MD5-checksum."

		## assume (!) this is a valid legacy-hash checksum
		return True, ""

	def _validPasswordSyntax(self, password):
		assert(type(password) == str)

		if (not password):
			return False, "Empty password."

		return (self._validLegacyPasswordSyntax(password))

	def _validUsernameSyntax(self, username):
		# checks if usernames syntax is correct / doesn't contain invalid chars
		if not username:
			return False, 'Username is blank.'
		for char in username:
			if not char.lower() in 'abcdefghijklmnopqrstuvwzyx[]_1234567890':
				return False, 'Only ASCII chars, [], _, 0-9 are allowed in usernames.'
		if len(username) < 3:
			return False, "Username is too short, must be at least 3 characters."		
		if len(username) > 20:
			return False, "Username is too long, max 20 characters."
		return True, ""

	def _validLoginSentence(self, sentence):
		# length checks
		if sentence.count('\t') != 2: return False
		lo, la, fl = sentence.split('\t',2)
		if len(lo)>64 or len(la)>40: return False
		i = la
		if ' ' in la:
			i,m = la.split(' ',1)
			if len(m) > 16: return False
			try: m = int(m,16)
			except: return False
		try: i = uint32(i)
		except: return False		
		for char in fl:
			if not char in 'abcdefghijklmnopqrstuvwzyx ':
				return False
		return True
	
	def _validChannelSyntax(self, channel):
		# checks if usernames syntax is correct / doesn''t contain invalid chars
		for char in channel:
			if not char.lower() in 'abcdefghijklmnopqrstuvwzyx[]_1234567890':
				return False, 'Only ASCII chars, [], _, 0-9 are allowed in channel names.'
		if len(channel) > 20:
			return False, "Channel name '%s' is too long, max is 20 chars." % channel
		return True, ""

	def _validBridgeSyntax(self, location, external_id, external_username):
		if not external_id: return False, 'external_id is blank.'
		if not location: return False,'location is blank.'
		if not external_username: return False,'external_username is blank.'
		for char in external_username:
			if not char.lower() in 'abcdefghijklmnopqrstuvwzyx[]_1234567890#':
				return False, "external_username '%s' is invalid: only ASCII chars, [], _, 0-9 and # are allowed in bridged usernames." % external_username
		if len(external_username) > 20:
			return False, "external_username '%s' is too long, max is 20 chars." % external_username
		if ':' in external_id:
			return False, "Char : is not allowed in external_id"
		for char in location:
			if not char.lower() in 'abcdefghijklmnopqrstuvwzyx[]_1234567890.': # must be a superset of username chars
				return False, 'Only ASCII chars, [], _, 0-9 and . are allowed in location names.'
		if len(external_id)>20:
			return False, "external_id '%s' is too long, max is 20 chars." % external_id
		if len(location)>20:
			return False, "location '%s' is too long, max is 20 chars." % location
		return True, ''

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

	def _getNextBattleId(self):
		self._root.nextbattle += 1 
		id = self._root.nextbattle
		return id

	def getCurrentBattle(self, client):
		if not client.current_battle:
			return False
		battle_id = client.current_battle
		if not battle_id in self._root.battles:
			logging.error("Invalid battle (id %i) stored for client %d %s" % (battle_id, client.session_id, client.username))
			return False
		return self._root.battles[battle_id]

	def broadcast_AddBattle(self, battle):
		for cid, client in self._root.usernames.items():
			client.Send(self.client_AddBattle(client, battle))

	def broadcast_RemoveBattle(self, battle):
		for cid, client in self._root.usernames.items():
			client.Send('BATTLECLOSED %s' % battle.battle_id)

	def broadcast_SendBattle(self, battle, data, sourceClient=None, flag=None, not_flag=None):
		# the sourceClient is only sent for SAY*, and RING commands
		if sourceClient:
			user_id = sourceClient.user_id
			if user_id in battle.mutelist:
				endtime = battle.mutelist[user_id]
				if endtime > datetime.datetime.now():
					self.out_SERVERMSG(sourceClient, "SAY You are muted in this battle until %s!" %(endtime))
				else:
					battle.mutelist.remove[user_id]

		for session_id in battle.users:
			client = self.clientFromSession(session_id)
			if flag and not flag in client.compat:
				continue
			if not_flag and not_flag in client.compat:
				continue
			if sourceClient == None or not sourceClient.user_id in client.ignored:
				client.Send(data)

	def broadcast_AddUser(self, client):
		for name, receiver in self._root.usernames.items():
			if client.session_id == receiver.session_id: # don't send ADDUSER to self
				continue
			if client.username == receiver.username:
				logging.error("Tried to send adduser to self: %s!"% client.username)
				continue
			receiver.Send(self.client_AddUser(receiver, client))

	def broadcast_RemoveUser(self, client):
		for name, receiver in self._root.usernames.items():
			if client.static:
				continue
			if not name == client.username:
				self.client_RemoveUser(receiver, client)

	def broadcast_Moderator(self, message):
		self.in_SAY(self._root.chanserv, 'moderator', message)

	def client_AddUser(self, receiver, user):
		'sends the protocol for adding a user'
		return 'ADDUSER %s %s %s %s' % (user.username, user.country_code, user.user_id, user.agent)

	def client_RemoveUser(self, client, user):
		'sends the protocol for removing a user'
		assert(len(user.username) > 0)
		client.Send('REMOVEUSER %s' % user.username)

	def client_AddBattle(self, client, battle):
		'sends the protocol for adding a battle'

		host = self.clientFromSession(battle.host)
		if host.ip_address == client.ip_address: # translates the ip to always be compatible with the client
			translated_ip = host.local_ip
		else:
			translated_ip = host.ip_address

		battle.ip = translated_ip
		battle.host = host.session_id # session_id -> username
		if 'u' in client.compat: 
			return 'BATTLEOPENED %s %s %s %s %s %s %s %s %s %s %s\t%s\t%s\t%s\t%s\t%s' %(battle.battle_id, battle.type, battle.natType, host.username, battle.ip, battle.port, battle.maxplayers, battle.passworded(), battle.rank, battle.maphash, battle.engine, battle.version, battle.map, battle.title, battle.modname, battle.name)
		return 'BATTLEOPENED %s %s %s %s %s %s %s %s %s %s %s\t%s\t%s\t%s\t%s' %(battle.battle_id, battle.type, battle.natType, host.username, battle.ip, battle.port, battle.maxplayers, battle.passworded(), battle.rank, battle.maphash, battle.engine, battle.version, battle.map, battle.title, battle.modname)
	
	def is_ignored(self, client, ignoredClient):
		# verify that this is an online client (only those have an .ignored attr)
		if hasattr(client, "ignored"):
			return ignoredClient.user_id in client.ignored
		else:
			return self.userdb.is_ignored(client.user_id, ignoredClient.user_id)

	def ignore_user(self, client, ignoreClient, reason=None):
		self.userdb.ignore_user(client.user_id, ignoreClient.user_id, reason)
		client.ignored[ignoreClient.user_id] = True

	def unignore_user(self, client, unignoreClient):
		self.userdb.unignore_user(client.user_id, unignoreClient.user_id)
		client.ignored.pop(unignoreClient.user_id)

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
		sock.close()

	def in_STLS(self, client):
		self.out_OK(client, "STLS")
		client.StartTLS()
		client.flushBuffer()
		client.Send(' '.join((self._root.server, str(self._root.server_version), '*', str(self._root.natport), '0')))

	def in_REGISTER(self, client, username, password, email = ''):
		'''
		Register a new user in the account database.

		@required.str username: Username to register
		@required.str password: Password to use (old-style: BASE64(MD5(PWRD)), new-style: BASE64(PWRD))
		'''

		# well formed-ness tests
		good, reason = self._validUsernameSyntax(username)
		good, reason = self._validPasswordSyntax(password)
		if not good:
			client.Send("REGISTRATIONDENIED %s" % (reason))
			return

		# test if user would be OK on db side (e.g. duplication)
		email = email.lower()
		good, reason = self.userdb.check_register_user(username, email, client.ip_address)
		if (not good):
			logging.info('[%s] Registration failed for user <%s>: %s' % (client.session_id, username, reason))
			client.Send('REGISTRATIONDENIED %s' % reason)
			return

		# require a valid looking email address, if we are going to require verification
		if self.verificationdb.active():
			good, reason = self.verificationdb.valid_email_addr(email)
			if not good:
				if email=='': reason += " -- If you were not asked to enter one, please update your lobby client!"
				client.Send('REGISTRATIONDENIED %s' % reason)
				return
		else:
			email = None # avoid triggering uniqueness constraint with empty strings

		# rate limit per ip
		recent_regs = self._root.recent_registrations.get(client.ip_address, 0)
		if recent_regs >= 3 and client.ip_address != self._root.online_ip:
			client.Send("REGISTRATIONDENIED too many recent registration attempts, please try again later")
			return
		self._root.recent_registrations[client.ip_address] = recent_regs + 1

		#save user to db
		self.userdb.register_user(username, password, client.ip_address, email)
		client_fromdb = self.clientFromUsername(username, True)

		# verification
		verif_reason = "registered an account on the SpringRTS lobbyserver (username: %s)" % username
		good, reason = self.verificationdb.check_and_send(client_fromdb.user_id, email, 4, verif_reason)
		if (not good):
			client.Send("REGISTRATIONDENIED %s" % ("verification failed: " + reason))
			return

		# declare success
		client.access = 'agreement'
		client.Send('REGISTRATIONACCEPTED')
		
		try: 
			thread.start_new_thread(self._check_nonresidential_ip, (client_fromdb.user_id, client_fromdb.username, client.ip_address))
		except: 
			logging.error('Failed to launch _check_nonresidential_ip: %s, %s, %s' % (client_fromdb.user_id, client_fromdb.username, client.ip_address))

		logging.info('[%s] Successfully registered user <%s>.' % (client.session_id, username))
		ip_str = client.ip_address
		if client.local_ip != client.ip_address:
			ip_str += " " + client.local_ip
		self.broadcast_Moderator('New: %s %s %s' %(username, ip_str, client.country_code))
	
	def _check_nonresidential_ip(self, user_id, username, ip_address):
		if not self._root.iphub_xkey:
			return
		if ip_address == self._root.online_ip:
			block = -1
		elif ip_address in self._root.ip_type_cache:
			block = self._root.ip_type_cache[ip_address]
		else:
			try:
				response = urllib.request.Request("http://v2.api.iphub.info/ip/{}".format(ip_address))
				response.add_header("X-Key", self._root.iphub_xkey)
				response = json.loads(urllib.request.urlopen(response).read().decode())
			except Exception as e:
				logging.error('Failed to check ip info for %s: %s' % (ip_address, str(e)))
				return
			block = response.get("block")
			self._root.ip_type_cache[ip_address] = block
		logging.info("<%s> ip %s has type %d" % (username, ip_address, block))
		if block == 1:
			self._root.nonres_registrations.add(user_id) # relies on GIL for thread safety!
			
	def _check_delayed_registration(self, client):
		if client.user_id in self._root.nonres_registrations: 
			time_waited = datetime.datetime.now() - client.register_date
			if time_waited.days == 0 and time_waited.seconds < 24*3600:
				time_remaining = datetime.timedelta(1,0,0) - time_waited
				return True, 'Your registration was detected as a non-residential IP address and will be delayed for 24 hours. Time remaining: %s' % self._pretty_time_delta(time_remaining)
			else:
				self._root.nonres_registrations.remove(client.user_id)
		return False, ''

	def in_LOGIN(self, client, username, password, cpu='0', local_ip='', sentence_args=''):
		'''
		Attempt to login the active client.

		@required.str username: Username
		@required.str password: Password BASE64(MD5(PWRD))
		@optional.int cpu: deprecated
		@optional.ip local_ip: LAN IP address, sent to clients when they have the same WAN IP as host
		@optional.sentence.str agent: Lobby name and version
		@optional.sentence.int user_id: User ID provided by lobby
		@optional.sentence.str compat_flags: Compatibility flags, sent in space-separated form, see lobby protocol docs for details
		'''

		if username in self._root.usernames:
			self.out_DENIED(client, username, 'Already logged in.')
			return
		
		if self.SayHooks.isNasty(username):
			self.out_DENIED(client, username, "Invalid username: '%s'" % username)
			return

		good, reason = self.userdb.check_login_user(username, password)
		if not good:
			self.out_DENIED(client, username, reason)
			return
		
		delay, reason = self._check_delayed_registration(client)
		if delay:
			self.out_DENIED(client, username, reason)
			return
 		
		banned, reason = self.userdb.check_banned(username, client.ip_address)
		if banned:
			assert (type(reason) == str)
			self.out_DENIED(client, username, reason)
			return			
			
		if self.SayHooks.isNasty(sentence_args):
			self.out_DENIED(client, username, "Invalid sentence args")
			return
		if sentence_args.count('\t')==0: # fixme: backwards compat for Melbot / Statserv
			agent = sentence_args
			last_sys_id = "0"
			last_mac_id = "0"
		elif not self._validLoginSentence(sentence_args):
			logging.warning("Invalid login sentence '%s' from <%s>" % (sentence_args, username))
			self.out_DENIED(client, username, 'Invalid sentence format, please update your lobby client.')
			return
		else: 
			agent, last_id, compat_flags = sentence_args.split('\t',2)
			if " " in last_id:
				last_mac_id, last_sys_id = last_id.split(" ") 
			else:
				last_mac_id = last_id 
				last_sys_id = "0" # backwards compat for SL<0.269
			for flag in compat_flags.split(' '):
				client.compat.add(flag)
		
		# login checks complete
		dbuser = self.userdb.login_user(username, password, client.ip_address, agent, last_sys_id, last_mac_id, local_ip, client.country_code)			

		# update local client fields from DB User values
		client.access = dbuser.access
		self._calc_access(client)
		client.username = dbuser.username
		client.password = dbuser.password
		client.user_id = dbuser.id
		client.bot = dbuser.bot
		client.last_ip = dbuser.last_ip
		client.last_agent = dbuser.last_agent
		client.last_sys_id = dbuser.last_sys_id
		client.last_mac_id = dbuser.last_mac_id
		client.register_date = dbuser.register_date
		client.last_login = dbuser.last_login
		client.ingame_time = dbuser.ingame_time
		client.email = dbuser.email
		client.agent = agent
	
		if (client.access == 'agreement'):
			logging.info('[%s] Sent user <%s> the terms of service on session.' % (client.session_id, dbuser.username))
			if self.verificationdb.active():
				client.Send("AGREEMENT A verification code has been sent to your email address. Please read our terms of service and then enter your four digit code below.")
				client.Send("AGREEMENT ")
			for line in self._root.agreement:
				client.Send("AGREEMENT %s" %(line))
			client.Send('AGREEMENTEND')
			return
		
		client.local_ip = local_ip
		if local_ip.startswith('127.') or not self._validateIP(local_ip):
			client.local_ip = client.ip_address

		if client.ip_address in self._root.trusted_proxies:
			client.setFlagByIP(local_ip, False)
	
		try:
			assert(username == client.username)
			assert(not client.user_id in self._root.user_ids)
			assert(not client.username in self._root.usernames)
		except Exception as e:
			logging.error("Exception from LOGIN asserts: %s %s %d" % (username, client.username, client.user_id))
			logging.error(traceback.format_exc())
		
		self._root.client_LoginStats(client)
		self._SendLoginInfo(client)

	def _SendLoginInfo(self, client):
		self._calc_status(client, 0)
		client.logged_in = True
		client.buffersend = True # enqeue all sends to client made from other threads until server state is send

		self._root.user_ids[client.user_id] = client
		self._root.usernames[client.username] = client

		logging.info('[%s] <%s> logged in (access=%s).' % (client.session_id, client.username, client.access))
		ignoreList = self.userdb.get_ignored_user_ids(client.user_id)
		client.ignored = {ignoredUserId:True for ignoredUserId in ignoreList}

		client.RealSend('ACCEPTED %s' % client.username)

		self._sendMotd(client, self._get_motd_string(client))
		self._checkCompat(client)

		for sessid, addclient in self._root.clients.items():
			if not addclient.logged_in:
				continue
			client.RealSend(self.client_AddUser(client, addclient))

		for battleid, battle in self._root.battles.items():
			client.RealSend(self.client_AddBattle(client, battle))
			client.RealSend('UPDATEBATTLEINFO %s %i %i %s %s' % (battle.battle_id, battle.spectators, battle.locked, battle.maphash, battle.map))
			for session_id in battle.users:
				battleclient = self.clientFromSession(session_id)
				if not battleclient.session_id == battle.host:
					client.RealSend('JOINEDBATTLE %s %s' % (battle.battle_id, battleclient.username))

		# client status is sent last, so battle status is calculated correctly updated at clients
		for sessid, addclient in self._root.clients.items():
			if not addclient.logged_in:
				continue
			if addclient.status == 0:
				continue
			client.RealSend('CLIENTSTATUS %s %d' % (addclient.username, addclient.status))

		client.RealSend('LOGININFOEND')
		client.flushBuffer()
		self.broadcast_AddUser(client) # send ADDUSER to all clients except self
		if client.status != 0:
			self._root.broadcast('CLIENTSTATUS %s %d'%(client.username, client.status)) # broadcast current client status
		if not client.bot and 'mod' in client.accesslevels:
			self.in_JOIN(client, "moderator")


	def in_CONFIRMAGREEMENT(self, client, verification_code = ""):
		# Confirm the terms of service as shown with the AGREEMENT commands. (Users must accept the terms of service to use their account.)
		# Verify the users verification code.
		if client.access != 'agreement':
			return
		
		time_waited = datetime.datetime.now() - client.register_date
		if time_waited.days == 0 and time_waited.seconds < 2:
			self.out_DENIED(client, client.username, "Please take at least a few seconds to read our terms of service!")
			return
		
		delay, reason = self._check_delayed_registration(client)
		if delay:
			self.out_DENIED(client, client.username, reason)
			return
		
		good, reason = self.verificationdb.verify(client.user_id, client.email, verification_code)
		if not good:
			self.out_DENIED(client, client.username, reason)
			return

		ip_string = ""
		if client.ip_address != client.last_ip:
			ip_string = client.ip_address + " "
		self.broadcast_Moderator('Agr: %s %s %s %s %s' %(client.username, ip_string, client.last_sys_id, client.last_mac_id, client.agent))
		client.access = 'user'
		self.userdb.save_user(client)
		self._calc_access_status(client)
		self._SendLoginInfo(client)

	def in_CREATEBOTACCOUNT(self, client, username, from_username, founder_username=None):
		# Create a new botflagged account with a blank email & the same password as from_username
		# register its battle to founder_username
		good, reason = self._validUsernameSyntax(username)
		if not good:
			self.out_FAILED(client, "CREATEBOTACCOUNT", "Invalid username '%s'" % username, True)
			return

		from_client = self.clientFromUsername(from_username, True)
		if not from_client:
			self.out_FAILED(client, "CREATEBOTACCOUNT", "User does not exist '%s'" % from_username, True)
			return
		password = from_client.password
		ip_address = from_client.ip_address
		country_code = from_client.country_code
		email = None # bots don't have email

		good, reason = self.userdb.check_register_user(username)
		if (not good):
			self.out_FAILED(client, "CREATEBOTACCOUNT", reason, True)
			return

		# set founder, if wanted
		founder = None
		if founder_username:
			founder = self.clientFromUsername(founder_username, True)
			if not founder:
				self.out_FAILED(client, "CREATEBOTACCOUNT", "User does not exist '%s'" % founder_username, True)
				return
			chan = '__battle__' + str(bot_client.user_id)
			channel = Channel.Channel(self._root, chan)
			self._root.channels[chan] = channel
			self._root.chanserv.Handle("SAIDPRIVATE %s :register %s %s" % (client.username, chan, founder.username))

		#save new bot user to db
		self.userdb.register_user(username, password, ip_address, email)
		bot_client = self.clientFromUsername(username, True)
		bot_client.access = 'user'
		bot_client.bot = True
		self.userdb.save_user(bot_client)

		# declare success
		self.broadcast_Moderator('New bot: <%s> created by <%s> from <%s>' %(username, client.username, from_client.username))
		msg = "A new bot account <%s> has been created, with the same password as <%s>" % (bot_client.username, from_client.username)
		if founder:
			msg += ", and battle founder <%s>" % founder.username
		self.out_SERVERMSG(client, msg)
		if client != from_client:
			self.out_SERVERMSG(from_client, msg)


	def in_SAY(self, client, chan, msg):
		'''
		Send a message to all users in specified channel.
		The client must be in the channel to send it a message.

		@required.str channel: The target channel.
		@required.str message: The message to send.
		'''
		if not msg: 
			return
		if not chan in self._root.channels:
			self.out_FAILED(client, "SAY", "Channel %s does not exist", False)
			return
		channel = self._root.channels[chan]
		if not client.session_id in channel.users:
			self.out_FAILED(client, "SAY", "Not present in channel %s" % chan, False)
			return
		msg = self.SayHooks.hook_SAY(self, client, channel, msg)
		if not msg or not msg.strip(): 
			return
		if channel.isMuted(client):
			client.Send('CHANNELMESSAGE %s You are %s.' % (chan, channel.getMuteMessage(client)))
			return
		if channel.store_history:
			self.userdb.add_channel_message(channel.id, client.user_id, None, msg, False)

		self._root.broadcast('SAID %s %s %s' % (chan, client.username, msg), chan, set([]), client, 'u')
		
		# backwards compat
		if hasattr(client, 'current_battle') and client.current_battle:
			battle = self._root.battles[client.current_battle]
			if battle.name==chan:
				self.broadcast_SendBattle(battle, 'SAIDBATTLE %s %s' % (client.username, msg), client, None, 'u')
				return
		self._root.broadcast('SAID %s %s %s' % (chan, client.username, msg), chan, set([]), client, None, 'u')


	def in_SAYEX(self, client, chan, msg):
		'''
		Send an action to all users in specified channel.
		The client must be in the channel to show an action.

		@required.str channel: The target channel.
		@required.str message: The action to send.
		'''
		if not msg: 
			return
		if not chan in self._root.channels:
			self.out_FAILED(client, "SAYEX", "Channel %s does not exist", False)
			return
		channel = self._root.channels[chan]
		if not client.session_id in channel.users:
			self.out_FAILED(client, "SAYEX", "Not present in channel %s" % chan, False)
			return
		msg = self.SayHooks.hook_SAY(self, client, channel, msg)
		if not msg or not msg.strip(): 
			return
		if channel.isMuted(client):
			client.Send('CHANNELMESSAGE %s You are %s.' % (chan, channel.getMuteMessage(client)))
			return
		if channel.store_history: 
			self.userdb.add_channel_message(channel.id, client.user_id, None, msg, True)

		self._root.broadcast('SAIDEX %s %s %s' % (chan, client.username, msg), chan, set([]), client, 'u')

		# backwards compat
		if hasattr(client, 'current_battle') and client.current_battle:
			battle = self._root.battles[client.current_battle]
			if battle.name==chan:
				self.broadcast_SendBattle(battle, 'SAIDBATTLEEX %s %s' % (client.username, msg), client, None, 'u')
				return
		self._root.broadcast('SAIDEX %s %s %s' % (chan, client.username, msg), chan, set([]), client, None, 'u')


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
			logging.info('[%s] <%s>: user to pm is not online: %s' % (client.session_id, client.username, user))
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

	def in_BATTLEHOSTMSG(self, client, battle_name, username, msg):
		# battle host sends a 'servermsg' style message, within a battle to a single user
		battle = self.getCurrentBattle(client)
		if not battle:
			return
		if client.session_id != battle.host:
			return
		if battle.name != battle_name:
			return
		user = self.clientFromUsername(username)
		if not user:
			return
		if not user.session_id in battle.users:
			return
		if self.is_ignored(user, client) or client.user_id in battle.mutelist:
			return
		if not 'u' in user.compat:
			user.Send('SAIDBATTLEEX %s %s' % (client.username, msg))
			return
		user.Send('SAIDEX %s %s %s' % (battle.name, client.username, msg))

	def in_BRIDGECLIENTFROM(self, client, location, external_id, external_username):
		# add external user to the bridge
		if not 'u' in client.compat:
			self.out_FAILED(client, "BRIDGECLIENTFROM", "You need the 'u' compatibility flag to bridge clients", True)
			return
		if not client.bot:
			if not client.isHosting():
				self.out_FAILED(client, "BRIDGECLIENTFROM", "Only bot users and battle hosts can bridge clients", True)
				return
			if location != client.username:
				self.out_FAILED(client, "BRIDGECLIENTFROM", "You are only allowed to bridge clients with location '%s'" % client.username, True)
				return		
		good, reason = self._validBridgeSyntax(location, external_id, external_username)
		if not good:
			self.out_FAILED(client, "BRIDGECLIENTFROM", "Invalid syntax: %s" % reason, True)
			return
		location_client = self.clientFromUsername(location, True)
		if location_client and location_client.bot and location != client.username:
			self.out_FAILED(client, "BRIDGECLIENTFROM", "You cannot bridge from a location named after another bot user", True)
			return
		if not location in self._root.bridged_locations:
			self._root.bridged_locations[location] = client.user_id
			assert(not location in client.bridge)
			client.bridge[location] = {}
			self.out_SERVERMSG(client, "You are now the bridge bot for location '%s'" % location)
		if self._root.bridged_locations[location] != client.user_id:
			existing_bridge = self.clientFromID(self._root.bridged_locations[location])
			self.out_FAILED(client, "BRIDGECLIENTFROM", "The location '%s' is already in use by bridge bot %s" % existing_bridge.username, True)
			return
		if not client.bot and len(client.bridge[location])>256:
			self.out_FAILED(client, "BRIDGECLIENTFROM", "You have reached your maximum allowed number (256) of bridged clients", True)
			return

		good, response = self._root.bridgeduserdb.bridge_user(location, external_id, external_username)
		if not good:
			self.out_FAILED(client, "BRIDGECLIENTFROM", response, True)
			return
		if response.bridged_id in self._root.bridged_ids:
			self.out_FAILED(client, "BRIDGECLIENTFROM", "The client already exists on the bridge (%s,%s)" % (response.location, response.external_id), True)
			return

		# copy db values to our local bridged client
		bridgedClient = BridgedClient.BridgedClient()
		bridgedClient.bridged_id = response.bridged_id
		bridgedClient.external_id = response.external_id
		bridgedClient.location = response.location
		bridgedClient.last_bridged = response.last_bridged
		bridgedClient.username = response.username
		bridgedClient.external_username = response.external_username

		# non-db values
		bridgedClient.channels = set()
		bridgedClient.bridge_user_id = client.user_id

		client.bridge[location][bridgedClient.external_id] = bridgedClient.bridged_id
		self._root.bridged_ids[bridgedClient.bridged_id] = bridgedClient
		self._root.bridged_usernames[bridgedClient.username] = bridgedClient
		client.Send("BRIDGEDCLIENTFROM %s %s %s" % (bridgedClient.location, bridgedClient.external_id, bridgedClient.external_username))

	def in_UNBRIDGECLIENTFROM(self, client, location, external_id):
		# tell the server that a currently bridged client is gone
		if not 'u' in client.compat:
			return
		bridgedClient = self._root.bridgedClient(location, external_id)
		if not bridgedClient:
			self.out_FAILED(client, "UNBRIDGECLIENTFROM", "Bridged client (%s,%s) not found" % (location, external_id), True)
			return
		if bridgedClient.bridge_user_id != client.user_id:
			self.out_FAILED(client, "UNBRIDGECLIENTFROM", "Bridged client <%s> is on a different bridge (got %i, expected %i)" % (bridgedClient.username, dbridgedClient.bridge_user_id, client.user_id), True)
			return
			
		bridgedClient_channels = bridgedClient.channels.copy()
		for chan in bridgedClient_channels:
			self.in_LEAVEFROM(client, chan, bridgedClient.location, bridgedClient.external_id)

		del client.bridge[location][external_id]
		del self._root.bridged_ids[bridgedClient.bridged_id]
		del self._root.bridged_usernames[bridgedClient.username]
		client.Send("UNBRIDGEDCLIENTFROM %s %s" % (bridgedClient.location, bridgedClient.external_id))

	def in_JOINFROM(self, client, chan, location, external_id):
		# bridged client joins a channel
		if not 'u' in client.compat:
			return
		if not chan in self._root.channels:
			self.out_FAILED(client, "JOINFROM", "Channel '%s' not found" % chan, False)
			return
		channel = self._root.channels[chan]
		if channel.hasKey() and not (channel.identity == "battle" and client.session_id == channel.host):
			self.out_FAILED(client, "JOINFROM", "Cannot bridge to #%s, this channel has a password" % chan, False)			
			return					
		if channel.identity != "battle" and not client.bot:
			self.out_FAILED(client, "JOINFROM", "A botflag is needed to bridge clients into #%s" % chan, False)
			return					
		if channel.identity == "battle" and client.session_id != channel.host:
			self.out_FAILED(client, "JOINFROM", "Only the battle host can bridge clients into #%s" % chan, False)
			return		
		bridgedClient = self._root.bridgedClient(location, external_id)
		if not bridgedClient:
			self.out_FAILED(client, "JOINFROM", "Bridged user (%s,%s) not found" % (location, external_id), False)
			return
		if bridgedClient.bridge_user_id != client.user_id:
			self.out_FAILED(client, "JOINFROM", "Bridged client <%s> is on a different bridge (got %i, expected %i)" % (bridgedClient.username, bridgedClient.bridge_user_id, client.user_id), False)
			return
		if bridgedClient.bridged_id in channel.bridged_ban:
			self.out_FAILED(client, "JOINFROM", "Bridged user <%s> is banned from channel #%s" % (bridgedClient.username, chan), False)
			return
		channel.addBridgedUser(client, bridgedClient)

	def in_LEAVEFROM(self, client, chan, location, external_id):
		# bridged client leaves a channel
		if not 'u' in client.compat:
			return
		if not chan in self._root.channels:
			self.out_FAILED(client, "LEAVEFROM", "Channel '%s' not found" % chan, False)
			return
		channel = self._root.channels[chan]
		bridgedClient = self._root.bridgedClient(location, external_id)
		if not bridgedClient:
			self.out_FAILED(client, "LEAVEFROM", "Bridged user (%s,%s) not found" % (location, external_id), False)
			return
		if bridgedClient.bridge_user_id != client.user_id:
			self.out_FAILED(client, "LEAVEFROM", "Bridged user <%s> is on a different bridge (got %i, expected %i)" % (bridgedClient.username, bridgedClient.bridge_user_id, client.user_id), False)
			return
		channel.removeBridgedUser(client, bridgedClient)

	def in_SAYFROM(self, client, chan, location, external_id, msg):
		# bridged client speaks in a channel
		if not msg: return
		if not chan in self._root.channels:
			return
		channel = self._root.channels[chan]
		bridgedClient = self._root.bridgedClient(location, external_id)
		if not bridgedClient or bridgedClient.bridge_user_id != client.user_id:
			return
		if not bridgedClient.bridged_id in channel.bridged_users:
			self.out_FAILED(client, "SAYFROM", "Bridged user <%s> not present in channel" % bridgedClient.username, False)
			return
		if channel.store_history: 
			self.userdb.add_channel_message(channel.id, client.user_id, bridgedClient.bridged_id, msg, False)

		self._root.broadcast('SAIDFROM %s %s %s' % (chan, bridgedClient.username, msg), chan, set([]), client, 'u')
		
		# backwards compat
		msg = '<' + bridgedClient.username + '> ' + msg
		if channel.identity=="battle":
			self._root.broadcast('SAIDBATTLE %s %s' % (client.username, msg), chan, set([]), client, None, 'u')
		else:
			self._root.broadcast('SAID %s %s %s' % (chan, client.username, msg), chan, set([]), client, None, 'u')
		if channel.store_history: #fixme for bridged clients
			self.userdb.add_channel_message(channel.id, client.user_id, msg)

		
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
		for (userId, reason) in self.userdb.get_ignore_list(client.user_id):
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

		friendRequestClient = self.clientFromUsername(username, True)
		if not friendRequestClient:
			self.out_SERVERMSG(client, "No such user.")
			return
		if username == client.username:
			self.out_SERVERMSG(client, "Can't send friend request to self. Sorry :(")
			return
		if self.userdb.are_friends(client.user_id, friendRequestClient.user_id):
			self.out_SERVERMSG(client, "Already friends with user.")
			return
		if self.is_ignored(friendRequestClient, client):
			# don't send friend request if ignored
			return
		if self.userdb.has_friend_request(client.user_id, friendRequestClient.user_id):
			# don't inform the user that there is already a friend request (so they won't be able to tell if they are being ignored or not)
			return

		self.userdb.add_friend_request(client.user_id, friendRequestClient.user_id, msg)
		if self.clientFromID(friendRequestClient.user_id):
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

		friendRequestClient = self.clientFromUsername(username, True)
		if not self.userdb.has_friend_request(friendRequestClient.user_id, client.user_id):
			self.out_SERVERMSG(client, "No such friend request.")
			return

		self.userdb.friend_users(client.user_id, friendRequestClient.user_id)
		self.userdb.remove_friend_request(friendRequestClient.user_id, client.user_id)

		client.Send('FRIEND userName=%s' % username)
		if self.clientFromID(friendRequestClient.user_id):
			friendRequestClient.Send('FRIEND userName=%s' % client.username)

	def in_DECLINEFRIENDREQUEST(self, client, tags):
		tags = self._parseTags(tags)
		# should write a helper function for mandatory args..?
		username = tags.get("userName")
		if not username:
			self.out_SERVERMSG(client, "Missing userName argument.")
			return

		friendRequestClient = self.clientFromUsername(username, True)
		if not self.userdb.has_friend_request(friendRequestClient.user_id, client.user_id):
			self.out_SERVERMSG(client, "No such friend request.")
			return
		self.userdb.remove_friend_request(friendRequestClient.user_id, client.user_id)

	def in_UNFRIEND(self, client, tags):
		tags = self._parseTags(tags)
		# should write a helper function for mandatory args..?
		username = tags.get("userName")
		if not username:
			self.out_SERVERMSG(client, "Missing userName argument.")
			return

		friendRequestClient = self.clientFromUsername(username, True)

		self.userdb.unfriend_users(client.user_id, friendRequestClient.user_id)

		client.Send('UNFRIEND userName=%s' % username)
		if self.clientFromID(friendRequestClient.user_id):
			friendRequestClient.Send('UNFRIEND userName=%s' % client.username)

	def in_FRIENDREQUESTLIST(self, client):
		client.Send('FRIENDREQUESTLISTBEGIN')
		for (userId, msg) in self.userdb.get_friend_request_list(client.user_id):
			friendRequestClient = self.clientFromID(userId, True)
			username = friendRequestClient.username
			if msg:
				client.Send('FRIENDREQUESTLIST userName=%s\tmsg=%s' % (username, msg))
			else:
				client.Send('FRIENDREQUESTLIST userName=%s' % (username))
		client.Send('FRIENDREQUESTLISTEND')

	def in_FRIENDLIST(self, client):
		client.Send('FRIENDLISTBEGIN')
		for userId in self.userdb.get_friend_user_ids(client.user_id):
			friendClient = self.clientFromID(userId, True)
			username = friendClient.username
			client.Send('FRIENDLIST userName=%s' % (username))
		client.Send('FRIENDLISTEND')


	def in_JOIN(self, client, chan, key=None):
		'''
		Attempt to join target channel.

		@required.str channel: The target channel.
		@optional.str password: The password to use for joining if channel is locked.
		'''
		chan = chan.lstrip('#')
		ok, reason = self._validChannelSyntax(chan)
		if not ok:
			client.Send('JOINFAILED %s' % reason)
			return

		user = client.username
		# FIXME: unhardcode this
		if (client.bot or client.agent.startswith("SPADS")) and chan in ("newbies") and client.username != "ChanServ":
			#client.Send('JOINFAILED %s No bots allowed in #%s!' %(chan, chan))
			return
		if chan == 'moderator' and not 'mod' in client.accesslevels:
			self.out_FAILED(client, "JOIN", "Only moderators allowed in this channel! access=%s" %(client.access), True)
			return
		if not chan:
			self.out_FAILED(client, 'JOIN', 'Invalid channel', False)
			return
		if not chan in self._root.channels:
			if chan.startswith('__battle__'):
				self.out_FAILED(client, 'JOIN', 'cannot create channel %s with prefix __battle__, these names are reserved for battles' % chan, False)
				return
			channel = Channel.Channel(self._root, chan)
			self._root.channels[chan] = channel
		else:
			channel = self._root.channels[chan]
		if client.session_id in channel.users:
			# https://github.com/springlobby/springlobby/issues/782
			#self.out_FAILED(client, "JOIN", 'Already in channel %s' %(chan), True)
			return
		if channel.identity=='battle' and client.username!='ChanServ' and not client.bot:
			client.Send("JOINFAILED Channel '%s' is associated to a battle, please use JOINBATTLE to access it" % chan)
			return
		if not channel.isFounder(client) and not 'mod' in client.accesslevels:
			if client.user_id in channel.ban or client.ip_address in channel.ban_ip:
				client.Send('JOINFAILED %s %s' % (chan, channel.getBanMessage(client)))
				return
			if channel.key and not channel.key in (key, None, '*', ''):
				client.Send('JOINFAILED %s Invalid key' % chan)
				return
		assert(chan not in client.channels)

		channel.addUser(client)

	def in_LEAVE(self, client, chan, reason=None):
		'''
		Leave target channel.

		@required.str channel: The target channel.
		'''
		if not chan in self._root.channels:
			return
		channel = self._root.channels[chan]
		if channel.identity=='battle' and client.username!='ChanServ':
			self.out_FAILED(client, 'LEAVE', '%s is a battle, use LEAVEBATTLE to leave it' % chan, True)
			return
		if not client.session_id in channel.users:
			self.out_FAILED(client, 'LEAVE', 'not in channel %s' % chan, True)
			return
		channel.removeUser(client, reason)
		assert(not client.session_id in channel.users)
		if not channel.registered() and len(channel.users)==0 and len(channel.bridged_users)==0:
			del self._root.channels[chan]

	def in_OPENBATTLE(self, client, type, natType, key, port, maxplayers, hashcode, rank, maphash, sentence_args):
		'''
		Host a new battle with the arguments specified.

		@required.int type: The type of battle to host.
		#0: Battle
		#1: Hosted replay

		@required.int natType: The method of NAT transversal to use.
		#0: None
		#1: Hole punching
		#2: Fixed source ports

		@required.str key: The password to use, or "*" to use no password.
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

		tabcount = sentence_args.count('\t')
		if tabcount == 4:
			engine, version, map, title, modname = sentence_args.split('\t', 4)
		else:
			self.out_OPENBATTLEFAILED(client, 'Invalid arguments (%d): %s' %(tabcount, sentence_args))
			return

		title = self.SayHooks.hook_OPENBATTLE(self, client, title).strip()

		checkvars = [
			(engine, 'No engine specified.'),
			(version, 'No engine version specified.'),
			(map, "No map name specified"),
			(title, "No title specified"),
			(modname, "No game name specified")]

		for var, error in checkvars:
			if not var:
				self.out_OPENBATTLEFAILED(client, error)
				return

		if client.bot and not self._validEngineVersion(engine, version):
			self.out_OPENBATTLEFAILED(client, "Engine version specified (%s,%s) is invalid: Spring %s or later is required!" % (engine, version, self._root.min_spring_version))
			return
			
		battle_id = self._getNextBattleId()

		try:
			battle_id = int(battle_id)
			type = int(type)
			natType = int(natType)
			key = str(key)
			port = int(port)
			maphash = int32(maphash)
			hashcode = int32(hashcode)
			maxplayers = int32(maxplayers)
		except Exception as e:
			self.out_OPENBATTLEFAILED(client, 'Invalid argument type, send this to your lobby dev: id=%s type=%s natType=%s key=%s port=%s maphash=%s gamehash=%s - %s' %
						(battle_id, type, natType, key, port, maphash, hashcode, str(e).replace("\n", "")))
			return False

		if port < 1 or port > 65535:
			self.out_OPENBATTLEFAILED(client, 'Port is out of range: 1-65535: %d' % port)
			return

		if hashcode == 0:
			self.out_OPENBATTLEFAILED(client, 'Invalid game hash 0')
			return
			
		if not client.TLS:
			self.out_SERVERMSG(client, "A TLS connection is required to host battles. Please upgrade your client.")
			return

		noflag_limit = 8
		if not client.bot and maxplayers > noflag_limit:
			maxplayers = noflag_limit
			self.out_SERVERMSG(client, "A botflag is required to host battles with > %i players. Your battle was restricted to %i players" % (noflag_limit, noflag_limit))

		battle_name = '__battle__' + str(client.user_id)
		if battle_name in self._root.channels:
			battle = self._root.channels[battle_name]
		else:
			battle = Battle.Battle(self._root, battle_name)
			self._root.channels[battle_name] = battle

		battle.battle_id = battle_id
		battle.host = client.session_id
		battle.key = key
		battle.type = type
		battle.natType = natType
		battle.port = port
		battle.title = title
		battle.map = map
		battle.maphash = maphash
		battle.modname = modname
		battle.hashcode = hashcode
		battle.engine = engine
		battle.version = version
		battle.rank = rank
		battle.maxplayers = maxplayers

		self._root.battles[battle.battle_id] = battle
		self.broadcast_AddBattle(battle)

		client.Send('OPENBATTLE %s' % battle.battle_id)
		battle.joinBattle(client)

	def in_JOINBATTLE(self, client, battle_id, key=None, scriptPassword=None):
		'''
		Attempt to join target battle.

		@required.int battleID: The ID of the battle to join.
		@optional.str key: The password to use if the battle requires one.
		@optional.str scriptPassword: A password unique to your user, to verify users connecting to the actual game.
		'''
		if scriptPassword: 
			client.scriptPassword = scriptPassword

		try:
			battle_id = int32(battle_id)
		except:
			client.Send('JOINBATTLEFAILED Invalid battle id: %s.' %(str(battle_id)))
			return

		username = client.username
		if client.current_battle in self._root.battles:
			client.Send('JOINBATTLEFAILED You are already in a battle')
			return

		if battle_id not in self._root.battles:
			client.Send('JOINBATTLEFAILED Battle does not exist')
			return
		battle = self._root.battles[battle_id]
		if client.session_id in battle.users: # user is already in battle
			client.Send('JOINBATTLEFAILED Client is already in battle')
			return
		host = self.clientFromSession(battle.host)
		if not battle.isFounder(client) and not 'mod' in client.accesslevels:
			if not battle.key in ('*', None) and not battle.key == key:
				client.Send('JOINBATTLEFAILED Incorrect password')
				return
			if client.user_id in battle.ban:
				client.Send('JOINBATTLEFAILED You are banned from the battle')
				return
			if battle.locked:
				client.Send('JOINBATTLEFAILED Battle is locked')
				return
		if 'b' in host.compat and not 'mod' in client.accesslevels: # use battleAuth
			if client.session_id in battle.pending_users:
				client.Send('JOINBATTLEFAILED Waiting for JOINBATTLEACCEPT/JOINBATTLEDENIED from host')
			else:
				self.addPendingBattle(client, battle)
			client_ip = client.local_ip if client.ip_address in self._root.trusted_proxies else client.ip_address
			host.Send('JOINBATTLEREQUEST %s %s' % (username, client_ip))
			return
		self.removePendingBattle(client)
		battle.joinBattle(client)
		
	def addPendingBattle(self, client, battle):
		self.removePendingBattle(client)
		battle.pending_users.add(client.session_id)
		client.pending_battle = battle.battle_id
		
	def removePendingBattle(self, client):
		if client.pending_battle:
			pending_battle = self._root.battles[client.pending_battle]
			pending_battle.pending_users.remove(client.session_id)
			client.pending_battle = None

	def in_JOINBATTLEACCEPT(self, client, username):
		'''
		Allow a user to join your battle, sent as a response to JOINBATTLEREQUEST.
		[host]
		@required.str username: The user to allow into your battle.
		'''
		user = self.clientFromUsername(username)
		if not user:
			self.out_FAILED(client, 'JOINBATTLEACCEPT', "Couldn't find user %s" %(username), True)
			return
		battle = self.getCurrentBattle(client)
		if not client.session_id == battle.host:
			self.out_FAILED(client, 'JOINBATTLEACCEPT', "Client isn't the specified host, %d vs %d" %(client.session_id, battle.host), True)
			return
		if not user.session_id in battle.pending_users:
			return
		self.removePendingBattle(user)
		battle.joinBattle(user)

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
		battle = self.getCurrentBattle(client)
		if not client.session_id == battle.host:
			return
		if not user.session_id in battle.pending_users:
			return
		self.removePendingBattle(user)
		user.Send('JOINBATTLEFAILED %s%s' % ('Access denied by host', (' ('+reason+')' if reason else '')))

	def in_KICKFROMBATTLE(self, client, username):
		'''
		Kick a player from their battle.
		[host]

		@required.str username: The player to kick.
		'''
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client): # for use by the (auto-)host; ops have Battle.kickUser()
			return
		user = self.clientFromUsername(username)
		if not user or not user.session_id in battle.users:
			return
		if 'mod' in user.accesslevels:
			return

		user.Send('FORCEQUITBATTLE %s' %(client.username))
		self.in_LEAVEBATTLE(user)

	def in_SETSCRIPTTAGS(self, client, scripttags):
		'''
		Set script tags and send them to all clients in your battle.

		@required.str scriptTags: A tab-separated list of key=value pairs.
		'''

		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			self.out_FAILED(client, "SETSCRIPTTAGS", "You are not allowed to change settings in this battle", True)
			return

		setscripttags = self._parseTags(scripttags)
		scripttags = []
		for tag in setscripttags:
			scripttags.append('%s=%s'%(tag.lower(), setscripttags[tag]))
		if not scripttags:
			return
		battle.script_tags.update(setscripttags)
		self._root.broadcast_battle('SETSCRIPTTAGS %s'%'\t'.join(scripttags), client.current_battle)

	def in_REMOVESCRIPTTAGS(self, client, tags):
		'''
		Remove script tags and send an update to all clients in your battle.

		@required.str tags: A space-separated list of tags.
		'''
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			self.out_FAILED(client, "REMOVESCRIPTTAGS", "You are not allowed to change settings in this battle", True)
			return

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
		battle = self.getCurrentBattle(client)
		if not battle:
			self.out_FAILED(client, "LEAVEBATTLE", "not in battle")
			return
		if not battle.battle_id in self._root.battles:
			self.out_FAILED(client, "LEAVEBATTLE", "couldn't find battle")
			return
		if battle.host == client.session_id:
			if not battle.registered():
				del self._root.channels[battle.name]
			del self._root.battles[battle.battle_id]
			battle.removeBattle()
			return
		battle.leaveBattle(client)

	def in_MYBATTLESTATUS(self, client, _battlestatus, _myteamcolor):
		'''
		Set your status in a battle.

		@required.int status: The status to set, formatted as an awesome bitfield.
		@required.sint teamColor: Teamcolor to set. Format is hex 0xBBGGRR represented as decimal.
		'''
		try:
			battlestatus = int32(_battlestatus)
		except:
			self.out_FAILED(client, 'MYBATTLESTATUS','invalid status: %s.' % (_battlestatus), True)
			return

		if battlestatus < 0:
			self.out_FAILED(client, 'MYBATTLESTATUS', 'invalid status is below 0: %s. Please update your lobby!' % (_battlestatus), True)
			battlestatus = battlestatus + 2147483648

		try:
			myteamcolor = int32(_myteamcolor)
		except:
			self.out_FAILED(client, 'MYBATTLESTATUS', 'invalid teamcolor: %s.' % (myteamcolor), True)
			return

		battle = self.getCurrentBattle(client)
		if not battle:
			self.out_FAILED(client, "MYBATTLESTATUS", "not inside a battle", True)
			return

		spectating = (client.battlestatus['mode'] == '0')

		clients = (self.clientFromSession(name) for name in battle.users)
		spectators = len([user for user in clients if user and (user.battlestatus['mode'] == '0')])

		u, u, u, u, side1, side2, side3, side4, sync1, sync2, u, u, u, u, handicap1, handicap2, handicap3, handicap4, handicap5, handicap6, handicap7, mode, ally1, ally2, ally3, ally4, id1, id2, id3, id4, ready, u = self._dec2bin(battlestatus, 32)[-32:]

		if spectating:
			if len(battle.users) - spectators >= int(battle.maxplayers):
				mode = '0'
			elif mode == '1':
				spectators -= 1
		elif mode == '0':
			spectators += 1

		oldstatus = battle.calc_battlestatus(client)
		oldcolor = client.teamcolor
		client.battlestatus.update({'ready':ready, 'id':id1+id2+id3+id4, 'ally':ally1+ally2+ally3+ally4, 'mode':mode, 'sync':sync1+sync2, 'side':side1+side2+side3+side4})
		client.teamcolor = myteamcolor

		oldspecs = battle.spectators
		battle.spectators = spectators

		if oldspecs != spectators:
			self._root.broadcast('UPDATEBATTLEINFO %s %i %i %s %s' % (battle.battle_id, battle.spectators, battle.locked, battle.maphash, battle.map))

		newstatus = battle.calc_battlestatus(client)
		statuscmd = 'CLIENTBATTLESTATUS %s %s %s'%(client.username, newstatus, myteamcolor)
		if oldstatus == newstatus and client.teamcolor == oldcolor: #nothing changed, just send back to client
			client.Send(statuscmd)
			return
		self._root.broadcast_battle(statuscmd, battle.battle_id)

	def in_UPDATEBATTLEINFO(self, client, SpectatorCount, locked, maphash, mapname):
		'''
		Update public properties of your battle.
		[host]

		@required.int spectators: The number of spectators in your battle.
		@required.int locked: A boolean (0 or 1) of whether battle is locked.
		@required.sint mapHash: A 32-bit signed hash of the current map as returned by unitsync.
		@required.str mapName: The name of the current map.
		'''
		battle = self.getCurrentBattle(client)
		if not battle:
			return
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

			oldstr = 'UPDATEBATTLEINFO %s %i %i %s %s' % (battle.battle_id, battle.spectators, battle.locked, battle.maphash, battle.map)
			battle.locked = int(locked)
			battle.maphash = maphash
			battle.map = mapname
			newstr = 'UPDATEBATTLEINFO %s %i %i %s %s' % (battle.battle_id, battle.spectators, battle.locked, battle.maphash, battle.map)
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
			self.out_FAILED(client, 'MYSTATUS', 'invalid status %s'%(_status), True)
			return
		was_ingame = client.is_ingame
		self._calc_status(client, status)
		if client.is_ingame and not was_ingame:
			battle = self.getCurrentBattle(client)
			if not battle:
				self.out_FAILED(client, 'MYSTATUS', 'ingame but no battleid set', True)
				return

			if len(battle.users) > 1:
				client.went_ingame = time.time()
			else:
				client.went_ingame = None
			if client.session_id == battle.host:
				if client.hostport:
					self._root.broadcast_battle('HOSTPORT %i' % client.hostport, battle.battle_id, host)
		elif was_ingame and not client.is_ingame and client.went_ingame:
			ingame_time = (time.time() - client.went_ingame) / 60
			if ingame_time >= 1:
				client.ingame_time += int(ingame_time)
				self.userdb.save_user(client)
		self._root.broadcast('CLIENTSTATUS %s %d'%(client.username, client.status))

	def in_CHANNELS(self, client):
		'''
		Return a listing of all channels on the server.
		'''

		for name, channel in self._root.channels.items():
			if channel.key:
				continue
			top = channel.topic
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

	def in_GETCHANNELMESSAGES(self, client, chan, last_msg_id):
		'''
		Get historical messages from the chan since the specified time
		@required.str chan: The target channel
		@required.str last_msg_id: messages to get since this id
		'''
		if not chan in self._root.channels:
			return
		channel = self._root.channels[chan]
		if channel.id == 0:
			return # unregistered channels use id 0
		if not client.session_id in channel.users:
			self.out_FAILED(client, "GETCHANNELMESSAGES", "Can't get channel messages when not joined", True)
			return
		try:
			timestamp = datetime.datetime.fromtimestamp(int(last_msg_id))
		except:
			self.out_FAILED(client, "GETCHANNELMESSAGES", "Invalid id", True)
			return
		msgs = self.userdb.get_channel_messages(client.user_id, channel.id, last_msg_id)
		for msg in msgs:
			timestamp = int(time.mktime(msg[0].timetuple()))
			self.out_JSON(client,  'SAID', {"chanName": chan, "time": str(timestamp), "userName": msg[1], "msg": msg[2], "ex_msg":msg[3], "id": msg[4]})

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
			battle = self.getCurrentBattle(client)
			if not battle:
				return
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
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return
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
		self._root.broadcast_battle('ADDSTARTRECT %s' % (allyno)+' %(left)s %(top)s %(right)s %(bottom)s' %(rect), client.current_battle)

	def in_REMOVESTARTRECT(self, client, allyno):
		'''
		Remove a start rectangle for an ally team.
		[host]

		@required.int allyno: The ally number for the rectangle.
		'''
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return
		allyno = int32(allyno)
		try:
			del battle.startrects[allyno]
		except:
			self.out_SERVERMSG(client, 'invalid rect removed: %d' % (allyno), True)
			return
		self._root.broadcast_battle('REMOVESTARTRECT %s' % allyno, client.current_battle)

	def in_DISABLEUNITS(self, client, units):
		'''
		Add a list of units to disable.
		[host]

		@required.str units: A string-separated list of unit names to disable.
		'''
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return
		units = units.split(' ')
		disabled_units = []
		for unit in units:
			if not unit in battle.disabled_units:
				battle.disabled_units.append(unit)
				disabled_units.append(unit)
		if disabled_units:
			disabled_units = ' '.join(disabled_units)
			self._root.broadcast_battle('DISABLEUNITS %s'%disabled_units, client.current_battle)

	def in_ENABLEUNITS(self, client, units):
		'''
		Remove units from the disabled unit list.
		[host]

		@required.str units: A string-separated list of unit names to enable.
		'''
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return
		units = units.split(' ')
		enabled_units = []
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
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return

		battle.disabled_units = []
		self._root.broadcast_battle('ENABLEALLUNITS', client.current_battle)

	def in_HANDICAP(self, client, username, value):
		'''
		Change the handicap value for a player.
		[host]

		@required.str username: The player to handicap.
		@required.int handicap: The percentage of handicap to give (1-100).
		'''
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return
		user = self.clientFromUsername(username)
		if not user or not user.session_id in battle.users:
			return

		if not value.isdigit() or not int(value) in range(0, 101):
			return
		user.battlestatus['handicap'] = self._dec2bin(value, 7)
		battle = self.getCurrentBattle(client)
		self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, battle.calc_battlestatus(user), user.teamcolor), user.current_battle)

	def in_FORCETEAMNO(self, client, username, teamno):
		'''
		Force target player's team number.
		[host]

		@required.str username: The target player.
		@required.int teamno: The team to assign them.
		'''
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return
		user = self.clientFromUsername(username)
		if not user or not user.session_id in battle.users:
			return

		user.battlestatus['id'] = self._dec2bin(teamno, 4)
		battle = self.getCurrentBattle(client)
		if not battle: return
		self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, battle.calc_battlestatus(user), user.teamcolor), user.current_battle)

	def in_FORCEALLYNO(self, client, username, allyno):
		'''
		Force target player's ally team number.
		[host]

		@required.str username: The target player.
		@required.int teamno: The ally team to assign them.
		'''
		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return
		user = self.clientFromUsername(username)
		if not user or not user.session_id in battle.users:
			return

		user.battlestatus['ally'] = self._dec2bin(allyno, 4)
		battle = self.getCurrentBattle(client)
		if not battle: return
		self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, battle.calc_battlestatus(user), user.teamcolor), user.current_battle)

	def in_FORCETEAMCOLOR(self, client, username, teamcolor):
		'''
		Force target player's team color.
		[host]

		@required.str username: The target player.
		@required.sint teamcolor: The color to assign, represented with hex 0xBBGGRR as a signed integer.
		'''

		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return
		user = self.clientFromUsername(username)
		if not user or not user.session_id in battle.users:
			return

		user.teamcolor = teamcolor
		battle = self.getCurrentBattle(client)
		if not battle: return
		self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, battle.calc_battlestatus(user), user.teamcolor), user.current_battle)

	def in_FORCESPECTATORMODE(self, client, username):
		'''
		Force target player to become a spectator.
		[host]

		@required.str username: The target player.
		'''

		battle = self.getCurrentBattle(client)
		if not battle or not battle.canChangeSettings(client):
			return
		user = self.clientFromUsername(username)
		if not user or not user.session_id in battle.users:
			return

		if not user.battlestatus['mode'] == '1': # ??!
			return
		battle = self.getCurrentBattle(user)
		if not battle:
			return
		battle.spectators += 1
		user.battlestatus['mode'] = '0'
		self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, battle.calc_battlestatus(user), user.teamcolor), user.current_battle)
		self._root.broadcast('UPDATEBATTLEINFO %s %i %i %s %s' %(battle.battle_id, battle.spectators, battle.locked, battle.maphash, battle.map))

	def in_ADDBOT(self, client, name, battlestatus, teamcolor, AIDLL):
		'''
		Add a bot to the current battle.
		[battle]

		@required.str name: The name of the bot.
		@required.int battlestatus: The battle status of the bot.
		@required.sint teamcolor: The color to assign, represented with hex 0xBBGGRR as a signed integer.
		@required.str AIDLL: The name of the DLL loading the bot.
		'''
		battle = self.getCurrentBattle(client)
		if not battle:
			self.out_FAILED(client, "ADDBOT", "Couldn't find battle", True)
			return

		if name in battle.bots:
			self.out_FAILED(client, "ADDBOT", "Bot already exists!", False)
			return
		client.battle_bots[name] = battle.battle_id
		battle.bots[name] = {'owner':client.username, 'battlestatus':battlestatus, 'teamcolor':teamcolor, 'AIDLL':AIDLL}
		self._root.broadcast_battle('ADDBOT %s %s %s %s %s %s'%(battle.battle_id, name, client.username, battlestatus, teamcolor, AIDLL), battle.battle_id)

	def in_UPDATEBOT(self, client, name, battlestatus, teamcolor):
		'''
		Update battle status and teamcolor for a bot.
		[battle]

		@required.str name: The name of the bot.
		@required.int battlestatus: The battle status of the bot.
		@required.sint teamcolor: The color to assign, represented with hex 0xBBGGRR as a signed integer.
		'''
		battle = self.getCurrentBattle(client)
		if not battle:
			self.out_FAILED(client, "UPDATEBOT", "Couldn't find battle", True)
			return
		if name in battle.bots:
			if client.username == battle.bots[name]['owner'] or client.session_id == battle.host:
				battle.bots[name].update({'battlestatus':battlestatus, 'teamcolor':teamcolor})
				self._root.broadcast_battle('UPDATEBOT %s %s %s %s'%(battle.battle_id, name, battlestatus, teamcolor), battle.battle_id)

	def in_REMOVEBOT(self, client, name):
		'''
		Remove a bot from the active battle.
		[battle]

		@required.str name: The name of the bot.
		'''
		battle = self.getCurrentBattle(client)
		if not battle:
			self.out_FAILED(client, "REMOVEBOT", "Couldn't find battle", True)
			return
		if name in battle.bots:
			if client.username == battle.bots[name]['owner'] or client.session_id == battle.host:
				del self._root.usernames[battle.bots[name]['owner']].battle_bots[name]
				del battle.bots[name]
				self._root.broadcast_battle('REMOVEBOT %s %s'%(battle.battle_id, name), battle.battle_id)

	def in_GETUSERID(self, client, username):
		user = self.clientFromUsername(username, True)
		if user:
			self.out_SERVERMSG(client, 'The ID for <%s> is %s %s' % (username, user.last_mac_id, user.last_sys_id))
		else:
			self.out_SERVERMSG(client, 'User not found.')

	def in_GETUSERINFO(self, client, username=''):
		# send back human readable messages detailing user
		if not username:
			# client requests their own details
			register_date = client.register_date.strftime('%b %d, %Y') if client.register_date else 'unknown'
			self.out_SERVERMSG(client, "Registration date: %s" %  register_date)
			self.out_SERVERMSG(client, "Email address: %s" % client.email)
			ingame_time = int(self._root.usernames[client.username].ingame_time)			
			self.out_SERVERMSG(client, "Ingame time: %d hours" % (ingame_time/60))
			return
		if not 'mod' in client.accesslevels:
			return
		# mod requests client details
		if not username:
			return
		if ':' in username:
			# bridged username
			bridged_user = self._root.bridgedClientFromUsername(username, True)
			if not bridged_user:
				self.out_SERVERMSG(client, "Bridged user '%s' does not exist" % username)
				return
			if bridged_user.bridged_id in self._root.bridged_ids:
				self.out_SERVERMSG(client, "<%s> is bridged,  bridged_id=%s,  bridge_user_id='%s'" % (bridged_user.username, bridged_user.bridged_id, bridged_user.bridge_user_id))
			else:
				self.out_SERVERMSG(client, "<%s> is not bridged,  bridged_id=%s, " % (bridged_user.username, bridged_user.bridged_id))
			self.out_SERVERMSG(client, "Last bridged: %s" % bridged_user.last_bridged.strftime('%b %d, %Y'))
			self.out_SERVERMSG(client, "external_id=%s,  location=%s,  external_username=%s" % (bridged_user.external_id, bridged_user.location, bridged_user.external_username))			
		else:
			# native username
			user = self.clientFromUsername(username, True)
			if not user:
				self.out_SERVERMSG(client, "User '%s' does not exist" % username)
				return
			register_date = user.register_date.strftime('%b %d, %Y') if user.register_date else 'unknown'
			last_login = user.last_login.strftime('%b %d, %Y, %H:%M:%S') if user.last_login else 'unknown'
			if user.username in self._root.usernames:
				if user.static:
					self.out_SERVERMSG(client, "User <%s> is static" % username)
					return
				self.out_SERVERMSG(client, "<%s> is online,  user_id=%d, session_id=%d" % (user.username, user.user_id, user.session_id))
				ingame_time = int(self._root.usernames[user.username].ingame_time)	
			else:
				self.out_SERVERMSG(client, "<%s> is offline,  user_id=%s" % (user.username, user.user_id))
				ingame_time = int(user.ingame_time)
			self.out_SERVERMSG(client, "Agent: %s" % (user.last_agent))
			self.out_SERVERMSG(client, "Registered %s" % register_date)
			self.out_SERVERMSG(client, "Last login %s" % last_login)
			self.out_SERVERMSG(client, "access=%s,  bot=%s,  ingame_time=%d hours" % (user.access, user.bot, ingame_time/60))
			self.out_SERVERMSG(client, "email=%s" % (user.email))
			self.out_SERVERMSG(client, "last_ip=%s" % (user.last_ip))
			self.out_SERVERMSG(client, "last_sys_id=%s, last_mac_id=%s" % (user.last_sys_id, user.last_mac_id))
	
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

	def in_GETIP(self, client, username):
		'''
		Get the current or last IP address for target user.

		@required.str username: The target user.
		'''
		target = self.clientFromUsername(username)
		if target:
			if target.ip_address in self._root.trusted_proxies:
				ip = "%s via proxy %s" % (target.local_ip, target.ip_address)
			else:
				ip = target.ip_address
			self.out_SERVERMSG(client, '<%s> is currently bound to %s' % (username, ip))
			return

		ip = self.userdb.get_ip(username)
		if ip:
			self.out_SERVERMSG(client, '<%s> was recently bound to %s' % (username, ip))

	def in_RENAMEACCOUNT(self, client, newname):
		'''
		Change the name of current user.

		@required.str username: The new username to apply.
		'''

		recent_renames = self._root.recent_renames.get(client.user_id, 0)
		if recent_renames >= 3:
			self.out_SERVERMSG(client, 'too many recent renames')
			return
		self._root.recent_renames[client.user_id] = recent_renames + 1

		good, reason = self._validUsernameSyntax(newname)
		if not good:
			self.out_SERVERMSG(client, '%s' %(reason))
			return
		if self.SayHooks.isNasty(newname):
			self.out_FAILED(client, "RENAMEACCOUNT", "invalid nickname: %s" %(newname), True)
			return
			
		good, reason = self.userdb.rename_user(client.username, newname)
		if not good:
			self.out_SERVERMSG(client, 'Failed to rename to <%s>: %s' % (newname, reason))
			return
		
		self.out_SERVERMSG(client, 'Your account has been renamed to <%s>. Reconnect with the new username (you will now be automatically disconnected).' % newname)
		client.Remove('renaming')


	def in_CHANGEPASSWORD(self, client, cur_password, new_password):
		# Change the password of current user.
		if (cur_password == new_password):
			self.out_SERVERMSG(client, "New password must be different to current password.")
			return

		good, reason = self._validPasswordSyntax(new_password)
		if (not good):
			self.out_SERVERMSG(client, '%s' % reason)
			return
			
		good, reason = self.userdb.check_login_user(client.username, cur_password)
		if not good:
			self.out_SERVERMSG(client, '%s' % reason)
			return

		self.userdb.set_user_password(client.username, new_password)
		self.out_SERVERMSG(client, 'Password changed successfully.')

	def in_SETBOTMODE(self, client, username, mode):
		# set bot mode of target user
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
			self._calc_status(user, user.status)
			self._root.broadcast('CLIENTSTATUS %s %d'%(user.username, user.status))

		self.out_SERVERMSG(client, 'Botmode for <%s> successfully changed to %s' % (username, bot))
		if bot:
			self.broadcast_Moderator('New bot: <%s> created by <%s>' % (username, client.username))
		else:
			self.broadcast_Moderator('User <%s> had botflag removed by <%s>' % (username, client.username))

	def in_BROADCAST(self, client, msg):
		self._root.broadcast('BROADCAST %s'%msg)

	def in_BROADCASTEX(self, client, msg):
		self._root.broadcast('SERVERMSGBOX %s'%msg)

	def in_ADMINBROADCAST(self, client, msg):
		self._root.admin_broadcast(msg)

	def in_SETMINSPRINGVERSION(self, client, version):
		# set the minimal engine version for botflagged hosts
		self._root.min_spring_version = version
		self.contentdb.set_min_spring_version(version)
		legacyBattleIds = []
		for battleId, battle in self._root.battles.items():
			if battle.hasBotflag() and not self._validEngineVersion(battle.engine, battle.version):
				legacyBattleIds.append(battleId)
				host = self.clientFromSession(battle.host)
				self.broadcast_SendBattle(battle, 'SAIDBATTLEEX %s -- This battle will close -- %s %s or later is now required by the server. Please join a battle with the new Spring version!' % (host.username, 'Spring', version), None, None, 'u')
				self.broadcast_SendBattle(battle, 'SAIDEX %s %s -- This battle will close -- %s %s or later is now required by the server. Please join a battle with the new Spring version!' % (battle.name, host.username, 'Spring', version), None, 'u', None)
		for battleId in legacyBattleIds:
			battle = self._root.battles[battleId]
			battle.removeBattle()
			del self._root.battles[battleId]
		self.out_SERVERMSG(client, 'Set Spring engine version to %s' % version)

	def in_EXIT(self, client, reason=('Exiting')):
		# disconnect from the server, with an optional reason.
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

	def in_KICK(self, client, username, reason=''):
		# kick target username from server
		kickeduser = self.clientFromUsername(username)
		if not kickeduser:
			self.out_SERVERMSG(client, 'User <%s> was not online' % username)
			return
		battle = self.getCurrentBattle(kickeduser)
		if battle:
			host = self.clientFromSession(battle.host)
			host.Send("KICKFROMBATTLE %s %s" % (battle.battle_id, username))
		self.out_SERVERMSG(kickeduser, 'You were kicked from the server (%s)' % (reason))
		kickeduser.Send('SERVERMSGBOX You were kicked from the server (%s)' % (reason))
		self.out_SERVERMSG(client, 'Kicked <%s> from the server' % username)
		kickeduser.Remove('was kicked from server by <%s> (%s)' % (client.username, reason))

	def in_BAN(self, client, username, duration, reason):
		# ban target user from the server, also ban their current ip and email
		good, response = self.bandb.ban(client, duration, reason, username)
		target = self.clientFromUsername(username)
		if good and target: # is online
			self.in_KICK(client, target.username, 'banned')
		if good: self.broadcast_Moderator("%s banned <%s> for %s days (%s)" % (client.username, username, duration, reason))
		if response: self.out_SERVERMSG(client, '%s' % response)

	def in_BANSPECIFIC(self, client, arg, duration, reason):
		# arg might be a username(->user_id), ip, or email; ban it
		good, response = self.bandb.ban_specific(client, duration, reason, arg)
		if good: self.broadcast_Moderator("%s banned-specific <%s> for %s days (%s)" % (client.username, arg, duration, reason))
		if response: self.out_SERVERMSG(client, '%s' % response)

	def in_UNBAN(self, client, arg):
		# arg might be a username(->user_id), ip, or email; remove all associated bans
		good, response = self.bandb.unban(client, arg)
		if good: self.broadcast_Moderator("%s unbanned <%s>" % (client.username, arg))
		if response: self.out_SERVERMSG(client, '%s' % response)

	def in_BLACKLIST(self, client, domain, reason=""):
		# add somedomain.xyz to the blacklist
		good, response = self.bandb.blacklist(client, domain, reason)
		if good: self.broadcast_Moderator("%s blacklisted '%s' (%s)" % (client.username, domain, reason))
		if response: self.out_SERVERMSG(client, '%s' % response)

	def in_UNBLACKLIST(self, client, domain):
		# remove somedomain.xyz from the blacklist
		good, response = self.bandb.unblacklist(client, domain)
		if good: self.broadcast_Moderator("%s un-blacklisted '%s'" % (client.username, domain))
		if response: self.out_SERVERMSG(client, '%s' % response)

	def in_LISTBANS(self, client):
		# send the banlist
		banlist = self.bandb.list_bans()
		if banlist:
			self.out_SERVERMSG(client, '-- Banlist --')
			for entry in banlist:
				self.out_SERVERMSG(client, "%s, %s, %s :: '%s' :: ends %s (%s)" % (entry['username'], entry['ip'], entry['email'], entry['reason'], entry['end_date'], entry['issuer']))
			self.out_SERVERMSG(client, '-- End Banlist --')
			return
		self.out_SERVERMSG(client, 'Banlist is empty')

	def in_LISTBLACKLIST(self, client):
		# send the blacklist of domains for email verification
		blacklist = self.bandb.list_blacklist()
		if blacklist:
			self.out_SERVERMSG(client, '-- Blacklist --')
			for entry in blacklist:
				self.out_SERVERMSG(client, "%s :: '%s' (%s)" % (entry['domain'], entry['reason'], entry['issuer']))
			self.out_SERVERMSG(client, '-- End Blacklist--')
			return
		self.out_SERVERMSG(client, 'Blacklist is empty')

	def in_SETACCESS(self, client, username, access):
		# set the access level of target user.
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
		self.out_OK(client, "SETACCESS")
		# remove the new mod/admin from everyones ignore list and notify affected users
		if access in ('mod', 'admin'):
			userIds = self.userdb.globally_unignore_user(user.user_id)
			for userId in userIds:
				userThatIgnored = self.clientFromID(userId)
				if userThatIgnored:
					userThatIgnored.ignored.pop(user.user_id)
					userThatIgnored.Send('UNIGNORE userName=%s' % (username))

	
	def in_STATS(self, client):
		if not 'admin' in client.accesslevels:
			return		
		self._root.stats()
		self.out_SERVERMSG(client, 'Stats were printed in the server logfile')
		
	def in_LISTMODS(self, client):
		if not 'mod' in client.accesslevels:
			return		
		admins, mods = self.userdb.list_mods()
		self.out_SERVERMSG(client, "Admins: %s" % admins)
		self.out_SERVERMSG(client, "Mods: %s" % mods)
	
	def in_RELOAD(self, client):
		self.broadcast_Moderator('Reload initiated by <%s>' % client.username)
		if not 'admin' in client.accesslevels:
			return		
		ret = self._root.reload(client)
		self.broadcast_Moderator(ret)
		self.out_SERVERMSG(client, ret)

	def in_CLEANUP(self, client):
		if not 'admin' in client.accesslevels:
			return		
		self.cleanup(client)
		
	def cleanup(self, client=None):
		# keep calm, delete all inconsistencies, and carry on
		if client:
			self.broadcast_Moderator('Cleanup initiated by <%s>' % (client.username))
			logging.info('Cleanup initiated by <%s>' % (client.username))
		else:
			self.broadcast_Moderator('Cleanup initiated by server error')
			logging.error("Cleanup initiated by server error")
			logging.error(traceback.print_exc())

		n_client = 0
		n_username = 0
		n_user_id = 0
		
		n_bridged_location = 0
		n_bridged_username = 0
		n_bridged_user_id = 0
		
		n_bridge_external_id = 0
		n_bridge_location = 0
		
		n_battle = 0
		n_battle_user = 0
		n_battle_pending_user = 0
		
		n_channel = 0
		n_channel_user = 0
		n_channel_bridged_user = 0
		
		n_mismatch = 0
		
		root = self._root
				
		try:
			# cleanup clients/sessions
			dupcheck = set()
			todel = []
			for session_id in root.clients:
				c = root.clients[session_id]
				if not c.connected:
					logging.error("client not connected: %s %d" % (c.username, c.session_id))
					todel.append(c)
					continue
				if c.username in dupcheck:
					logging.error("client username failed dup check: %s %d" % (c.username, c.session_id))
					todel.append(c)
					continue
				dupcheck.add(c.username)
				if c.username not in root.usernames:
					logging.error("client with missing username: %s %d" % (c.username, c.session_id))
					todel.append(c)
					continue
				d = root.usernames[c.username]
				if d.session_id != c.session_id:
					logging.error("missmatched session_id: (%s %d) (%s %d)" % (c.username, c.session_id, d.username, d.session_id))
				
			for c in todel:
				del root.clients[c.session_id]
				logging.error("deleted invalid client: %s %d" % (c.username, c.session_id))
				n_client = n_client + 1
				
			# cleanup usernames
			todel = []
			for username in root.usernames:
				c = root.usernames[username]
				if not c.session_id in root.clients:
					logging.error("username with missing client: %s %d" % (c.username, c.session_id))
					todel.append(username)
					continue
				d = root.clients[c.session_id]
				if d.username != c.username:
					logging.error("missmatched username: (%s %d) (%s %d)" % (d.username, d.session_id, c.username, c.session_id))
					cs.n_mismatch = cs.n_mismatch + 1
			
			for username in todel:
				del root.usernames[username]
				logging.error("deleted invalid username: %s" % username)
				n_username = n_username + 1
			
			# cleanup user_ids
			todel = []
			for user_id in root.user_ids:
				c = root.user_ids[user_id]
				if not c.session_id in root.clients:
					logging.error("user_id with missing client: %d<%s> %d" % (c.user_id, c.username, c.session_id))
					todel.append(user_id)
					continue
				d = root.clients[c.session_id]
				if d.user_id != c.user_id:
					logging.error("missmatched user_id: (%d<%s> %d) (%d<%s> %d)" % (d.user_id, d.username, d.session_id, c.user_id, c.username, c.session_id))
					n_mismatch = n_mismatch + 1
			
			for user_id in todel:
				del root.user_ids[user_id]
				logging.error("deleted invalid user_id: %d" % user_id)
				n_user_id = n_user_id + 1
			
			# cleanup bridged locations
			todel = []
			bridged_locations = set()
			for location in root.bridged_locations:
				bridge_user_id = root.bridged_locations[location]
				c = root.user_ids[bridge_user_id]
				if not location in c.bridge:
					logging.error("location with missing bridge: %s %s" % (location, c.username))
					todel.append(location)
				bridged_locations.add(location)
				
			for location in todel:
				del root.bridged_locations[location]
				logging.error("deleted invalid bridged location: %s" % location)
				n_bridged_location = n_bridged_location + 1
			
			# cleanup bridge locations
			for session_id in root.clients:
				c = root.clients[session_id]
				todel = []
				for location in c.bridge:
					if not location in root.bridged_locations:
						logging.error("bridge contains invalid location: %s %s" % (c.username, location))
						todel.append(location)
			
				for location in todel:
					del c.bridge[location]
					logging.error("deleted invalid location from bridge: %s %s" % (c.username, location))
					n_bridge_location = n_bridge_location + 1
			
			
			# cleanup bridged usernames
			todel = []
			for bridged_username in root.bridged_usernames:
				b = root.bridged_usernames[bridged_username]
				if not b.bridge_user_id or not b.bridge_user_id in root.user_ids:
					logging.error("bridged username with missing bridge: %s %d" % (b.username, b.bridge_user_id))
					todel.append(bridged_username)
					continue
				bridge_user = root.user_ids[b.bridge_user_id]
				bridge = bridge_user.bridge
				if not b.location in bridge:
					logging.error("bridged_username has location missing from bridge: %d<%s> %s %s %s" % (b.bridged_id, b.username, b.location, b.external_id, bridge_user.username))
					todel.append(bridged_username)				
					continue
				if not b.external_id in bridge[b.location]:
					logging.error("bridged_username has external_id missing from bridge: %d<%s> %s %s %s" % (b.bridged_id, b.username, b.location, b.external_id, bridge_user.username))
					todel.append(bridged_username)
					
			for bridged_username in todel:
				del root.bridged_usernames[bridged_username]
				logging.error("deleted invalid bridged_username: %s" % bridged_username)
				n_bridged_username = n_bridged_username + 1
			
			# cleanup bridged_ids
			todel = []
			for bridged_id in root.bridged_ids:
				b = root.bridged_ids[bridged_id]
				if not b.bridge_user_id or not b.bridge_user_id in root.user_ids:
					logging.error("bridged_id with missing bridge: %d<%s> %d" % (b.bridged_id, b.username, b.bridge_user_id))
					todel.append(bridged_id)
					continue
				bridge_user = root.user_ids[b.bridge_user_id]
				bridge = bridge_user.bridge
				if not b.location in bridge:
					logging.error("bridged_id has location missing from bridge: %d<%s> %s %s %s" % (b.bridged_id, b.username, b.location, b.external_id, bridge_user.username))
					todel.append(bridged_id)				
					continue
				if not b.external_id in bridge[b.location]:
					logging.error("bridged_id has external_id missing from bridge: %d<%s> %s %s %s" % (b.bridged_id, b.username, b.location, b.external_id, bridge_user.username))
					todel.append(bridged_id)
			
			for bridged_id in todel:
				del root.bridged_ids[bridged_id]
				logging.error("deleted invalid bridged_id: %s" % bridged_id)
				n_bridged_user_id = n_bridged_user_id + 1		
		
			# cleanup bridge external_ids
			for session_id in root.clients:
				c = root.clients[session_id]
				for location in c.bridge:
					todel = []
					for external_id in c.bridge[location]:
						bridged_id = c.bridge[location][external_id]
						if not bridged_id in root.bridged_ids:
							logging.error("bridge has external_id with missing bridged_id: %s %s %s %d" % (c.username, location, external_id, bridged_id))
							todel.append(external_id)
					
					for external_id in todel:
						del c.bridge[location][external_id]
						logging.error("deleted invalid external_id from bridge: %s %s %s" % (c.username, location, external_id))
						n_bridge_external_id = n_bridge_external_id + 1
			
			# cleanup battle users
			for battle_id, battle in root.battles.items():
				for session_id in battle.users.copy():
					if not session_id in root.clients:
						battle.users.remove(session_id)
						logging.error("deleted invalid session %d from battle %d" % (session_id, battle_id))
						n_battle_user = n_battle_user + 1
				for session_id in battle.pending_users.copy():
					if not session_id in root.clients:
						battle.pending_users.remove(session_id)
						logging.error("deleted invalid session %d from pending users for battle %d" % (session_id, battle_id))
						n_battle_pending_user = n_battle_pending_user + 1
			
			# cleanup battles
			for battle_id in root.battles.copy():
				battle = root.battles[battle_id]
				if not battle.host in root.clients:
					del root.battles[battle_id]
					logging.error("deleted battle %d with invalid host %d" % (battle_id, battle.host))
					n_battle = n_battle + 1
					continue
				if len(battle.users) == 0:
					del root.battles[battle_id]
					logging.error("deleted battle %d, empty" % battle_id)
					n_battle = n_battle + 1
			
			# cleanup channel users & channels
			for channel in root.channels.copy():
				for session_id in root.channels[channel].users.copy():
					if not session_id in root.clients:
						root.channels[channel].users.remove(session_id)
						logging.error("deleted invalid session_id %d from channel %s" % (session_id, channel))
						n_channel_user = n_channel_user + 1
				for bridged_id in root.channels[channel].bridged_users.copy():
					if not bridged_id in root.bridged_ids:
						root.channels[channel].bridged_users.remove(bridged_id)
						logging.error("deleted invalid bridged_id %d from channel %s" % (bridged_id, channel))
						n_channel_bridged_user = n_channel_bridged_user + 1
				
				if len(root.channels[channel].users) == 0:
					if len(root.channels[channel].bridged_users) > 0:
						logging.error("warning: empty channel %s contains %d bridged users" % (channel, len(root.channels[channel].bridged_users)))
					del root.channels[channel]
					logging.error("deleted empty channel %s" % channel)
					n_channel = n_channel + 1

		except Exception as e:
			logging.error("Cleanup failed: " + str(e))
			logging.error(traceback.format_exc())			
			return
		
		cleaned_info = "deleted:"
		cleaned_info += "\n %d clients, %d usernames, %d user_ids" % (n_client, n_username, n_user_id)
		cleaned_info += "\n %d bridged_locations, %d bridged_usernames, %d bridged_user_ids, %d bridge_external_ids, %d bridge_locations" % (n_bridged_location, n_bridged_username, n_bridged_user_id, n_bridge_external_id, n_bridge_location)
		cleaned_info += "\n %d battles, %d battle_users, %d battle_pending_users" % (n_battle, n_battle_user, n_battle_pending_user)
		cleaned_info += "\n %d channels, %d channel_users, %d channel_bridged_users" % (n_channel, n_channel_user, n_channel_bridged_user)
		cleaned_info += "\n found %d mismatches" % (n_mismatch)
		logging.info(cleaned_info)
		
		n_delete = n_client + n_username + n_user_id + n_bridged_location + n_bridged_username + n_bridged_user_id + n_bridge_external_id + n_bridge_location + n_battle + n_battle_user + n_battle_pending_user + n_channel + n_channel_user + n_channel_bridged_user
		cleaned_msg = 'Cleanup complete: %s deletions, %s mismatches' % (n_delete, n_mismatch)	
		if client:
			self.out_SERVERMSG(client, cleaned_msg)
		self.broadcast_Moderator(cleaned_msg)


	def in_CHANGEEMAILREQUEST(self, client, newmail):
		# request to be sent a verification code for changing email address
		if not self.verificationdb.active():
			client.Send("CHANGEEMAILREQUESTDENIED email verification is currently turned off, a blank verification code will be accepted!")
			return
		newmail = newmail.lower()
		found,_ = self.userdb.get_user_id_with_email(newmail)
		if found and not client.bot:
			client.Send("CHANGEEMAILREQUESTDENIED another user is already registered to the email address '%s'" % newmail)
			return
		reason = "requested to change your email address for the account <%s> on on the SpringRTS lobbyserver" % client.username
		good, reason = self.verificationdb.check_and_send(client.user_id, newmail, 4, reason)
		if not good:
			client.Send("CHANGEEMAILREQUESTDENIED " + reason)
			return
		client.Send("CHANGEEMAILREQUESTACCEPTED")

	def in_CHANGEEMAIL(self, client, newmail, verification_code=""):
		# client requests to change their own email address, with verification code if necessary
		newmail = newmail.lower()
		found,_ = self.userdb.get_user_id_with_email(newmail)
		if found and not client.bot: # bots should share email addr with the bot owner
			client.Send("CHANGEEMAILDENIED another user is already registered to the email address '%s'" % newmail)
			return
		good, reason = self.verificationdb.verify(client.user_id, newmail, verification_code)
		if not good:
			client.Send("CHANGEEMAILDENIED " + reason)
			return
		client.email = newmail
		self.userdb.save_user(client)
		self.out_SERVERMSG(client, "Your email address has been changed to " + client.email)
		client.Send("CHANGEEMAILACCEPTED " + newmail)

	def in_RESETPASSWORDREQUEST(self, client, email):
		# client requests to reset the pw of an account; account recovery by email
		# we do not assume that the client is logged in
		if not self.verificationdb.active():
			client.Send("RESETPASSWORDREQUESTDENIED Email verification is currently turned off, account recovery is disabled")
			return
		email = email.lower()
		good, response = self.userdb.get_user_id_with_email(email)
		if not good:
			client.Send("RESETPASSWORDREQUESTDENIED " + response)
			return
		recover_client = self.clientFromID(response, True) # can't assume that the user is logged in, or even genuinely the client
		reason = "requested to recover your account <" + recover_client.username + "> on the SpringRTS lobbyserver"
		good, reason = self.verificationdb.check_and_send(recover_client.user_id, email, 8, reason)
		if not good:
			client.Send("RESETPASSWORDREQUESTDENIED " + reason)
			return
		client.Send("RESETPASSWORDREQUESTACCEPTED %s" % recover_client.email)

	def in_RESETPASSWORD(self, client, email, verification_code):
		# we do not assume that the client is logged in
		if not self.verificationdb.active():
			client.Send("RESETPASSWORDDENIED Email verification is currently turned off, account recovery is disabled")
			return

		email = email.lower()
		good, response = self.userdb.get_user_id_with_email(email)
		if not good:
			client.Send("RESETPASSWORDDENIED " + response)
			return
		recover_client = self.clientFromID(response, True)
		good, reason = self.verificationdb.verify(recover_client.user_id, email, verification_code)
		if not good:
			client.Send("RESETPASSWORDDENIED " + reason)
			return

		self.verificationdb.reset_password(recover_client.user_id, True)
		client.Send("RESETPASSWORDACCEPTED %s %s" % (recover_client.email, recover_client.username))
		self.out_SERVERMSG(client, "Your password has been reset. Please check your email account." + client.email)
		client.Remove("")
		
	def in_RESETUSERPASSWORD(self, client, username, newmail=None):
		# reset password, send the new password by email to the user
		# if the user does not have an email address associated to their account, it can be added with newmail
		if not self.verificationdb.active():
			self.out_SERVERMSG("Email verification is currently turned off, account recovery is disabled")
			return
			
		recover_client = self.clientFromUsername(username, True) 
		if not recover_client:
			self.out_SERVERMSG(client, "User <%s> does not exist" % (username))
			return		
		good, reason = self.verificationdb.valid_email_addr(recover_client.email)
		if good and newmail:
			self.out_SERVERMSG(client, "User <%s> already has a valid email address (%s), please try again without specifying an email address" % (username, recover_client.email))
			return
		if not good and not newmail:
			self.out_SERVERMSG(client, "User <%s> does not have a valid email address, please specify an email address to add to their account" % username)
			return
		if not good and newmail:
			good_new, reason_new = self.verificationdb.valid_email_addr(newmail)
			if not good_new:
				self.out_SERVERMSG(client, "The email address '%s' is not valid: %s" % (newmail, reason_new))
				return
			recover_client.email = newmail
			self.userdb.save_user(recover_client)
		self.verificationdb.reset_password(recover_client.user_id, True)
		self.out_SERVERMSG(client, "An email was sent to '%s' containing a new password for <%s>" % (recover_client.email, recover_client.username), True)

	def in_DELETEACCOUNT(self, client, username):
		# schedule the user account for deletion; after a delay during which the account becomes inaccessible
		delete_client = self.clientFromUsername(username, True) 
		if not delete_client:
			self.out_SERVERMSG(client, "User <%s> does not exist" % (username))
			return		
			
		# ensure that account is not logged in while we modify it & deter use of account deletion requests for smurfing
		if delete_client.email:
			self.in_BANSPECIFIC(client, delete_client.email, 28, "account deletion request scheduled")
		self.in_KICK(client, username, "account deletion request")
	
		delete_client.ingame_time = 0
		delete_client.bot = 0
		delete_client.access = "user"
		delete_client.email = "" # prevent account recovery
		self.userdb.save_user(delete_client)
		self.verificationdb.reset_password(delete_client.user_id, False)		
		# now the account can no longer be accessed & has no ingame time or special status 
		# -> automated deletion after 28 days
		self.out_SERVERMSG(client, "Account deletion of <%s> scheduled by <%s>" % (delete_client.username, client.username), True)
	
	def in_RESENDVERIFICATION(self, client, newmail):
		if not self.verificationdb.active():
			client.Send("RESENDVERIFICATIONDENIED email verification is currently turned off, you do not need a verification code!")
			return
		good, reason = self.verificationdb.resend(client.user_id, newmail)
		if not good:
			client.Send("RESENDVERIFICATIONDENIED %s" % reason)
			return
		client.Send("RESENDVERIFICATIONACCEPTED")
		
	def in_JSON(self, client, rawcmd):
		try:
			cmd = json.loads(rawcmd)
		except Exception as e:
			self.out_JSON(client, "FAILED", {"msg": str(e)})
			return

		if "PROMOTE" in cmd:
			if not client.bot: # only bots are allowed to promote
				return
			battle = self.getCurrentBattle(client)
			if not battle: #needs to be in battle
				return
			data = {"PROMOTE": {"battleid": battle.battle_id}}
			self._root.broadcast('JSON ' + json.dumps(data, separators=(',', ':')))
			return

		self.out_JSON(client, "FAILED", {"msg": "Unknown command: %s" %(rawcmd)})


	# Deprecated protocol section #
	#
	def in_MUTE(self, client, chan, user, duration=0):
		self._root.chanserv.Handle("SAIDPRIVATE %s :mute %s %s %s -" % (client.username, chan, user, duration))
	def in_UNMUTE(self, client, chan, user):
		self._root.chanserv.Handle("SAIDPRIVATE %s :unmute %s %s" % (client.username, chan, user))
	def in_MUTELIST(self, client, chan):
		self._root.chanserv.Handle("SAIDPRIVATE %s :listmutes %s" % (client.username, chan))
	def in_FORCELEAVECHANNEL(self, client, chan, user, reason=''):
		self._root.chanserv.Handle("SAIDPRIVATE %s :kick %s %s" % (client.username, chan, user))
	def in_SETCHANNELKEY(self, client, chan, key='*'):
		self._root.chanserv.Handle("SAIDPRIVATE %s :setkey #' + chan + ' ' + key" % (client.username, chan, key))
	def in_STARTTLS(self, client):
		client.StartTLS()
		client.flushBuffer()
		client.Send(' '.join((self._root.server, str(self._root.server_version), '*', str(self._root.natport), '0')))
	def in_SAYBATTLE(self, client, msg):
		battle = self.getCurrentBattle(client)
		if not battle: return
		self.in_SAY(client, battle.name, msg)
	def in_SAYBATTLEEX(self, client, msg):
		battle = self.getCurrentBattle(client)
		if not battle: return
		self.in_SAYEX(client, battle.name, msg)
	def in_SAYBATTLEPRIVATEEX(self, client, username, msg):
		if not username: return
		battle = self.getCurrentBattle(client)
		if not battle: return
		self.in_BATTLEHOSTMSG(client, battle.name, username, msg)
	def in_GETINGAMETIME(self, client):
		self.out_FAILED(client, "GETINGAMETIME", "deprecated, using GETUSERINFO instead!")
		self.in_GETUSERINFO(client)
	
	# Begin outgoing protocol section #
	#
	# Any function definition beginning with out_ and ending with capital letters
	# is a definition of an outgoing command.
	#
	# Most outgoing commands are sent directly via client.Send within an in_ command

	def out_DENIED(self, client, username, reason):
		# response to LOGIN
		client.Send("DENIED %s" %(reason))
		logging.info('[%s] Failed to log in user <%s>: %s'%(client.session_id, username, reason))

	def out_OPENBATTLEFAILED(self, client, reason):
		client.Send('OPENBATTLEFAILED %s' % (reason))
		logging.info('[%s] <%s> OPENBATTLEFAILED: %s' % (client.session_id, client.username, reason))

	def out_SERVERMSG(self, client, message, log = False):
		# send a message to the client
		client.Send('SERVERMSG %s' %(message))
		if log:
			logging.info('[%s] <%s>: %s' % (client.session_id, client.username, message))

	def out_FAILED(self, client, cmd, message, log = False):
		client.Send('FAILED ' + self._dictToTags({'msg':message, 'cmd':cmd}))
		if log:
			logging.warning('[%s] <%s>: %s %s' % (client.session_id, client.username, cmd, message))

	def out_OK(self, client, cmd):
		client.Send('OK ' + self._dictToTags({'cmd': cmd}))

	def out_JSON(self, client, cmd, dict):
		client.Send('JSON ' + json.dumps({cmd: dict}, separators=(',', ':')))

def check_protocol_commands():
	for command in restricted_list:
		if 'in_' + command not in dir(Protocol):
			print("command not implemented: %s" % command)
			return False

	for func in dir(Protocol):
		if func[:3] == 'in_' and func[3:] not in restricted_list:
			print("unused function %s"%(func))
			return False		
	return True

def selftest():
	assert(check_protocol_commands())
	assert('SETACCESS' not in restricted['everyone'])
	class DummyRoot():
		def SayHooks(self):
			pass
		def getUserDB(self):
			pass
		def getVerificationDB(self):
			pass
		def getBanDB(self):
			pass
		def getContentDB(self):
			pass
	p = Protocol(DummyRoot())
	assert(p._validUsernameSyntax("abcde")[0])
	assert(not p._validUsernameSyntax("abcde ")[0])
	assert(p._validChannelSyntax("abcde")[0])
	assert(not p._validChannelSyntax("#abcde")[0])
	assert(not p._validChannelSyntax("ab cde")[0])

	tests = {
		"104": True,
		"103": False,
		"105": True,
		"103.0": False,
		"83.0": False,
		"84.1": False,
		"83.0.1-13-g1234aaf develop": False,
		"84.1.1-1354-g1234567 release": False,
		"98.0.1-847-g61dee311 develop": False,
		"104.0": True,
		"104.0.1-730-g9af20e498a maintenance": True,
		"104.0.1-1145-g6bce463 develop": True,
		"105.0": True,
		"105.0.1": True,
	}
	p._root.min_spring_version = "104.0"
	for ver, res in tests.items():
		assert(p._validEngineVersion("spring", ver) == res)
	p._root.min_spring_version = "104"
	for ver, res in tests.items():
		assert(p._validEngineVersion("spring", ver) == res)

if __name__ == '__main__':
	selftest()
