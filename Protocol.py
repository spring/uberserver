import inspect, time, re
import md5, base64, binascii
import traceback, sys, os

restricted = {
				'TOKENIZE':'everyone', 'TELNET':'everyone', 'HASH':'everyone', 'EXIT':'everyone', 'PING':'everyone', # everyone
				'LOGIN':'fresh', 'REGISTER':'fresh', # freshly connected client
				'ADDBOT':'user', 'ADDSTARTRECT':'user', 'CHANNELS':'user', 'DISABLEUNITS':'user', # user
				'ENABLEALLUNITS':'user', 'ENABLEUNITS':'user', 'FORCEALLYNO':'user', # user
				'FORCESPECTATORMODE':'user', 'FORCETEAMCOLOR':'user', 'FORCETEAMNO':'user', 'GETINGAMETIME':'user', # user
				'HANDICAP':'user', 'JOIN':'user', 'JOINBATTLE':'user', 'KICKFROMBATTLE':'user', 'LEAVE':'user', 'LEAVEBATTLE':'user', # user
				'MAPGRADES':'user', 'MUTELIST':'user', 'MYBATTLESTATUS':'user', 'MYSTATUS':'user', 'OPENBATTLE':'user', # user
				'REMOVEBOT':'user', 'REMOVESTARTRECT':'user', 'RING':'user', 'SAY':'user', 'SAYBATTLE':'user', 'SAYBATTLEEX':'user', # user
				'SAYEX':'user', 'SAYPRIVATE':'user', 'SCRIPT':'user', 'SCRIPTEND':'user', 'SCRIPTSTART':'user', 'SETBOTMODE':'user', # user
				'SETSCRIPTTAGS':'user', 'UPDATEBATTLEINFO':'user', 'UPDATEBOT':'user', 'UPDATEBATTLEDETAILS':'user', # user
				'KICKUSER':'mod', 'CHANNELTOPIC': 'mod', 'MUTE': 'mod', 'UNMUTE': 'mod', # moderator
				'FORCELEAVECHANNEL':'mod', 'FORCECLOSEBATTLE':'mod', # moderator
				'FORGEMSG':'admin', 'FORGEREVERSEMSG':'admin', 'SETBOTMODE':'admin', 'SETINGAMETIME':'admin', # admin
				'ALIAS':'admin', 'UNALIAS':'admin', 'ALIASLIST':'admin', 'GETLOBBYVERSION':'admin', 'GETSENDBUFFERSIZE':'admin', # admin
				'BROADCAST':'admin', 'BROADCASTEX':'admin', 'ADMINBROADCAST':'admin', 'TESTLOGIN':'admin', # admin
				'KILLALL':'admin', 'SETINGAMETIME':'admin', # admin
				'MOD':'admin', 'ADMIN':'admin', # admin
				}

#from Users import UsersHandler
#from Users import LANUsersHandler as UsersHandler # we're in LAN mode

ipRegex = r"^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$"
re_ip = re.compile(ipRegex)

def validateIP(ipAddress):
	return re_ip.match(ipAddress)

class Protocol:

	def __init__(self,root,handler):
		LAN = root.LAN
		self._root = root
		self.handler = handler
		if LAN:
			self.userdb = __import__('LANUsers').UsersHandler()
		else:
			self.userdb = __import__('SQLUsers').UsersHandler()
		self.SayHooks = __import__('SayHooks')

	def _new(self,client):
		client.Send('TASServer 0.35 * 8201 0')

	def _remove(self,client,reason='Quit'):
		if client.username:
			if client.removing: return
			client.removing = True
			user = client.username
			if not user in self._root.usernames:
				return
			if not client == self._root.usernames[user]:
				return
			channels = list(client.channels)
			bots = dict(client.battle_bots)
			#del self._root.clients[client.session_id]
			del self._root.usernames[user]
			for chan in channels:
				if user in self._root.channels[chan]['users']:
					self._root.channels[chan]['users'].remove(user)
				if user in self._root.channels[chan]['blindusers']:
					self._root.channels[chan]['blindusers'].remove(user)
				self._root.broadcast('LEFT %s %s %s'%(chan, user, reason), chan, user)
			if client.current_battle in self._root.battles:
				battle_id = client.current_battle
				if self._root.battles[battle_id]['host'] == user:
					self._root.broadcast('BATTLECLOSED %s'%battle_id)
					del self._root.battles[battle_id]
				else:
					del self._root.battles[battle_id]['users'][user]
					for bot in bots:
						del self._root.battles[battle_id]['bots'][bot]
						self._root.broadcast_battle('REMOVEBOT %s %s'%(battle_id, bot), battle_id)
					self._root.broadcast('LEFTBATTLE %s %s'%(battle_id, user))
				self.incoming_MYSTATUS(client,'0')
			self._root.broadcast('REMOVEUSER %s'%user)

	def _handle(self,client,msg):
		if msg.startswith('#'):
			test = msg.split(' ')[0][1:]
			if test.isdigit():
				msg_id = '#%s '%test
				msg = ' '.join(msg.split(' ')[1:])
			else:
				msg_id = ''
		else:
			msg_id = ''
		client.msg_id = msg_id # works since handling is done in order for each ClientHandler thread ^_^
		numspaces = msg.count(' ')
		if numspaces:
			command,args = msg.split(' ',1)
		else:
			command = msg
		command = command.upper()
		
		if not hasattr(self, 'incoming_'+command):
			return False

		if command in restricted:
			if not restricted[command] in client.accesslevels:
				client.Send('SERVERMSG %s failed. Insufficient rights.'%command)
				return False
		else:
			if not 'user' in client.accesslevels:
				client.Send('SERVERMSG %s failed. Insufficient rights.'%command)
				return False
		
		command = 'incoming_%s' % command
		if hasattr(self,command):
			function = getattr(self,command)
		else:
			client.Send('SERVERMSG %s failed. Command does not exist.'%('_'.join(command.split('_')[1:])))
			return False
		function_info = inspect.getargspec(function)
		total_args = len(function_info[0])-2
		#if there are no arguments, just call the function
		if not total_args:
			function(client)
			return True
		#check for optional arguments
		optional_args = 0
		if function_info[3]:
			optional_args = len(function_info[3])
		#check if we've got enough words for filling the required args
		required_args = total_args - optional_args
		if numspaces < required_args:
			client.Send('SERVERMSG %s failed. Incorrect arguments.'%('_'.join(command.split('_')[1:])))
			return False
		if required_args == 0 and numspaces == 0:
			function(client)
			return True
		#bunch the last words together if there are too many of them
		if numspaces > total_args-1:
			arguments = args.split(' ',total_args-1)
		else:
			arguments = args.split(' ')
		function(*([client]+arguments))
		# makes debugging for typeerror not work <_<
		#try:
		#	function(*([client]+arguments))
		#except TypeError:
		#	client.Send('SERVERMSG %s failed. Incorrect arguments.'%command.partition('incoming_')[2])
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
				if battle_id:
					client.udpport = udpport
					client.hostport = udpport
					host = self._root.battles[battle_id]['host']
					if not host == username:
						self._root.usernames[host].Send('CLIENTIPPORT %s %s %s'%(username, ip, udpport))
				else:
					client.udpport = udpport
			else:
				self._root.admin_broadcast('NAT spoof from %s pretending to be <%s>'%(ip,username))

	def _calc_access(self, client):
		if not client.access:
			return
		userlevel = client.access
		inherit = {'mod':['user'], 'admin':['mod', 'user']}

		if userlevel in inherit:
			inherited = inherit[userlevel]
		else:
			inherited = [userlevel]
		if not client.access in inherited: inherited.append(client.access)
		client.accesslevels = inherited+['everyone']
		self._calc_status(client, client.status)

	def _calc_status(self, client, status):
		status = self._dec2bin(status, 7)
		bot, access, rank1, rank2, rank3, away, ingame = status[0:7]
		rank1, rank2, rank3 = self._dec2bin(6, 3)
		accesslist = {'user':0, 'mod':1, 'admin':1}
		access = client.access
		if access in accesslist:
			access = accesslist[access]
		else:
			access = 0
		bot = int(client.bot)
		ingame_time = float(client.ingame_time/60) # hours
		if ingame_time >= 1000: # make this into a list
			rank = 6
		elif ingame_time >= 300:
			rank = 5
		elif ingame_time >= 100:
			rank = 4
		elif ingame_time >= 30:
			rank = 3
		elif ingame_time >= 15:
			rank = 2
		elif ingame_time >= 5:
			rank = 1
		else:
			rank = 0
		rank1, rank2, rank3 = self._dec2bin(rank, 3)
		client.ingame = (ingame == '1')
		client.away = (away == '1')
		status = self._bin2dec('%s%s%s%s%s%s%s'%(bot, access, rank1, rank2, rank3, away, ingame))
		client.status = status
		return status

	def _calc_battlestatus(self, client):
		battlestatus = client.battlestatus
		status = self._bin2dec('0000%s%s0000%s%s%s%s%s0'%(battlestatus['side'], battlestatus['sync'], battlestatus['handicap'], battlestatus['mode'], battlestatus['ally'], battlestatus['id'], battlestatus['ready']))
		return status
	
	def _new_channel(self, chan):
		# probably make a SQL query here
		return {'users':[], 'blindusers':[], 'admins':[], 'ban':{}, 'allow':[], 'autokick':'ban', 'owner':'', 'mutelist':{}, 'antispam':{'enabled':True, 'quiet':False, 'timeout':3, 'bonus':2, 'unique':4, 'bonuslength':100, 'duration':900}, 'censor':False, 'antishock':False, 'topic':None, 'key':None}

	def _time_remaining(seconds):
		if mutelist[mute] < 1:
			message = 'forever'
		else:
			seconds = mutelist[mute] - time.time()
			minutesleft = float(seconds) / 60
			hoursleft = minutesleft / 60
			daysleft = hoursleft / 24
			if daysleft > 7:
				message = '%0.2f weeks' % (daysleft / 7)
			if daysleft == 7:
				message = '1 week'
			if daysleft > 1:
				message = '%0.2f days' % daysleft
			if daysleft == 1:
				message = '1 day'
			elif hoursleft > 1:
				message = '%0.2f hours' % hoursleft
			elif hoursleft == 1:
				message = '1 hour'
			elif minutesleft > 1:
				message = '%0.1f minutes' % minutesleft
			elif minutesleft == 1:
				message = '1 minute'
			else:
				message = '%0.0f second(s)'%(float(seconds))
		return message

	def incoming_PING(self,client,args=None):
		if args:
			client.Send('PONG %s'%args)
		else:
			client.Send('PONG')

	def incoming_REGISTER(self, client, username, password):
		(good, reason) = self.userdb.register_user(username, password, client.ip_address)
		if good:
			client.Send('REGISTRATIONACCEPTED')
		else:
			client.Send('REGISTRATIONDENIED %s'%reason)
	
	def incoming_TOKENIZE(self, client):
		client.tokenized = True
		client.Send('TOKENIZED')
	
	def incoming_TELNET(self, client):
		client.telnet = True
		client.Send('Welcome, telnet user.')
	
	def incoming_HASH(self, client):
		client.hashpw = True
		if client.telnet:
			client.Send('Your password will be hashed for you when you login.')

	def incoming_LOGIN(self, client, username, password='', cpu='0', local_ip='', sentence_args=''):
		if not username:
			client.Send('DENIED Invalid username.')
			return
		try: int(cpu)
		except: cpu = '0'
		if not validateIP(local_ip): local_ip = client.ip_address
		if '\t' in sentence_args:
			lobby_id, user_id = sentence_args.split('\t',1)
		else:
			lobby_id = sentence_args
		if client.hashpw:
			m = md5.new()
			m.update(password)
			password = base64.b64encode(binascii.a2b_hex(m.hexdigest()))
		if not username in self._root.usernames:
			good, reason = self.userdb.login_user(username, password, client.ip_address)
			if good:
				self._root.console_write('Handler %s: Successfully logged in user <%s> on session %s.'%(client.handler.num, username, client.session_id))
				self._root.usernames[username] = client
				client.ingame_time = reason.ingame_time
				client.bot = reason.bot
				client.access = reason.access
				self._calc_access(client)
				client.username = username
				client.password = password
				client.cpu = cpu
				client.local_ip = None
				client.hook = ''
				client.went_ingame = -1
				if local_ip.startswith('127.') or not validateIP(local_ip):
					client.local_ip = client.ip_address
				else:
					client.local_ip = local_ip
				client.lobby_id = lobby_id
				client.teamcolor = '0'
				client.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
				client.Send('ACCEPTED %s'%username)
				client.Send('MOTD Hey there.')
				
				usernames = dict(self._root.usernames)
				for user in usernames:
					try:
						#if username == user: continue
						addclient = self._root.usernames[user]
						client.Send('ADDUSER %s %s %s'%(user,addclient.country_code,addclient.cpu))
					except:
						pass #person must have left :)
					
				self._root.broadcast('ADDUSER %s %s %s'%(username,client.country_code,cpu),ignore=username)
				battles = dict(self._root.battles)
				for battle in battles:
					battle_id = battle
					battle = self._root.battles[battle]
					type, natType, host, port, maxplayers, passworded, rank, maphash, map, title, modname = [battle['type'], battle['natType'], battle['host'], battle['port'], battle['maxplayers'], battle['passworded'], battle['rank'], battle['maphash'], battle['map'], battle['title'], battle['modname']]
					if not host in self._root.usernames: continue # host left server
					ip_address = self._root.usernames[host].ip_address
					host_local_ip = self._root.usernames[host].local_ip
					if client.ip_address == ip_address: # translates the ip to always be compatible with the client
						translated_ip = host_local_ip
						# probably don't need this
						#if host_local_ip == local_ip:
						#	translated_ip = '127.0.0.1'
						#else:
						#	translated_ip = host_local_ip
						# this is probably not needed # neither is this
					else:
						translated_ip = ip_address
					client.Send('BATTLEOPENED %s %s %s %s %s %s %s %s %s %s %s\t%s\t%s' %(battle_id, type, natType, host, translated_ip, port, maxplayers, passworded, rank, maphash, map, title, modname))
					for user in battle['users']:
						client.Send('JOINEDBATTLE %s %s'%(battle_id, user))
				usernames = dict(self._root.usernames)
				for user in usernames:
					if user == username: continue
					client.Send('CLIENTSTATUS %s %s'%(user,self._root.usernames[user].status))
				#self._root.usernames[username] = client.session_id
				client.Send('LOGININFOEND')
				client.status = self._calc_status(client, 0)
				self._root.broadcast('CLIENTSTATUS %s %s'%(username,client.status))
				#client.Send('CLIENTSTATUS %s %s'%(username,client.status))
			else:
				self._root.console_write('Handler %s: Failed to log in user <%s> on session %s. (rejected by database)'%(client.handler.num, username, client.session_id))
				client.Send('DENIED %s'%reason)
		else:
			oldclient = self._root.usernames[username]
			if time.time() - oldclient.lastdata > 15:
				oldclient._protocol._remove(oldclient, 'Removing: Ghosted')
				oldclient.Remove()
				self._root.console_write('Handler %s: Old client inactive, ghosting user <%s> from session %s.'%(client.handler.num, username, client.session_id))
				client.Send('DENIED Ghosted old user, please relogin.')
			else:
				self._root.console_write('Handler %s: Failed to log in user <%s> on session %s. (already logged in)'%(client.handler.num, username, client.session_id))
				client.Send('DENIED Already logged in.') # negotiate relogin ----- ask other client if it is still connected, then wait 15 seconds to allow for latency

	def incoming_HOOK(self, client, chars=''):
		chars = chars.strip()
		if chars.count(' '): return
		client.hook = chars
		if chars:
			client.Send('SERVERMSG Hooking commands enabled. Use help if you don\'t know what you\'re doing. Prepend commands with "%s"'%chars)
		elif client.hook:
			client.Send('SERVERMSG Hooking commands disabled.')

	def incoming_SAY(self,client,chan,msg):
		if not msg: return
		if chan in self._root.channels:
			user = client.username
			if user in self._root.channels[chan]['users']:
				msg = self.SayHooks.hook_SAY(self,client,chan,msg) # comment out to remove sayhook # might want at the beginning in case someone needs to unban themselves from a channel # nevermind, i just need to add inchan :>
				if not msg: return
				if user in self._root.channels[chan]['mutelist']:
					mute = self._root.channels[chan]['mutelist'][user]
					if mute == 0:
						self._root.broadcast('SAID %s %s %s' % (chan,client.username,msg),chan)
					else:
						client.Send('CHANNELMESSAGE %s You are muted for the next %s.'%(chan, self._time_remaining(mute)))
				else:
					self._root.broadcast('SAID %s %s %s' % (chan,client.username,msg),chan)

	def incoming_SAYEX(self,client,chan,msg):
		if not msg: return
		if chan in self._root.channels:
			user  = client.username
			if user in self._root.channels[chan]['users']:
				msg = self.SayHooks.hook_SAYEX(self,client,chan,msg) # comment out to remove sayhook # might want at the beginning in case someone needs to unban themselves from a channel
				if user in self._root.channels[chan]['mutelist']:
					mute = self._root.channels[chan]['mutelist'][user]
					if mute == 0:
						self._root.broadcast('SAIDEX %s %s %s' % (chan,client.username,msg),chan)
					else:
						client.Send('CHANNELMESSAGE %s You are muted for the next %s.'%(chan, self._time_remaining(mute)))
				else:
					self._root.broadcast('SAIDEX %s %s %s' % (chan,client.username,msg),chan)

	def incoming_SAYPRIVATE(self,client,user,msg):
		if not msg: return
		if user in self._root.usernames:
			msg = self.SayHooks.hook_SAYPRIVATE(self,client,user,msg) # comment out to remove sayhook # might want at the beginning in case someone needs to unban themselves from a channel
			client.Send('SAYPRIVATE %s %s'%(user,msg))
			self._root.usernames[user].Send('SAIDPRIVATE %s %s'%(client.username,msg))

	def incoming_MUTE(self,client,chan,user,duration=None,args=''):
		ip = False
		quiet = False
		if args:
			for arg in args.lower().split(' '):
				if arg == 'ip':
					ip = True
				elif arg == 'quiet':
					quiet = True
		if not chan in self._root.channels:
			return
		if user in self._root.channels[chan]['users']:
			if not quiet:
				self._root.broadcast('CHANNELMESSAGE %s <%s> has muted <%s>.'%(chan, client.username, user), chan)
			try:
				duration = float(duration)*60
				if duration < 1:
					duration = -1
				else:
					duration = time.time() + duration
			except: duration = -1
			self._root.channels[chan]['mutelist'][user] = duration

	def incoming_UNMUTE(self,client,chan,user,quiet=''):
		quiet = (quiet.lower()=='quiet')
		if not chan in self._root.channels:
			return
		#elif user in self._root.channels[chan]:
		#	return
		if user in self._root.channels[chan]['mutelist']:
			self._root.broadcast('CHANNELMESSAGE %s <%s> has unmuted <%s>.'%(chan, client.username, user), chan)
			del self._root.channels[chan]['mutelist'][user]

	def incoming_MUTELIST(self, client, channel):
		if channel in self._root.channels:
			if 'mutelist' in self._root.channels[channel]:
				mutelist = dict(self._root.channels[channel]['mutelist'])
				client.Send('MUTELISTBEGIN %s'%channel)
				for mute in mutelist:
					message = self._time_remaining(mutelist[mute])
					client.Send('MUTELIST %s, %s'%(mute,message))
				client.Send('MUTELISTEND')

	def incoming_JOIN(self,client,chan,key=None):
		alreadyaliased = []
		run = True
		blind = False
		nolock = False
		while run:
			alreadyaliased.append(chan)
			if chan in self._root.chan_alias:
				alias = self._root.chan_alias[chan]
				chan, blind, nolock = (alias['chan'], alias['blind'], alias['nolock'])
				if chan in alreadyaliased: run = False # hit infinite loop
			else:
				run = False
		user = client.username
		chan = chan.lstrip('#')
		if not chan: return
		if not chan in self._root.channels:
			self._root.channels[chan] = self._new_channel(chan)
		channel = self._root.channels[chan]
		if not user in channel['users']:
			if not user == channel['owner'] and not 'mod' in client.accesslevels and not 'admin' in client.accesslevels:
				if not channel['key'] == key and channel['key'] and not nolock:
					client.Send('SERVERMSG Cannot join #%s: invalid key'%chan)
					return
				elif user in channel['ban'] and channel['autokick'] == 'ban':
					client.Send('SERVERMSG Cannot join #%s: you are banned from the channel %s'%(chan,channel['ban'][user]))
					return
				elif not user in channel['allow'] and channel['autokick'] == 'allow':
					client.Send('SERVERMSG Cannot join #%s: you are not allowed'%channel['ban']['user'])
					return
			if not chan in client.channels:
				client.channels.append(chan)
			client.Send('JOIN %s'%chan)
			if not blind:
				self._root.broadcast('JOINED %s %s'%(chan,user),chan,self._root.channels[chan]['blindusers'])
				self._root.channels[chan]['users'].append(user)
				client.Send('CLIENTS %s %s'%(chan, ' '.join(self._root.channels[chan]['users'])))
			else:
				self._root.channels[chan]['users'].append(user)
				self._root.channels[chan]['blindusers'].append(user)
		topic = channel['topic']
		if topic and user in self._root.channels[chan]['users']: # putting this outside of the check means a user can rejoin a channel to get the topic while in it
			client.Send('CHANNELTOPIC %s %s %s %s'%(chan, topic['user'], topic['time'], topic['text']))

	def incoming_SETCHANNELKEY(self,client,chan,key='*'):
		if key == '*':
			key = None
		if chan in self._root.channels:
			self._root.channels[chan]['key'] = key
			if key == None:
				self._root.broadcast('CHANNELMESSAGE %s Channel unlocked by <%s>'%(chan,client.username))
			else:
				self._root.broadcast('CHANNELMESSAGE %s Channel locked by <%s>'%(chan,client.username))

	def incoming_LEAVE(self,client,chan):
		user = client.username
		if chan in self._root.channels:
			if chan in client.channels:
				client.channels.remove(chan)
			if user in self._root.channels[chan]['users']:
				self._root.channels[chan]['users'].remove(user)
				self._root.broadcast('LEFT %s %s'%(chan, user), chan, self._root.channels[chan]['blindusers']+[user])
			if user in self._root.channels[chan]['blindusers']:
				self._root.channels[chan]['blindusers'].remove(user)
	
	def incoming_MAPGRADES(self, client, grades):
		client.Send('MAPGRADESFAILED Not implemented.')

	def incoming_OPENBATTLE(self, client, type, natType, password, port, maxplayers, hashcode, rank, maphash, sentence_args):
		if client.current_battle in self._root.battles:
			self.incoming_LEAVEBATTLE(client)
			#client.Send('SERVERMSG You are already in battle.')
			#return
		if sentence_args.count('\t') > 1:
			map, title, modname = sentence_args.split('\t',2)
		else:
			return False
		battle_id = str(self._root.nextbattle)
		self._root.nextbattle += 1
		client.current_battle = battle_id
		if password == '*':
			passworded = 0
		else:
			passworded = 1
		clients = dict(self._root.clients)
		for user in clients:
			if self._root.clients[user].ip_address == client.ip_address: # translates the ip to always be compatible with the client
				if client.local_ip == self._root.clients[user].local_ip:
					translated_ip = '127.0.0.1'
				else:
					translated_ip = client.local_ip
			else:
				translated_ip = client.ip_address
			self._root.clients[user].Send('BATTLEOPENED %s %s %s %s %s %s %s %s %s %s %s\t%s\t%s' %(battle_id, type, natType, client.username, translated_ip, port, maxplayers, passworded, rank, maphash, map, title, modname))
		self._root.battles[str(battle_id)] = {'type':type, 'natType':natType, 'password':password, 'port':port, 'maxplayers':maxplayers, 'hashcode':hashcode, 'rank':rank, 'maphash':maphash, 'map':map, 'title':title, 'modname':modname, 'passworded':passworded, 'users':{client.username:''}, 'host':client.username, 'startrects':{}, 'disabled_units':{}, 'bots':{}, 'script_tags':{}, 'replay_script':{}, 'replay':False, 'sending_replay_script':False}
		client.Send('OPENBATTLE %s'%battle_id)
		client.Send('REQUESTBATTLESTATUS')

	def incoming_SAYBATTLE(self, client, msg):
		if not msg: return
		if client.current_battle:
			battle_id = client.current_battle
			if not battle_id in self._root.battles: return
			user = client.username
			msg = self.SayHooks.hook_SAYBATTLE(self,client,battle_id,msg)
			if not msg: return
			self._root.broadcast_battle('SAIDBATTLE %s %s' % (user,msg),battle_id)

	def incoming_SAYBATTLEEX(self, client, msg):
		if client.current_battle in self._root.battles:
			self._root.broadcast_battle('SAIDBATTLEEX %s %s' % (client.username,msg),client.current_battle)

	def incoming_JOINBATTLE(self, client, battle_id, password=None):
		username = client.username
		if client.current_battle in self._root.battles:
			client.Send('JOINBATTLEFAILED You are already in a battle.')
			return
		if battle_id in self._root.battles:
			battle = self._root.battles[battle_id]
			if not battle['passworded'] == 0 and not battle['password'] == password:
				client.Send('JOINBATTLEFAILED Incorrect password.')
				return
			if not username in battle['users']:
				if username in client.battle_bans:
					client.Send('JOINBATTLEFAILED <%s> has banned you from his/her battles.'%battle['host'])
					return
				client.Send('JOINBATTLE %s %s'%(battle_id, battle['hashcode']))
				scripttags = []
				battle_script_tags = battle['script_tags']
				for tag in battle_script_tags:
					scripttags.append('%s=%s'%(tag, battle_script_tags[tag]))
				client.Send('SETSCRIPTTAGS %s'%'\t'.join(scripttags))
				self._root.broadcast('JOINEDBATTLE %s %s'%(battle_id,username))
				if battle['natType'] > 0:
					host = self._root.battles[battle_id]['host']
					if host == username:
						raise NameError,'%s is having an identity crisis'%(host)
					if client.udpport:
						self._root.usernames[host].Send('CLIENTIPPORT %s %s %s'%(username, client.ip_address, client.udpport))
				battle_users = self._root.battles[battle_id]['users']
				for user in battle_users:
					battlestatus = self._calc_battlestatus(self._root.usernames[user])
					teamcolor = self._root.usernames[user].teamcolor
					if battlestatus and teamcolor:
						client.Send('CLIENTBATTLESTATUS %s %s %s'%(user, battlestatus, teamcolor))
				battle_bots = self._root.battles[battle_id]['bots']
				for iter in battle_bots:
					bot = battle_bots[iter]
					client.Send('ADDBOT %s %s %s %s %s %s'%(battle_id, iter, bot['owner'], bot['battlestatus'], bot['teamcolor'], bot['AIDLL']))
				client.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
				client.teamcolor = '0'
				client.current_battle = battle_id
				self._root.battles[battle_id]['users'][username] = ''
				client.Send('REQUESTBATTLESTATUS')
				return
		client.Send('JOINBATTLEFAILED Unable to join battle.')

	def incoming_SETSCRIPTTAGS(self, client, scripttags): # need to add checking if the client is in a battle and the host
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				setscripttags = {}
				for tagpair in scripttags.split('\t'):
					if not '=' in tagpair:
						continue # this fails; tag isn't split by anything
					(tag, value) = tagpair.split('=')
					setscripttags.update({tag:value})
				scripttags = []
				for tag in setscripttags:
					scripttags.append('%s=%s'%(tag, setscripttags[tag]))
				self._root.battles[battle_id]['script_tags'].update(setscripttags)
				if not scripttags:
					return
				self._root.broadcast_battle('SETSCRIPTTAGS %s'%'\t'.join(scripttags), battle_id)
	
	def incoming_SCRIPTSTART(self, client):
		battle_id = client.current_battle
		if battle_id:
			if self._root.battles[battle_id]['host'] == client.username:
				self._root.battles[battle_id]['replay_script'] = []
				if self._root.battles[battle_id]['sending_replay_script']:
					client.Send('SERVERMSG You have issues. Talk to your lobby dev.')
					self._root.battles[battle_id]['sending_replay_script'] = False
				else:
					self._root.battles[battle_id]['sending_replay_script'] = True
	
	def incoming_SCRIPT(self, client, scriptline):
		battle_id = client.current_battle
		if battle_id:
			if self._root.battles[battle_id]['host'] == client.username:
				if self._root.battles[battle_id]['sending_replay_script']:
					self._root.battles[battle_id]['replay_script'].append('%s\n'%scriptline)

	def incoming_SCRIPTEND(self, client):
		battle_id = client.current_battle
		if battle_id:
			if self._root.battles[battle_id]['host'] == client.username:
				if self._root.battles[battle_id]['sending_replay_script']:
					self._root.battles[battle_id]['replay'] = True
					self._root.battles[battle_id]['sending_replay_script'] = False

	def incoming_LEAVEBATTLE(self, client):
		if client.current_battle in self._root.battles:
			battle_id = client.current_battle
			if self._root.battles[battle_id]['host'] == client.username:
				self._root.broadcast('BATTLECLOSED %s'%battle_id)
				client.hostport = 8542
				del self._root.battles[battle_id]
			elif client.username in self._root.battles[battle_id]['users']:
				del self._root.battles[battle_id]['users'][client.username]
				battle_bots = dict(client.battle_bots)
				for bot in battle_bots:
					del client.battle_bots[bot]
					del self._root.battles[battle_id]['bots'][bot]
					self._root.broadcast_battle('REMOVEBOT %s'%bot, battle_id)
				self._root.broadcast('LEFTBATTLE %s %s'%(battle_id, client.username))
		client.current_battle = None

	def incoming_MYBATTLESTATUS(self, client, battlestatus, myteamcolor):
		if not battlestatus.isdigit():
			client.Send('SERVERMSG MYBATTLESTATUS failed - invalid status.')
			return
		if not myteamcolor.isdigit():
			client.Send('SERVERMSG MYBATTLESTATUS failed - invalid teamcolor.')
			return
		if client.current_battle in self._root.battles:
			u, u, u, u, side1, side2, side3, side4, sync1, sync2, u, u, u, u, handicap1, handicap2, handicap3, handicap4, handicap5, handicap6, handicap7, mode, ally1, ally2, ally3, ally4, id1, id2, id3, id4, ready, u = self._dec2bin(battlestatus, 32)[0:32]
			client.battlestatus.update({'ready':ready, 'id':id1+id2+id3+id4, 'ally':ally1+ally2+ally3+ally4, 'mode':mode, 'sync':sync1+sync2, 'side':side1+side2+side3+side4})
			client.teamcolor = myteamcolor
			self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(client.username, self._calc_battlestatus(client), myteamcolor), client.current_battle)

	def incoming_UPDATEBATTLEINFO(self, client, SpectatorCount, locked, maphash, mapname):
		if not client.current_battle == None:
			if self._root.battles[client.current_battle]['host'] == client.username:
				updated = {'SpectatorCount':SpectatorCount, 'locked':locked, 'maphash':maphash, 'mapname':mapname}
				self._root.battles[client.current_battle].update(updated)
				self._root.broadcast('UPDATEBATTLEINFO %s %s %s %s %s' %(client.current_battle,updated['SpectatorCount'], updated['locked'], updated['maphash'], updated['mapname']), client.current_battle)

	def incoming_MYSTATUS(self, client, status):
		if not status.isdigit():
			client.Send('SERVERMSG MYSTATUS failed - invalid status.')
			return
		was_ingame = client.ingame
		client.status = self._calc_status(client, status)
		if client.ingame and not was_ingame:
			battle_id = client.current_battle
			if battle_id:
				host = self._root.battles[battle_id]['host']
				if len(self._root.battles[battle_id]['users']) > 1:
					client.went_ingame = time.time()
				if client.username == host:
					if not client.hostport == 8542:
						self._root.broadcast_battle('HOSTPORT %i'%client.hostport, battle_id, host)
					if self._root.battles[battle_id]['replay']:
						self._root.broadcast_battle('SCRIPTSTART', battle_id, client.username)
						for line in self._root.battles[battle_id]['replay_script']:
							self._root.broadcast_battle('SCRIPT %s'%line, battle_id, client.username)
						self._root.broadcast_battle('SCRIPTEND', battle_id, client.username)
		elif was_ingame and not client.ingame:
			ingame_time = float(time.time() - client.went_ingame) / 60
			if ingame_time >= 1:
				client.ingame_time += int(ingame_time)
		if not client.username in self._root.usernames: return
		self._root.broadcast('CLIENTSTATUS %s %s'%(client.username, client.status))

	def incoming_CHANNELS(self, client):
		for channel in self._root.channels:
			if not channel['owner']: return # only list registered channels
			chaninfo = '%s %s'%(channel, len(self._root.channels[channel]['users']))
			topic = self._root.channels[channel]['topic']
			if topic:
				chaninfo = '%s %s'%(chaninfo, topic['text'])
			client.Send('CHANNEL %s'%chaninfo)
		client.Send('ENDOFCHANNELS')

	def incoming_CHANNELTOPIC(self, client, channel, topic):
		if channel in self._root.channels:
			if client.username in self._root.channels[channel]['users']:
				topicdict = {'user':client.username, 'text':topic, 'time':'%s'%(int(time.time())*1000)}
				self._root.channels[channel]['topic'] = topicdict
				self._root.broadcast('CHANNELMESSAGE %s Topic changed.'%channel, channel)
				self._root.broadcast('CHANNELTOPIC %s %s %s %s'%(channel, client.username, topicdict['time'], topic), channel)

	def incoming_CHANNELMESSAGE(self, client, channel, message):
		if channel in self._root.channels:
			self._root.broadcast('CHANNELMESSAGE %s %s'%(channel, message), channel)

	def incoming_FORCELEAVECHANNEL(self, client, channel, username, reason=''):
		if channel in self._root.channels:
			if username in self._root.channels[channel]['users']:
				self._root.usernames[username].Send('FORCELEAVECHANNEL %s %s %s'%(channel,client.username,reason))
				del self._root.channels[channel]['users'][username]
				self._root.broadcast('CHANNELMESSAGE %s %s kicked from channel by <%s>.'%(channel,username,client.username),channel)
				self._root.broadcast('LEFT %s %s kicked from channel.'%(channel,username),channel)

	def incoming_RING(self, client, username):
		if username in self._root.usernames:
			self._root.usernames[username].Send('RING %s'%(client.username))

	def incoming_ADDSTARTRECT(self, client, allyno, left, top, right, bottom):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if self._root.battles[client.current_battle]['host'] == client.username:
				self._root.battles[client.current_battle]['startrects'][allyno] = {'left':left, 'top':top, 'right':right, 'bottom':bottom}
				self._root.broadcast_battle('ADDSTARTRECT %s %s %s %s %s'%(allyno, left, top, right, bottom), client.current_battle)

	def incoming_REMOVESTARTRECT(self, client, allyno):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if self._root.battles[battle_id]['host'] == client.username:
				del self._root.battles[battle_id]['startrects'][allyno]
				self._root.broadcast_battle('REMOVESTARTRECT %s'%allyno,client.current_battle)

	def incoming_DISABLEUNITS(self, client, units):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				units = units.split(' ')
				disabled_units = []
				for unit in units:
					if not unit in self._root.battles[battle_id]['disabled_units']:
						self._root.battles[battle_id]['disabled_units'][unit] = ''
						disabled_units.append(unit)
				if disabled_units:
					disabled_units = ' '.join(disabled_units)
					self._root.broadcast_battle('DISABLEUNITS %s'%disabled_units, battle_id, client.username)

	def incoming_ENABLEUNITS(self, client, units):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				units = units.split(' ')
				enabled_units = []
				for unit in units:
					if unit in self._root.battles[battle_id]['disabled_units']:
						del self._root.battles[battle_id]['disabled_units'][unit]
						enabled_units.append(unit)
				if enabled_units:
					enabled_units = ' '.join(enabled_units)
					self._root.broadcast_battle('ENABLEUNITS %s'%enabled_units, battle_id, client.username)

	def incoming_ENABLEALLUNITS(self, client):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				self._root.battles[battle_id]['disabled_units'] = {}
				self._root.broadcast_battle('ENABLEALLUNITS', battle_id, client.username)

	def incoming_HANDICAP(self, client, username, value):
		battle_id = client.current_battle
		if battle_id in self._root.battles and value in str(range(0,101)).strip('[]').split(', '):
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					self._root.clients[client].battlestatus['handicap'] = self._dec2bin(value, 7)
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(self._root.clients[client]), self._root.clients[client].teamcolor), battle_id)

	def incoming_KICKFROMBATTLE(self, client, username):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host'] or 'mod' in client.accesslevels:
				if username in self._root.battles[battle_id]['users']:
					kickuser = self._root.usernames[username]
					kickuser.Send('FORCEQUITBATTLE')
					self._root.broadcast('LEFTBATTLE %s %s'%(battle_id, username), ignore=username)
					if username == self._root.battles[battle_id]['host']:
						self._root.broadcast('BATTLECLOSED %s'%battle_id)
			else:
				client.Send('SERVERMSG You must be the battle host to kick from a battle.')

	def incoming_FORCETEAMNO(self, client, username, teamno):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					self._root.clients[client].battlestatus['id'] = self._dec2bin(teamno, 4)
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(self._root.clients[client]), self._root.clients[client].teamcolor), battle_id)

	def incoming_FORCEALLYNO(self, client, username, allyno):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					self._root.clients[client].battlestatus['ally'] = self._dec2bin(allyno, 4)
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(self._root.clients[client]), self._root.clients[client].teamcolor), battle_id)

	def incoming_FORCETEAMCOLOR(self, client, username, teamcolor):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					self._root.clients[client].teamcolor = teamcolor
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(self._root.clients[client]), self._root.clients[client].teamcolor), battle_id)

	def incoming_FORCESPECTATORMODE(self, client, username):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					self._root.clients[client].battlestatus['mode'] = '0'
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(self._root.clients[client]), self._root.clients[client].teamcolor), battle_id)

	def incoming_ADDBOT(self, client, name, battlestatus, teamcolor, AIDLL): #need to add bot removal on user removal
		if client.current_battle in self._root.battles:
			battle_id = client.current_battle
			if not name in self._root.battles[battle_id]['bots']:
				client.battle_bots[name] = battle_id
				self._root.battles[battle_id]['bots'][name] = {'owner':client.username, 'battlestatus':battlestatus, 'teamcolor':teamcolor, 'AIDLL':AIDLL}
				self._root.broadcast_battle('ADDBOT %s %s %s %s %s %s'%(battle_id, name, client.username, battlestatus, teamcolor, AIDLL), battle_id)

	def incoming_UPDATEBOT(self, client, name, battlestatus, teamcolor):
		if client.current_battle in self._root.battles:
			battle_id = client.current_battle
			if name in self._root.battles[battle_id]['bots']:
				if client.username == self._root.battles[battle_id]['bots'][name]['owner'] or client.username == self._root.battles[battle_id]['host']:
					self._root.battles[battle_id]['bots'][name].update({'battlestatus':battlestatus, 'teamcolor':teamcolor})
					self._root.broadcast_battle('UPDATEBOT %s %s %s %s'%(battle_id, name, battlestatus, teamcolor), battle_id)
	
	def incoming_REMOVEBOT(self, client, name):
		if client.current_battle in self._root.battles:
			battle_id = client.current_battle
			if name in self._root.battles[battle_id]['bots']:
				if client.username == self._root.battles[battle_id]['bots'][name]['owner'] or client.username == self._root.battles[battle_id]['host']:
					del self._root.usernames[self._root.battles[battle_id]['bots'][name]['owner']].battle_bots[name]
					del self._root.battles[battle_id]['bots'][name]
				self._root.broadcast_battle('REMOVEBOT %s %s'%(battle_id, name), battle_id)
	
	def incoming_FORCECLOSEBATTLE(self, client, battle_id=None):
		if not battle_id: battle_id = client.current_battle
		if not battle_id in self._root.battles:
			client.Send('SERVERMSG Invalid battle ID.')
			return
		self.incoming_KICKFROMBATTLE(client, self._root.battles[battle_id])
	
	def incoming_GETINGAMETIME(self, client, username=None):
		if username and 'mod' in client.accesslevels:
			if username in self._root.usernames: # change to do SQL query if user is not logged in # maybe abstract in the datahandler to automatically query SQL for users not logged in.
				ingame_time = self._root.usernames[username].ingame_time
				client.Send('SERVERMSG %s has an in-game time of %d minutes (%d hours).'%(username, ingame_time, ingame_time / 60))
		else:
			ingame_time = client.ingame_time
			client.Send('SERVERMSG Your in-game time is %d minutes (%d hours).'%(ingame_time, ingame_time / 60))

	def incoming_FORGEMSG(self, client, user, msg):
		if user in self._root.usernames:
			self._root.usernames[user].Send(msg)

	def incoming_FORGEREVERSEMSG(self, client, user, msg):
		if user in self._root.usernames:
			self._handle(self._root.usernames[user], msg)

	def incoming_GETLOBBYVERSION(self, client, user):
		if user in self._root.usernames: # need to concatenate to a function liek user = _find_user(user), if user: do junk else: say there's no user or owait... i can return to way back by catching an exception :D
			if hasattr(self._root.usernames[user], 'lobby_id'):
				client.Send('SERVERMSG <%s> is using %s'%(user, self._root.usernames[user].lobby_id))
	
	def incoming_GETSENDBUFFERSIZE(self, client, username):
		if username in self._root.usernames:
			client.Send('SERVERMSG <%s> has a sendbuffer size of %s'%(username, len(self._root.usernames[username].sendbuffer)))

	def incoming_SETINGAMETIME(self, client, user, minutes):
		if user in self._root.usernames:
			self._root.usernames[user].ingame_time = minutes

	def incoming_SETBOTMODE(self, client, user, mode):
		if user in self._root.usernames:
			self._root.usernames[user].bot = (mode == True)
	
	def incoming_BROADCAST(self, client, msg):
		self._root.broadcast('SERVERMSG %s'%msg)
	
	def incoming_BROADCASTEX(self, client, msg):
		self._root.broadcast('SERVERMSGBOX %s'%msg)
	
	def incoming_ADMINBROADCAST(self, client, msg):
		self._root.admin_broadcast(msg)

	def incoming_KICKUSER(self, client, user):
		if user in self._root.usernames:
			kickeduser = self._root.usernames[user]
			for chan in list(kickeduser.channels):
				self._root.broadcast('CHANNELMESSAGE %s <%s> has been kicked from the server by <%s>'%(chan, user, client.username))
			self._remove(kickeduser, 'Kicked from server')
			kickeduser.Remove()
	
	def incoming_KILLALL(self, client):
		self._remove(client, 'Idiot')
		client.Remove()
	
	def incoming_TESTLOGIN(self, client, username, password):
		good, reason = self.userdb.login_user(username, password, client.ip_address)
		if good:
			client.Send('TESTLOGINACCEPT')
		else:
			client.Send('TESTLOGINDENY')

	def incoming_EXIT(self, client, reason=('Exiting')):
		self._remove(client, 'Quit: %s'%reason)
		try: client.handler.input.remove(client.conn)
		except: pass
		try: client.handler.output.remove(client.conn)
		except: pass
		client.Remove()

	def incoming_PYTHON(self, client, code):
		'Execute Python code.'
		code = code.replace('\\n', '\n').replace('\\t','\t')
		try:
			exec code
		except:
			self._root.error(traceback.format_exc())

	def incoming_MOD(self, client, user):
		changeuser = self._root.usernames[user]
		changeuser.access = 'mod'
		changeuser.accesslevels = ['mod', 'user']
		self._calc_access(changeuser)
		self._root.broadcast('CLIENTSTATUS %s %s'%(user,changeuser.status))

	def incoming_ADMIN(self, client, user):
		changeuser = self._root.usernames[user]
		changeuser.access = 'admin'
		changeuser.accesslevels = ['admin', 'mod', 'user']
		self._calc_access(changeuser)
		self._root.broadcast('CLIENTSTATUS %s %s'%(user,changeuser.status))

