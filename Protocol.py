import inspect, time, re
import md5, base64, binascii
import traceback, sys, os

restricted = {
'everyone':['TOKENIZE','TELNET','HASH','EXIT','PING'],
'fresh':['LOGIN','REGISTER'],
'agreement':['CONFIRMAGREEMENT'],
'user':[
	########
	# battle
	'ADDBOT',
	'ADDSTARTRECT',
	'DISABLEUNITS',
	'ENABLEUNITS',
	'FORCEALLYNO',
	'FORCESPECTATORMODE',
	'FORCETEAMCOLOR',
	'FORCETEAMNO',
	'HANDICAP',
	'JOINBATTLE',
	'KICKFROMBATTLE',
	'LEAVEBATTLE',
	'MAPGRADES',
	'MYBATTLESTATUS',
	'OPENBATTLE',
	'REMOVEBOT',
	'REMOVESTARTRECT',
	'RING',
	#########
	# channel
	'CHANNELS',
	'JOIN',
	'LEAVE',
	'MUTELIST',
	'SAY',
	'SAYEX',
	'SAYPRIVATE',
	'SAYBATTLE',
	'SAYBATTLEEX',
	'SCRIPT',
	'SCRIPTEND',
	'SCRIPTSTART',
	'SETSCRIPTTAGS',
	'UPDATEBATTLEINFO',
	'UPDATEBOT',
	'UPDATEBATTLEDETAILS',
	########
	# meta
	'GETINGAMETIME',
	'GETREGISTRATIONDATE',
	'MYSTATUS',
	'RENAMEACCOUNT'],
	'mod':['CHANNELTOPIC','FORCECLOSEBATTLE','FORCELEAVECHANNEL','KICKUSER','MUTE','SETBOTMODE','UNMUTE'],
	'admin':[
	#########
	# channel
	'ALIAS','UNALIAS','ALIASLIST',
	#########
	# server
	'ADMINBROADCAST', 'BROADCAST','BROADCASTEX','RELOAD'
	#########
	# users
	'FORGEMSG','FORGEREVERSEMSG',
	'GETLOBBYVERSION','GETSENDBUFFERSIZE',
	'ADMIN','MOD','DEBUG',
	'TESTLOGIN','SETBOTMODE','SETINGAMETIME',],
}

restricted_list = []
for level in restricted:
	restricted_list += restricted[level]

#from Users import UsersHandler
#from Users import LANUsersHandler as UsersHandler # we're in LAN mode

ipRegex = r"^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$"
re_ip = re.compile(ipRegex)

def validateIP(ipAddress):
	return re_ip.match(ipAddress)

class Protocol:
	def __init__(self, root, handler):
		LAN = root.LAN
		self._root = root
		self.handler = handler
		if LAN or not root.engine:
			self.userdb = __import__('LANUsers').UsersHandler(root) # maybe make an import request to datahandler, then have it reload it too. less hardcoded-ness
		else:
			try: self.userdb = __import__('SQLUsers').UsersHandler(root, root.engine)
			except:
				print traceback.format_exc()
				print 'Error importing SQL - reverting to LAN'
				self.userdb = __import__('LANUsers').UsersHandler(root)
		self.SayHooks = root.SayHooks

	def _new(self, client):
		if self._root.LAN: lan = '1'
		else: lan = '0'
		login_string = ' '.join((self._root.server, str(self._root.server_version), self._root.latestspringversion, str(self._root.natport), lan))
		#login_string = '%s %s %s %s %s'% (self._root.server, self._root.server_version, self._root.latestspringversion, self._root.natport, lan)
		client.Send(login_string)

	def _remove(self, client, reason='Quit'):
		if client.username:
			if client.removing: return
			if client.static: return
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
				self.in_MYSTATUS(client,'0')
			self._root.broadcast('REMOVEUSER %s'%user)
			del self._root.clients[client.session_id]

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
		
		if not hasattr(self, 'in_'+command):
			return False

		access = []
		for level in client.accesslevels:
			access += restricted[level]
		
		if command in restricted_list:
			if not command in access:
				client.Send('SERVERMSG %s failed. Insufficient rights.'%command)
				return False
		else:
			if not 'user' in client.accesslevels:
				client.Send('SERVERMSG %s failed. Insufficient rights.'%command)
				return False
		
		command = 'in_%s' % command
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
		#	client.Send('SERVERMSG %s failed. Incorrect arguments.'%command.partition('in_')[2])
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
		bot, access, rank1, rank2, rank3, away, ingame = status[-7:]
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
		client.is_ingame = (ingame == '1')
		client.away = (away == '1')
		status = self._bin2dec('%s%s%s%s%s%s%s'%(bot, access, rank1, rank2, rank3, away, ingame))
		client.status = status
		return status

	def _calc_battlestatus(self, client):
		battlestatus = client.battlestatus
		status = self._bin2dec('0000%s%s0000%s%s%s%s%s0'%(battlestatus['side'], battlestatus['sync'], battlestatus['handicap'], battlestatus['mode'], battlestatus['ally'], battlestatus['id'], battlestatus['ready']))
		return status
	
	def _new_channel(self, chan):
		# probably make a SQL query here # nevermind, I'll just load channels at the beginning
		return {'users':[], 'blindusers':[], 'admins':[], 'ban':{}, 'allow':[], 'autokick':'ban', 'chanserv':False, 'owner':'', 'mutelist':{}, 'antispam':{'enabled':False, 'quiet':False, 'agressiveness':1, 'bonuslength':100, 'duration':900}, 'censor':False, 'antishock':False, 'topic':None, 'key':None}

	def _format_time(self, seconds):
		if seconds < 1:
			message = 'forever'
		else:
			seconds = seconds - time.time()
			minutesleft = float(seconds) / 60
			hoursleft = minutesleft / 60
			daysleft = hoursleft / 24
			if daysleft > 7:
				message = '%0.2f weeks' % (daysleft / 7)
			if daysleft == 7:
				message = 'a week'
			if daysleft > 1:
				message = '%0.2f days' % daysleft
			if daysleft == 1:
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

	def in_PING(self, client, args=None):
		if args:
			client.Send('PONG %s'%args)
		else:
			client.Send('PONG')
	
	def in_PORTTEST(self, client, port):
		host = client.ip_address
		port = int(port)
		sock = socket(AF_INET,SOCK_DGRAM)
		sock.sendto('Port testing...', (host, port))

	def in_REGISTER(self, client, username, password):
		good, reason = self.userdb.register_user(username, password, client.ip_address)
		if good:
			client.Send('REGISTRATIONACCEPTED')
		else:
			client.Send('REGISTRATIONDENIED %s'%reason)
	
	def in_TOKENIZE(self, client):
		client.tokenized = True
		client.Send('TOKENIZED')
	
	def in_TELNET(self, client):
		client.telnet = True
		client.Send('Welcome, telnet user.')
	
	def in_HASH(self, client):
		client.hashpw = True
		if client.telnet:
			client.Send('Your password will be hashed for you when you login.')

	def in_LOGIN(self, client, username, password='', cpu='0', local_ip='', sentence_args=''):
		if not username:
			client.Send('DENIED Invalid username.')
			return
		try: int(cpu)
		except: cpu = '0'
		if not validateIP(local_ip): local_ip = client.ip_address
		if '\t' in sentence_args:
			lobby_id, user_id = sentence_args.split('\t',1)
			if user_id.replace('-',1).isnum():
				user_id = int(user_id)
			else: user_id = None
		else:
			lobby_id = sentence_args
			user_id = 0
		if client.hashpw:
			m = md5.new()
			m.update(password)
			password = base64.b64encode(binascii.a2b_hex(m.hexdigest()))
		#good, reason = self.userdb.login_user(username, password, client.ip_address)
		#if not self._root.LAN and good: username = reason.casename # springlobby can't handle the username changing after login
		if not username in self._root.usernames:
			good, reason = self.userdb.login_user(username, password, client.ip_address, lobby_id, user_id)
			if good:
				if client.access == 'agreement':
					agreement = ['AGREEMENT {\rtf1\ansi\ansicpg1250\deff0\deflang1060{\fonttbl{\f0\fswiss\fprq2\fcharset238 Verdana;}{\f1\fswiss\fprq2\fcharset238{\*\fname Arial;}Arial CE;}{\f2\fswiss\fcharset238{\*\fname Arial;}Arial CE;}}',
					'AGREEMENT {\*\generator Msftedit 5.41.15.1507;}\viewkind4\uc1\pard\ul\b\f0\fs22 Terms of Use\ulnone\b0\f1\fs20\par',
					'AGREEMENT \f2\par',
					'AGREEMENT \f0\fs16 While the administrators and moderators of this server will attempt to keep spammers and players violating this agreement off the server, it is impossible for them to maintain order at all times. Therefore you acknowledge that any messages in our channels express the views and opinions of the author and not the administrators or moderators (except for messages by these people) and hence will not be held liable.\par',
					'AGREEMENT \par',
					'AGREEMENT You agree not to use any abusive, obscene, vulgar, slanderous, hateful, threatening, sexually-oriented or any other material that may violate any applicable laws. Doing so may lead to you being immediately and permanently banned (and your service provider being informed). You agree that the administrators and moderators of this server have the right to mute, kick or ban you at any time should they see fit. As a user you agree to any information you have entered above being stored in a database. While this information will not be disclosed to any third party without your consent administrators and moderators cannot be held responsible for any hacking attempt that may lead to the data being compromised. Passwords are sent and stored in encoded form. Any personal information such as personal statistics will be kept privately and will not be disclosed to any third party.\par',
					'AGREEMENT \par',
					'AGREEMENT By using this service you hereby agree to all of the above terms.\fs18\par',
					'AGREEMENT \f2\fs20\par',
					'AGREEMENT }',
					'AGREEMENTEND']
					for line in agreement: client.Send(line)
					return
				self._root.console_write('Handler %s: Successfully logged in user <%s> on session %s.'%(client.handler.num, username, client.session_id))
				client.username = username
				self._root.usernames[username] = client
				
				client.ingame_time = int(reason.ingame_time)
				client.bot = reason.bot
				client.access = reason.access
				client.last_login = reason.last_login
				client.register_date = reason.register_date
				self._calc_access(client)
				client.username = username
				client.password = password
				client.cpu = cpu
				client.local_ip = None
				client.hook = ''
				client.went_ingame = 0
				if local_ip.startswith('127.') or not validateIP(local_ip):
					client.local_ip = client.ip_address
				else:
					client.local_ip = local_ip
				client.lobby_id = lobby_id
				client.teamcolor = '0'
				client.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
				client.Send('ACCEPTED %s'%username)
				client.Send('MOTD Hey there.')
				
				self._root.broadcast('ADDUSER %s %s %s'%(username,client.country_code,cpu),ignore=username)
				
				# aquire usernames lock
				#lock = self._root.usernames.lock()
				usernames = dict(self._root.usernames) # cache them here in case anyone joins or hosts a battle
				for user in usernames: #self._root.usernames.__iter__(lock):
					try:
						#if username == user: continue
						addclient = self._root.usernames[user]
						client.Send('ADDUSER %s %s %s'%(user,addclient.country_code,addclient.cpu))
					except: pass #person must have left :)
				#self._root.usernames.unlock(lock)
				# release usernames lock
				
				# acquire battles lock
				#lock = self._root.battles.lock()
				battles = dict(self._root.battles)
				for battle in battles: #self._root.battles.__iter__(lock):
					#try:
						battle_id = battle
						ubattle = self._root.battles[battle_id].copy()
						#type, natType, host, port, maxplayers, passworded, rank, maphash, engine, version, map, title, modname = [battle['type'], battle['natType'], battle['host'], battle['port'], battle['maxplayers'], battle['passworded'], battle['rank'], battle['maphash'], battle['engine'], battle['version'], battle['map'], battle['title'], battle['modname']]
						host = ubattle['host']
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
						ubattle.update({'ip':translated_ip})
						#client.Send('BATTLEOPENED %s %s %s %s %s %s %s %s %s %s %s %s %s\t%s\t%s' %(battle_id, type, natType, host, translated_ip, port, maxplayers, passworded, rank, maphash, engine, version, map, title, modname))
						#self._root.clients[user].Send('BATTLEOPENED %(id)s %(type)s %(natType)s %(host)s %(ip)s %(port)s %(maxplayers)s %(passworded)s %(rank)s %(maphash)s %(engine)s %(version)s %(map)s\t%(title)s\t%(modname)s' % battle)
						client.Send('BATTLEOPENED %(id)s %(type)s %(natType)s %(host)s %(ip)s %(port)s %(maxplayers)s %(passworded)s %(rank)s %(maphash)s %(map)s\t%(title)s\t%(modname)s' % ubattle)
						for user in ubattle['users']:
							if not user == ubattle['host']: client.Send('JOINEDBATTLE %s %s'%(battle_id, user))
					#except: pass # battle closed
				#self._root.battles.unlock(lock)
				
				#lock = self._root.usernames.lock()
				for user in usernames: # self._root.usernames.__iter__(lock):
					if user == username: continue # potential problem spot, might need to check to make sure username is still in user db
					client.Send('CLIENTSTATUS %s %s'%(user,self._root.usernames[user].status))
				#self._root.usernames.unlock(lock)
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
				if self._root.LAN and not oldclient.password == password:
					client.Send('DENIED Would ghost old user, but we are in LAN mode and your password does not match.')
					return
				oldclient._protocol._remove(oldclient, 'Removing: Ghosted')
				oldclient.Remove()
				self._root.console_write('Handler %s: Old client inactive, ghosting user <%s> from session %s.'%(client.handler.num, username, client.session_id))
				#client.Send('DENIED Ghosted old user, please relogin.') # relogin is automagic :D
				self.in_LOGIN(client, username, password, cpu, local_ip, sentence_args) # kicks old user and logs in new user
			else:
				self._root.console_write('Handler %s: Failed to log in user <%s> on session %s. (already logged in)'%(client.handler.num, username, client.session_id))
				client.Send('DENIED Already logged in.') # negotiate relogin ----- ask other client if it is still connected, then wait 15 seconds to allow for latency

	def in_CONFIRMAGREEMENT(self, client):
		if client.access == 'agreement':
			client.access = 'fresh'
			# TODO - Update access in db

	def in_HOOK(self, client, chars=''):
		chars = chars.strip()
		if chars.count(' '): return
		client.hook = chars
		if chars:
			client.Send('SERVERMSG Hooking commands enabled. Use help if you don\'t know what you\'re doing. Prepend commands with "%s"'%chars)
		elif client.hook:
			client.Send('SERVERMSG Hooking commands disabled.')
	
	def in_SAYHOOKED(self, client, chan, msg):
		if not msg: return
		if chan in self._root.channels:
			user = client.username
			if user in self._root.channels[chan]['users']:
				self.SayHooks.hook_SAY(self, client, chan, msg)
	
	#def in_SAYEXHOOKED(self, client, chan, msg): # sayex hook was only for filtering
	#	if not msg: return
	#	if chan in self._root.channels:
	#		user = client.username
	#		if user in self._root.channels[chan]['users']:
	#			self.SayHooks.hook_SAYEX(self,client,chan,msg)
	
	def in_SAYPRIVATEHOOKED(self, client, msg):
		if not msg: return
		user = client.username
		self.SayHooks.hook_SAYPRIVATE(self, client, msg)
	
	def in_SAYBATTLEHOOKED(self, client, msg):
		battle_id = client.current_battle
		if not battle_id in self._root.battles: return
		if not client in self._root.battles['users']: return
		self.SayHooks.hook_SAYBATTLE(self, client, battle_id, msg)

	def in_SAY(self, client, chan, msg):
		if not msg: return
		if chan in self._root.channels:
			user = client.username
			if user in self._root.channels[chan]['users']:
				msg = self.SayHooks.hook_SAY(self, client, chan, msg) # comment out to remove sayhook # might want at the beginning in case someone needs to unban themselves from a channel # nevermind, i just need to add inchan :>
				if not msg: return
				if user in self._root.channels[chan]['mutelist']:
					mute = self._root.channels[chan]['mutelist'][user]
					if mute == 0:
						self._root.broadcast('SAID %s %s %s' % (chan, client.username, msg), chan)
					else:
						client.Send('CHANNELMESSAGE %s You are muted for the next %s.'%(chan, self._format_time(mute)))
				else:
					self._root.broadcast('SAID %s %s %s' % (chan, client.username ,msg), chan)

	def in_SAYEX(self, client, chan, msg):
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
						client.Send('CHANNELMESSAGE %s You are muted for the next %s.'%(chan, self._format_time(mute)))
				else:
					self._root.broadcast('SAIDEX %s %s %s' % (chan,client.username,msg),chan)

	def in_SAYPRIVATE(self, client, user, msg):
		if not msg: return
		if user in self._root.usernames:
			msg = self.SayHooks.hook_SAYPRIVATE(self, client, user, msg) # comment out to remove sayhook # might want at the beginning in case someone needs to unban themselves from a channel
			client.Send('SAYPRIVATE %s %s'%(user, msg))
			self._root.usernames[user].Send('SAIDPRIVATE %s %s'%(client.username, msg))

	def in_MUTE(self, client, chan, user, duration=None, args=''):
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

	def in_UNMUTE(self, client, chan, user, quiet=''):
		quiet = (quiet.lower()=='quiet')
		if not chan in self._root.channels:
			return
		#elif user in self._root.channels[chan]:
		#	return
		if user in self._root.channels[chan]['mutelist']:
			self._root.broadcast('CHANNELMESSAGE %s <%s> has unmuted <%s>.'%(chan, client.username, user), chan)
			del self._root.channels[chan]['mutelist'][user]

	def in_MUTELIST(self, client, channel):
		if channel in self._root.channels:
			if 'mutelist' in self._root.channels[channel]:
				mutelist = dict(self._root.channels[channel]['mutelist'])
				client.Send('MUTELISTBEGIN %s'%channel)
				for mute in mutelist:
					message = self._format_time(mutelist[mute])
					client.Send('MUTELIST %s, %s'%(mute,message))
				client.Send('MUTELISTEND')

	def in_JOIN(self, client, chan, key=None):
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
	
	def in_SETCHANNELKEY(self, client, chan, key='*'):
		if key == '*':
			key = None
		if chan in self._root.channels:
			self._root.channels[chan]['key'] = key
			if key == None:
				self._root.broadcast('CHANNELMESSAGE %s Channel unlocked by <%s>'%(chan,client.username), chan)
			else:
				self._root.broadcast('CHANNELMESSAGE %s Channel locked by <%s>'%(chan,client.username), chan)
	
	def in_LEAVE(self, client, chan):
		user = client.username
		if chan in self._root.channels:
			if chan in client.channels:
				client.channels.remove(chan)
			if user in self._root.channels[chan]['users']:
				self._root.channels[chan]['users'].remove(user)
				self._root.broadcast('LEFT %s %s'%(chan, user), chan, self._root.channels[chan]['blindusers']+[user])
			if user in self._root.channels[chan]['blindusers']:
				self._root.channels[chan]['blindusers'].remove(user)
	
	def in_MAPGRADES(self, client, grades):
		client.Send('MAPGRADESFAILED Not implemented.')

	def in_OPENBATTLE(self, client, type, natType, password, port, maxplayers, hashcode, rank, maphash, sentence_args):
	#def in_OPENBATTLE(self, client, type, natType, password, port, maxplayers, hashcode, rank, maphash, engine, version, sentence_args):
		if client.current_battle in self._root.battles:
			self.in_LEAVEBATTLE(client)
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
		battle_id = str(battle_id)
		#battle = {'id':battle_id, 'type':type, 'natType':natType, 'password':password, 'port':port, 'maxplayers':maxplayers, 'hashcode':hashcode, 'rank':rank, 'maphash':maphash, 'engine':engine, 'version':version, 'map':map, 'title':title, 'modname':modname, 'passworded':passworded, 'users':{client.username:''}, 'host':client.username, 'startrects':{}, 'disabled_units':{}, 'bots':{}, 'script_tags':{}, 'replay_script':{}, 'replay':False, 'sending_replay_script':False, 'locked':False}
		battle = {'id':battle_id, 'type':type, 'natType':natType, 'password':password, 'port':port, 'maxplayers':maxplayers, 'hashcode':hashcode, 'rank':rank, 'maphash':maphash, 'map':map, 'title':title, 'modname':modname, 'passworded':passworded, 'users':{client.username:''}, 'host':client.username, 'startrects':{}, 'disabled_units':{}, 'bots':{}, 'script_tags':{}, 'replay_script':{}, 'replay':False, 'sending_replay_script':False, 'locked':False}
		for user in clients:
			ubattle = battle.copy()
			if self._root.clients[user].ip_address == client.ip_address: # translates the ip to always be compatible with the client
				if client.local_ip == self._root.clients[user].local_ip:
					translated_ip = '127.0.0.1'
				else:
					translated_ip = client.local_ip
			else:
				translated_ip = client.ip_address
			ubattle.update({'passworded':passworded, 'ip':translated_ip})
			#self._root.clients[user].Send('BATTLEOPENED %(id)s %(type)s %(natType)s %(host)s %(ip)s %(port)s %(maxplayers)s %(passworded)s %(rank)s %(maphash)s %(engine)s %(version)s %(map)s\t%(title)s\t%(modname)s' % battle)
			self._root.clients[user].Send('BATTLEOPENED %(id)s %(type)s %(natType)s %(host)s %(ip)s %(port)s %(maxplayers)s %(passworded)s %(rank)s %(maphash)s %(map)s\t%(title)s\t%(modname)s' % ubattle)
		self._root.battles[battle_id] = battle
		#self._root.battles[str(battle_id)] = {'type':type, 'natType':natType, 'password':password, 'port':port, 'maxplayers':maxplayers, 'hashcode':hashcode, 'rank':rank, 'maphash':maphash, 'engine':engine, 'version':version, 'map':map, 'title':title, 'modname':modname, 'passworded':passworded, 'users':{client.username:''}, 'host':client.username, 'startrects':{}, 'disabled_units':{}, 'bots':{}, 'script_tags':{}, 'replay_script':{}, 'replay':False, 'sending_replay_script':False, 'locked':False}
		client.Send('OPENBATTLE %s'%battle_id)
		client.Send('REQUESTBATTLESTATUS')

	def in_SAYBATTLE(self, client, msg):
		if not msg: return
		if client.current_battle:
			battle_id = client.current_battle
			if not battle_id in self._root.battles: return
			user = client.username
			msg = self.SayHooks.hook_SAYBATTLE(self,client,battle_id,msg)
			if not msg: return
			self._root.broadcast_battle('SAIDBATTLE %s %s' % (user,msg),battle_id)

	def in_SAYBATTLEEX(self, client, msg):
		if client.current_battle in self._root.battles:
			self._root.broadcast_battle('SAIDBATTLEEX %s %s' % (client.username,msg),client.current_battle)

	def in_JOINBATTLE(self, client, battle_id, password=None):
		username = client.username
		if client.current_battle in self._root.battles:
			client.Send('JOINBATTLEFAILED You are already in a battle.')
			return
		if battle_id in self._root.battles:
			battle = self._root.battles[battle_id]
			if battle['passworded'] == 1 and not battle['password'] == password:
				client.Send('JOINBATTLEFAILED Incorrect password.')
				return
			if battle['locked'] == '1':
				client.Send('JOINBATTLEFAILED Battle is locked.')
				return
			if not username in battle['users']:
				if username in client.battle_bans:
					client.Send('JOINBATTLEFAILED <%s> has banned you from his/her battles.'%battle['host'])
					return
				battle_users = self._root.battles[battle_id]['users']
				battle_bots = self._root.battles[battle_id]['bots']
				startrects = self._root.battles[battle_id]['startrects']
				client.Send('JOINBATTLE %s %s'%(battle_id, battle['hashcode']))
				self._root.battles[battle_id]['users'][username] = ''
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
				for user in battle_users:
					battlestatus = self._calc_battlestatus(self._root.usernames[user])
					teamcolor = self._root.usernames[user].teamcolor
					if battlestatus and teamcolor:
						client.Send('CLIENTBATTLESTATUS %s %s %s'%(user, battlestatus, teamcolor))
				for iter in battle_bots:
					bot = battle_bots[iter]
					client.Send('ADDBOT %s %s'(battle_id,iter)+' %(owner)s %(battlestatus)s %(teamcolor)s %(AIDLL)s'%(bot))
					#client.Send('ADDBOT %s %s %s %s %s %s'%(battle_id, iter, bot['owner'], bot['battlestatus'], bot['teamcolor'], bot['AIDLL']))
				for allyno in startrects:
					rect = self._root.battles[battle_id]['startrects'][allyno]
					client.Send('ADDSTARTRECT %s'%(allyno)+' %(left)s %(top)s %(right)s %(bottom)s'%(rect))
					#client.Send('ADDSTARTRECT %s %s %s %s %s'%(allyno, rect['left'], rect['top'], rect['right'], rect['bottom']))
				
				client.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
				client.teamcolor = '0'
				client.current_battle = battle_id
				client.Send('REQUESTBATTLESTATUS')
				return
		client.Send('JOINBATTLEFAILED Unable to join battle.')

	def in_SETSCRIPTTAGS(self, client, scripttags): # need to add checking if the client is in a battle and the host
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
	
	def in_SCRIPTSTART(self, client):
		battle_id = client.current_battle
		if battle_id:
			if self._root.battles[battle_id]['host'] == client.username:
				self._root.battles[battle_id]['replay_script'] = []
				if self._root.battles[battle_id]['sending_replay_script']:
					client.Send('SERVERMSG You have issues. Talk to your lobby dev.')
					self._root.battles[battle_id]['sending_replay_script'] = False
				else:
					self._root.battles[battle_id]['sending_replay_script'] = True
	
	def in_SCRIPT(self, client, scriptline):
		battle_id = client.current_battle
		if battle_id:
			if self._root.battles[battle_id]['host'] == client.username:
				if self._root.battles[battle_id]['sending_replay_script']:
					self._root.battles[battle_id]['replay_script'].append('%s\n'%scriptline)

	def in_SCRIPTEND(self, client):
		battle_id = client.current_battle
		if battle_id:
			if self._root.battles[battle_id]['host'] == client.username:
				if self._root.battles[battle_id]['sending_replay_script']:
					self._root.battles[battle_id]['replay'] = True
					self._root.battles[battle_id]['sending_replay_script'] = False

	def in_LEAVEBATTLE(self, client):
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
					if bot in self._root.battles[battle_id]['bots']:
						del self._root.battles[battle_id]['bots'][bot]
						self._root.broadcast_battle('REMOVEBOT %s'%bot, battle_id)
				self._root.broadcast('LEFTBATTLE %s %s'%(battle_id, client.username))
		client.current_battle = None

	def in_MYBATTLESTATUS(self, client, battlestatus, myteamcolor):
		try:
			if int(battlestatus) < 1:
				battlestatus = str(int(battlestatus) + 2147483648)
		except:
			client.Send('SERVERMSG MYBATTLESTATUS failed - invalid status (%s).'%battlestatus)
			return
		if not myteamcolor.isdigit():
			client.Send('SERVERMSG MYBATTLESTATUS failed - invalid teamcolor (%s).'%myteamcolor)
			return
		if client.current_battle in self._root.battles:
			if client.battlestatus['mode'] == '1': spectator = True
			else: spectator = False
			u, u, u, u, side1, side2, side3, side4, sync1, sync2, u, u, u, u, handicap1, handicap2, handicap3, handicap4, handicap5, handicap6, handicap7, mode, ally1, ally2, ally3, ally4, id1, id2, id3, id4, ready, u = self._dec2bin(battlestatus, 32)[-32:]
			if len(self._root.battles[client.current_battle]['users']) > self._root.battles[client.current_battle]['maxplayers'] and spectator and not mode == '0':
				mode = '0'
			client.battlestatus.update({'ready':ready, 'id':id1+id2+id3+id4, 'ally':ally1+ally2+ally3+ally4, 'mode':mode, 'sync':sync1+sync2, 'side':side1+side2+side3+side4})
			client.teamcolor = myteamcolor
			self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(client.username, self._calc_battlestatus(client), myteamcolor), client.current_battle)

	def in_UPDATEBATTLEINFO(self, client, SpectatorCount, locked, maphash, mapname):
		battle_id = client.current_battle
		if battle_id:
			if self._root.battles[battle_id]['host'] == client.username:
				updated = {'id':battle_id, 'spectators':SpectatorCount, 'locked':locked, 'maphash':maphash, 'mapname':mapname}
				old = self._root.battles[battle_id]
				self._root.battles[battle_id].update(updated)
				# if old == self._root.battles[battle_id]: return # nothing changed # apparently broken
				self._root.broadcast('UPDATEBATTLEINFO %(id)s %(spectators)s %(locked)s %(maphash)s %(mapname)s'%updated, battle_id)

	def in_MYSTATUS(self, client, status):
		if not status.isdigit():
			client.Send('SERVERMSG MYSTATUS failed - invalid status.')
			return
		was_ingame = client.is_ingame
		client.status = self._calc_status(client, status)
		if client.is_ingame and not was_ingame:
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
		elif was_ingame and not client.is_ingame and client.went_ingame:
			ingame_time = (time.time() - client.went_ingame) / 60
			if ingame_time >= 1:
				client.ingame_time += int(ingame_time)
		if not client.username in self._root.usernames: return
		self._root.broadcast('CLIENTSTATUS %s %s'%(client.username, client.status))

	def in_CHANNELS(self, client):
		for channel in self._root.channels:
			if not self._root.channels[channel]['owner'] or self._root.channels[channel]['key']: return # only list unlocked registered channels
			chaninfo = '%s %s'%(channel, len(self._root.channels[channel]['users']))
			topic = self._root.channels[channel]['topic']
			if topic:
				chaninfo = '%s %s'%(chaninfo, topic['text'])
			client.Send('CHANNEL %s'%chaninfo)
		client.Send('ENDOFCHANNELS')

	def in_CHANNELTOPIC(self, client, channel, topic):
		if channel in self._root.channels:
			if client.username in self._root.channels[channel]['users']:
				if topic == '*':
					self._root.broadcast('CHANNELMESSAGE %s Topic disabled.'%channel, channel)
					topicdict = {}
				else:
					self._root.broadcast('CHANNELMESSAGE %s Topic changed.'%channel, channel)
					topicdict = {'user':client.username, 'text':topic, 'time':'%s'%(int(time.time())*1000)}
				self._root.channels[channel]['topic'] = topicdict
				self._root.broadcast('CHANNELTOPIC %s %s %s %s'%(channel, client.username, topicdict['time'], topic), channel)

	def in_CHANNELMESSAGE(self, client, channel, message):
		if channel in self._root.channels:
			self._root.broadcast('CHANNELMESSAGE %s %s'%(channel, message), channel)

	def in_FORCELEAVECHANNEL(self, client, channel, username, reason=''):
		if channel in self._root.channels:
			if username in self._root.channels[channel]['users']:
				self._root.usernames[username].Send('FORCELEAVECHANNEL %s %s %s'%(channel,client.username,reason))
				self._root.channels[channel]['users'].remove(username)
				self._root.broadcast('CHANNELMESSAGE %s %s kicked from channel by <%s>.'%(channel,username,client.username),channel)
				self._root.broadcast('LEFT %s %s kicked from channel.'%(channel,username),channel)

	def in_RING(self, client, username):
		if username in self._root.usernames:
			self._root.usernames[username].Send('RING %s'%(client.username))

	def in_ADDSTARTRECT(self, client, allyno, left, top, right, bottom):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if self._root.battles[battle_id]['host'] == client.username:
				rect = {'left':left, 'top':top, 'right':right, 'bottom':bottom}
				self._root.battles[battle_id]['startrects'][allyno] = rect
				self._root.broadcast_battle('ADDSTARTRECT %s'%(allyno)+' %(left)s %(top)s %(right)s %(bottom)s'%(rect), client.current_battle)

	def in_REMOVESTARTRECT(self, client, allyno):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if self._root.battles[battle_id]['host'] == client.username:
				del self._root.battles[battle_id]['startrects'][allyno]
				self._root.broadcast_battle('REMOVESTARTRECT %s'%allyno,client.current_battle)

	def in_DISABLEUNITS(self, client, units):
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

	def in_ENABLEUNITS(self, client, units):
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

	def in_ENABLEALLUNITS(self, client):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				self._root.battles[battle_id]['disabled_units'] = {}
				self._root.broadcast_battle('ENABLEALLUNITS', battle_id, client.username)

	def in_HANDICAP(self, client, username, value):
		battle_id = client.current_battle
		if battle_id in self._root.battles and value in str(range(0,101)).strip('[]').split(', '):
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					client.battlestatus['handicap'] = self._dec2bin(value, 7)
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), battle_id)

	def in_KICKFROMBATTLE(self, client, username):
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

	def in_FORCETEAMNO(self, client, username, teamno):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					client.battlestatus['id'] = self._dec2bin(teamno, 4)
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), battle_id)

	def in_FORCEALLYNO(self, client, username, allyno):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					client.battlestatus['ally'] = self._dec2bin(allyno, 4)
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), battle_id)

	def in_FORCETEAMCOLOR(self, client, username, teamcolor):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					client.teamcolor = teamcolor
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), battle_id)

	def in_FORCESPECTATORMODE(self, client, username):
		battle_id = client.current_battle
		if battle_id in self._root.battles:
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					client.battlestatus['mode'] = '0'
					self._root.broadcast_battle('CLIENTBATTLESTATUS %s %s %s'%(username, self._calc_battlestatus(client), client.teamcolor), battle_id)

	def in_ADDBOT(self, client, name, battlestatus, teamcolor, AIDLL): #need to add bot removal on user removal
		if client.current_battle in self._root.battles:
			battle_id = client.current_battle
			if not name in self._root.battles[battle_id]['bots']:
				client.battle_bots[name] = battle_id
				self._root.battles[battle_id]['bots'][name] = {'owner':client.username, 'battlestatus':battlestatus, 'teamcolor':teamcolor, 'AIDLL':AIDLL}
				self._root.broadcast_battle('ADDBOT %s %s %s %s %s %s'%(battle_id, name, client.username, battlestatus, teamcolor, AIDLL), battle_id)

	def in_UPDATEBOT(self, client, name, battlestatus, teamcolor):
		if client.current_battle in self._root.battles:
			battle_id = client.current_battle
			if name in self._root.battles[battle_id]['bots']:
				if client.username == self._root.battles[battle_id]['bots'][name]['owner'] or client.username == self._root.battles[battle_id]['host']:
					self._root.battles[battle_id]['bots'][name].update({'battlestatus':battlestatus, 'teamcolor':teamcolor})
					self._root.broadcast_battle('UPDATEBOT %s %s %s %s'%(battle_id, name, battlestatus, teamcolor), battle_id)
	
	def in_REMOVEBOT(self, client, name):
		if client.current_battle in self._root.battles:
			battle_id = client.current_battle
			if name in self._root.battles[battle_id]['bots']:
				if client.username == self._root.battles[battle_id]['bots'][name]['owner'] or client.username == self._root.battles[battle_id]['host']:
					del self._root.usernames[self._root.battles[battle_id]['bots'][name]['owner']].battle_bots[name]
					del self._root.battles[battle_id]['bots'][name]
				self._root.broadcast_battle('REMOVEBOT %s %s'%(battle_id, name), battle_id)
	
	def in_FORCECLOSEBATTLE(self, client, battle_id=None):
		if not battle_id: battle_id = client.current_battle
		if not battle_id in self._root.battles:
			client.Send('SERVERMSG Invalid battle ID.')
			return
		self.in_KICKFROMBATTLE(client, self._root.battles[battle_id])
	
	def in_GETINGAMETIME(self, client, username=None):
		if username and 'mod' in client.accesslevels:
			if username in self._root.usernames: # change to do SQL query if user is not logged in # maybe abstract in the datahandler to automatically query SQL for users not logged in.
				ingame_time = int(self._root.usernames[username].ingame_time)
				client.Send('SERVERMSG %s has an in-game time of %d minutes (%d hours).'%(username, ingame_time, ingame_time / 60))
		else:
			ingame_time = int(client.ingame_time)
			client.Send('SERVERMSG Your in-game time is %d minutes (%d hours).'%(ingame_time, ingame_time / 60))
	
	def in_GETREGISTRATIONDATE(self, client, username=None):
		if username and 'mod' in client.accesslevels:
			if username in self._root.usernames:
				reason = self._root.usernames[username].register_date
				good = True
			else: good, reason = self.userdb.get_registration_date(username)
		else:
			good = True
			username = client.username
			reason = client.register_date
		if good: client.Send('SERVERMSG <%s> registered on %s.' % (username, time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(reason))))
		else: client.Send('SERVERMSG Database returned error when retrieving registration date for <%s> (%s)' % (username, reason))
	
	def in_RENAMEACCOUNT(self, client, newname):
		client.Send('SERVERMSG Renames are currently disabled.')
		return
		user = client.username
		if user == newname: return
		good, reason = self.userdb.rename_user(user, newname)
		if good:
			client.Remove('renaming')
			client.Send('SERVERMSG Your account has been renamed to <%s>. Reconnect with the new username (you will now be automatically disconnected).' % newname)
		else:
			client.Send('SERVERMSG Failed to rename to <%s>: %s' % (newname, reason))
	
	def in_CHANGEPASSWORD(self, newpassword):
		client.Send('SERVERMSG Changing password is currently disabled.')

	def in_FORGEMSG(self, client, user, msg):
		if user == client.username:
			client.Send(msg)
		else:
			client.Send('SERVERMSG Forging messages to anyone but yourself is disabled.')
	#	if user in self._root.usernames:
	#		self._root.usernames[user].Send(msg)

	def in_FORGEREVERSEMSG(self, client, user, msg):
		client.Send('SERVERMSG Forging messages is disabled.')
	#	if user in self._root.usernames:
	#		self._handle(self._root.usernames[user], msg)

	def in_GETLOBBYVERSION(self, client, user):
		if user in self._root.usernames: # need to concatenate to a function liek user = _find_user(user), if user: do junk else: say there's no user or owait... i can return to way back by catching an exception :D
			if hasattr(self._root.usernames[user], 'lobby_id'):
				client.Send('SERVERMSG <%s> is using %s'%(user, self._root.usernames[user].lobby_id))
	
	def in_GETSENDBUFFERSIZE(self, client, username):
		if username in self._root.usernames:
			client.Send('SERVERMSG <%s> has a sendbuffer size of %s'%(username, len(self._root.usernames[username].sendbuffer)))

	def in_SETINGAMETIME(self, client, user, minutes):
		if user in self._root.usernames:
			self._root.usernames[user].ingame_time = int(minutes)

	def in_SETBOTMODE(self, client, user, mode):
		if user in self._root.usernames:
			bot = (mode.lower() in ('true', 'yes', '1'))
			self._root.usernames[user].bot = bot
			client.Send('SERVERMSG <%s> is now a bot: %s' % bot)
			# TODO - sync with database
	
	def in_BROADCAST(self, client, msg):
		self._root.broadcast('SERVERMSG %s'%msg)
	
	def in_BROADCASTEX(self, client, msg):
		self._root.broadcast('SERVERMSGBOX %s'%msg)
	
	def in_ADMINBROADCAST(self, client, msg):
		self._root.admin_broadcast(msg)

	def in_KICKUSER(self, client, user, reason=''):
		if reason.startswith('quiet'):
			reason = reason.split('quiet')[1].lstrip()
			quiet = True
		else: quiet = False
		if user in self._root.usernames:
			kickeduser = self._root.usernames[user]
			if reason: reason = ' (reason: %s)' % reason
			if not quiet:
				for chan in list(kickeduser.channels):
					self._root.broadcast('CHANNELMESSAGE %s <%s> kicked <%s> from the server%s'%(chan, client.username, user, reason),chan)
			client.Send('SERVERMSG You\'ve kicked <%s> from the server.' % user)
			kickeduser.SendNow('SERVERMSG You\'ve been kicked from server by <%s>%s' % (client.username, reason))
			kickeduser.Remove('Kicked from server')
	
	def in_KILLALL(self, client):
		client.Remove('Idiot')
	
	def in_TESTLOGIN(self, client, username, password):
		good, reason = self.userdb.login_user(username, password, client.ip_address)
		if good:
			client.Send('TESTLOGINACCEPT')
		else:
			client.Send('TESTLOGINDENY')

	def in_EXIT(self, client, reason=('Exiting')):
		if reason: reason = 'Quit: %s' % reason
		else: reason = 'Quit'
		client.Remove(reason)

	def in_PYTHON(self, client, code):
		'Execute Python code.'
		code = code.replace('\\n', '\n').replace('\\t','\t')
		try:
			exec code
		except:
			self._root.error(traceback.format_exc())

	def in_MOD(self, client, user):
		changeuser = self._root.usernames[user]
		changeuser.access = 'mod'
		changeuser.accesslevels = ['mod', 'user']
		self._calc_access(changeuser)
		self._root.broadcast('CLIENTSTATUS %s %s'%(user,changeuser.status))

	def in_ADMIN(self, client, user):
		changeuser = self._root.usernames[user]
		changeuser.access = 'admin'
		changeuser.accesslevels = ['admin', 'mod', 'user']
		self._calc_access(changeuser)
		self._root.broadcast('CLIENTSTATUS %s %s'%(user,changeuser.status))

	def in_DEBUG(self, client, enabled=None):
		if enabled == 'on':	client.debug = True
		elif enabled == 'off': client.debug = False
		else: client.debug = not client.debug
		
	def in_RELOAD(self, client, user):
		'Reloads Protocol, SayHooks, Telnet, UserHandler, and ChanServ'
		self._root.reload()

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
	f = open('protocol.txt', 'w')
	f.write('\n'.join(make_docs()))
	f.close()