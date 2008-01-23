import inspect
import time

class Protocol:

	def __init__(self,root,handler):
		self._root = root
		self.handler = handler

        def _new(self,client):
		client.Send('TASServer 0.35 * 8201 1')

	def _remove(self,client):
		if client.username:
                        if not client.username in self._root.usernames:
                                return
			if not client.session_id == self._root.usernames[client.username]:
				return
			user = client.username
			del self._root.usernames[user]
			for chan in list(client.channels):
				client.channels.remove(chan)
				if user in self._root.channels[chan]['users']:
					del self._root.channels[chan]['users'][user]
				self._root.broadcast('LEFT %s %s Quit'%(chan, user), chan, user)
			if client.current_battle:
                                battle_id = client.current_battle
                                if battle_id in self._root.battles:
                                        if self._root.battles[battle_id]['host'] == user:
                                                self._root.broadcast('BATTLECLOSED %s'%battle_id)
                                                del self._root.battles[battle_id]
                                        else:
                                                del self._root.battles[battle_id]['users'][user]
                                                bots = dict(client.battle_bots)
                                                for bot in bots:
                                                        del client.battle_bots[bot]
                                                        del self._root.battles[battle_id]['bots'][bot]
                                                        self._root.broadcast_battle('REMOVEBOT %s %s'%(battle_id, bot), battle_id)
                                                self._root.broadcast('LEFTBATTLE %s %s'%(battle_id, user))
			self._root.broadcast('REMOVEUSER %s'%user)
			pass

	def _handle(self,client,msg):
                if msg.startswith('#'):
                        test = msg.split(' ')[0][1:]
                        if test.isdigit():
                                msg_id = '#%s '%test
                                msg = ' '.join(msg.split(' ')[1:])
                else:
                        msg_id = ''
                client.msg_id = msg_id # just setting the message id on the client works unless...hmmmmm - make check for broadcast
		numspaces = msg.count(' ')
		if numspaces:
			command,args = msg.split(' ',1)
		else:
			command = msg
		command = 'incoming_%s' % command.upper()
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
			client.Send('SERVERMSG %s failed. Incorrect arguments.'%command.partition('incoming_')[2])
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

	def _calc_status(self, client, status):
		status = self._dec2bin(status, 7)
		bot, access, rank1, rank2, rank3, away, ingame = status[0:7]
		rank1, rank2, rank3 = self._dec2bin(6, 3)
		access = 0
		bot = 0
		status = self._bin2dec('%s%s%s%s%s%s%s'%(bot, access, rank1, rank2, rank3, away, ingame))
		return status

	def _calc_battlestatus(self, client):
		battlestatus = client.battlestatus
		status = self._bin2dec('0000%s%s0000%s%s%s%s%s0'%(battlestatus['side'], battlestatus['sync'], battlestatus['handicap'], battlestatus['mode'], battlestatus['ally'], battlestatus['id'], battlestatus['ready']))
		return status

	def incoming_PING(self,client,args=None):
		if args:
			client.Send('PONG %s'%args)
		else:
			client.Send('PONG')

	def incoming_LOGIN(self, client, username, password, cpu, local_ip, sentence_args):
		if '\t' in sentence_args:
			lobby_id, user_id = sentence_args.split('\t',1)
		else:
			lobby_id = sentence_args
		if not username in self._root.usernames:
			client.username = username
			client.password = password
			client.cpu = cpu
			client.local_ip = local_ip
			client.lobby_id = lobby_id
			client.channels = []
			client.battle_bots = {}
			client.current_battle = None
			client.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
			client.Send('ACCEPTED %s'%username)
			client.Send('MOTD Hey there.')
			usernames = dict(self._root.usernames)
			for user in usernames:
                                addclient = self._root.clients[self._root.usernames[user]]
				client.Send('ADDUSER %s %s %s'%(user,addclient.country_code,addclient.cpu))
			self._root.broadcast('ADDUSER %s %s %s'%(username,client.country_code,cpu))
			battles = dict(self._root.battles)
			for battle in battles:
				battle_id = battle
				battle = self._root.battles[battle]
				type, natType, host, port, maxplayers, passworded, rank, maphash, map, title, modname = [battle['type'], battle['natType'], battle['host'], battle['port'], battle['maxplayers'], battle['passworded'], battle['rank'], battle['maphash'], battle['map'], battle['title'], battle['modname']]
				ip_address = self._root.clients[self._root.usernames[host]].ip_address
				ip_address = self._root.clients[self._root.usernames[host]].local_ip
				if client.ip_address == ip_address:
					translated_ip = local_ip
				else:
					translated_ip = ip_address
				client.Send('BATTLEOPENED %s %s %s %s %s %s %s %s %s %s %s\t%s\t%s' %(battle_id, type, natType, host, translated_ip, port, maxplayers, passworded, rank, maphash, map, title, modname))
			usernames = dict(self._root.usernames)
			for user in usernames:
				#client.Send('CLIENTSTATUS %s %s'%(user,self._calc_status(self._root.clients[self._root.usernames[user]],0)))
                                client.Send('CLIENTSTATUS %s %s'%(user,self._root.clients[self._root.usernames[user]].status))
			self._root.usernames[username] = client.session_id
			client.Send('LOGININFOEND')
			client.status = self._calc_status(client, 0)
			self._root.broadcast('CLIENTSTATUS %s %s'%(username,client.status))
			#client.Send('CLIENTSTATUS %s %s'%(username,client.status))
		else:
			client.Send('DENIED Already logged in.')

	def incoming_SAY(self,client,chan,msg):
                user  = client.username
                if user in self._root.channels[chan]['users']:
                        if self._root.channels[chan]['users'][user]['muted'] == False: # should place mute in self._root.channels[chan]['mutelist'][user] = time
                                self._root.broadcast('SAID %s %s %s' % (chan,client.username,msg),chan)
                        else:
                                client.Send('CHANNELMESSAGE %s You are muted.'%chan) # mute needs to be in the channel object, not the user (user can unmute by leaving and returning atm)

	def incoming_SAYEX(self,client,chan,msg):
		self._root.broadcast('SAIDEX %s %s %s' % (chan,client.username,msg),chan)

	def incoming_SAYPRIVATE(self,client,user,msg):
		if user in self._root.usernames:
			client.Send('SAYPRIVATE %s %s'%(user,msg))
			self._root.clients[self._root.usernames[user]].Send('SAIDPRIVATE %s %s'%(client.username,msg))

	def incoming_MUTE(self,client,chan,user,duration=None):
                if user in self._root.channels[chan]['users']:
                        self._root.channels[chan]['users'][user]['muted'] = True

       	def incoming_UNMUTE(self,client,chan,user):
                if user in self._root.channels[chan]['users']:
                        self._root.channels[chan]['users'][user]['muted'] = False

	def incoming_JOIN(self,client,chan,key=None):
		user = client.username
		if not chan in self._root.channels:
			self._root.channels[chan] = {'users':{}}
                if 'topic' in self._root.channels[chan]: # putting this outside of the check means a user can fake rejoin a channel to get the topic
                        topic = self._root.channels[chan]['topic']
                        client.Send('CHANNELTOPIC %s %s %s %s'%(chan, topic['user'], topic['time'], topic['text']))
		if not user in self._root.channels[chan]['users']:
                        if not chan in client.channels:
                                client.channels.append(chan)
                        client.Send('JOIN %s'%chan)
			self._root.broadcast('JOINED %s %s'%(chan,user),chan)
			self._root.channels[chan]['users'][user] = {'muted':False,'operator':False,'founder':False}
			users = dict(self._root.channels[chan]['users'])
			for user in users:
				client.Send('CLIENTS %s %s'%(chan,user))

	def incoming_LEAVE(self,client,chan):
		user = client.username
		if chan in self._root.channels:
                        if chan in client.channels:
                                client.channels.remove(chan)
                        if user in self._root.channels[chan]['users']:
				del self._root.channels[chan]['users'][user]
                                self._root.broadcast('LEFT %s %s'%(chan, user), chan, user)

        def incoming_OPENBATTLE(self, client, type, natType, password, port, maxplayers, hashcode, rank, maphash, sentence_args):
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
			if self._root.clients[user].ip_address == client.ip_address:
				translated_ip = client.local_ip
			else:
				translated_ip = client.ip_address
			self._root.clients[user].Send('BATTLEOPENED %s %s %s %s %s %s %s %s %s %s %s\t%s\t%s' %(battle_id, type, natType, client.username, translated_ip, port, maxplayers, passworded, rank, maphash, map, title, modname))
		self._root.battles[str(battle_id)] = {'type':type, 'natType':natType, 'password':password, 'port':port, 'maxplayers':maxplayers, 'hashcode':hashcode, 'rank':rank, 'maphash':maphash, 'map':map, 'title':title, 'modname':modname, 'passworded':passworded, 'users':{client.username:''}, 'host':client.username, 'startrects':{}, 'disabled_units':{}, 'bots':{}, 'script_tags':{}}
		client.Send('OPENBATTLE %s'%battle_id)
		client.Send('REQUESTBATTLESTATUS')

	def incoming_SAYBATTLE(self, client, msg):
		if not client.current_battle == None:
				self._root.broadcast_battle('SAIDBATTLE %s %s' % (client.username,msg),client.current_battle)

	def incoming_SAYBATTLEEX(self, client, msg):
		if not client.current_battle == None:
				self._root.broadcast_battle('SAIDBATTLEEX %s %s' % (client.username,msg),client.current_battle)

	def incoming_JOINBATTLE(self, client, battle_id):
		if battle_id in self._root.battles:
			if not client.username in self._root.battles[battle_id]['users']:
				battle = self._root.battles[battle_id]
				client.Send('JOINBATTLE %s %s'%(battle_id, battle['hashcode']))
				scripttags = []
				battle_script_tags = battle['script_tags']
				for tag in battle_script_tags:
                                        scripttags.append('%s=%s'%(tag, battle_script_tags[tag]))
                                client.Send('SETSCRIPTTAGS %s'%'\t'.join(scripttags))
				self._root.broadcast('JOINEDBATTLE %s %s'%(battle_id,client.username))
				battle_users = self._root.battles[battle_id]['users']
				for user in battle_users:
					battlestatus = self._calc_battlestatus(self._root.clients[self._root.usernames[user]])
					teamcolor = self._root.clients[self._root.usernames[user]].teamcolor
					if battlestatus and teamcolor:
						client.Send('CLIENTBATTLESTATUS %s %s %s'%(user, battlestatus, teamcolor))
				battle_bots = self._root.battles[battle_id]['bots']
				for iter in battle_bots:
                                        bot = battle_bots[iter]
                                        client.Send('ADDBOT %s %s %s %s %s %s'%(battle_id, iter, bot['owner'], bot['battlestatus'], bot['teamcolor'], bot['AIDLL']))
				client.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
				client.teamcolor = '0'
				client.current_battle = battle_id
				self._root.battles[battle_id]['users'][client.username] = ''
				client.Send('REQUESTBATTLESTATUS')

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

	def incoming_LEAVEBATTLE(self, client):
		if not client.current_battle == None:
			battle_id = client.current_battle
			if self._root.battles[battle_id]['host'] == client.username:
				self._root.broadcast('BATTLECLOSED %s'%battle_id)
				del self._root.battles[battle_id]
			elif client.username in self._root.battles[battle_id]['users']:
				del self._root.battles[battle_id]['users'][client.username]
				for bot in client.battle_bots:
					del client.battle_bots[bot]
					del self._root.battles[battle_id]['bots'][bot]
					self._root.broadcast_battle('REMOVEBOT %s'%bot, battle_id)
				self._root.broadcast('LEFTBATTLE %s %s'%(battle_id, client.username))
			client.current_battle = None

	def incoming_MYBATTLESTATUS(self, client, battlestatus, myteamcolor):
		if client.current_battle in self._root.battles:
			und1, und2, und3, und4, side1, side2, side3, side4, sync1, sync2, und5, und6, und7, und8, handicap1, handicap2, handicap3, handicap4, handicap5, handicap6, handicap7, mode, ally1, ally2, ally3, ally4, id1, id2, id3, id4, ready, und9 = self._dec2bin(battlestatus, 32)[0:37]
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
		client.status = self._calc_status(client, status)
		self._root.broadcast('CLIENTSTATUS %s %s'%(client.username, client.status))

	def incoming_CHANNELS(self, client):
		for channel in self._root.channels:
			chaninfo = '%s %s'%(channel, len(self._root.channels[channel]['users']))
			if 'topic' in self._root.channels[channel]:
				chaninfo = '%s %s '%(chaninfo, self._root.channels[channel]['topic'])
			client.Send('CHANNEL %s'%chaninfo)
		client.Send('ENDOFCHANNELS')

	def incoming_CHANNELTOPIC(self, client, channel, topic):
		if channel in self._root.channels:
                        if user in self._root.channels[chan]['users']:
                                topicdict = {'user':client.username, 'text':topic, 'time':'%s'%(int(time.time())*1000)}
                                self._root.channels[channel]['topic'] = topicdict
                                self._root.broadcast('CHANNELTOPIC %s %s %s %s'%(channel, client.username, topicdict['time'], topic), channel)

	def incoming_CHANNELMESSAGE(self, client, channel, message):
		if channel in self._root.channels:
			self._root.broadcast('CHANNELMESSAGE %s %s'%(channel, message), channel)

	def incoming_FORCELEAVECHANNEL(self, client, channel, username, reason=''):
		if channel in self._root.channels:
			if username in self._root.channels[channel]['users']:
				self._root.clients[self._root.usernames[username]].Send('FORCELEAVECHANNEL %s %s %s'%(channel,client.username,reason))
				del self._root.channels[channel]['users'][username]
				self._root.broadcast('LEFT %s %s kicked from channel'%(channel,username),channel)

	def incoming_MUTELIST(self, client, channame):
		if channel in self._root.channels:
			if 'mutelist' in self._root.channels[channel]:
				mutelist = self._root.channels[channel]['mutelist']
				client.Send('MUTELISTBEGIN')
				for mute in mutelist:
					client.Send('MUTELIST %s'%mute)
				client.Send('MUTELISTEND')

	def incoming_RING(self, client, username):
		if username in self._root.usernames:
			self._root.clients[self._root.usernames[username]].Send('RING %s'%(client.username))

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
			if client.username == self._root.battles[battle_id]['host']:
				if username in self._root.battles[battle_id]['users']:
					client = self._root.usernames[username]
					self._root.clients[client].Send('FORCEQUITBATTLE')
					self._root.broadcast('LEFTBATTLE %s %s'%(battle_id, username),None, username)
					if username == self._root.battles[battle_id]['host']:
						self._root.broadcast('BATTLECLOSED %s'%battle_id)

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
                if client.current_battle:
                        battle_id = client.current_battle
                        if not name in self._root.battles[battle_id]['bots']:
                                client.battle_bots[name] = battle_id
                                self._root.battles[battle_id]['bots'][name] = {'owner':client.username, 'battlestatus':battlestatus, 'teamcolor':teamcolor, 'AIDLL':AIDLL}
                                self._root.broadcast_battle('ADDBOT %s %s %s %s %s %s'%(battle_id, name, client.username, battlestatus, teamcolor, AIDLL), battle_id)

	def incoming_UPDATEBOT(self, client, name, battlestatus, teamcolor):
                if client.current_battle:
                        battle_id = client.current_battle
                        if name in self._root.battles[battle_id]['bots']:
                                if client.username == self._root.battles[battle_id]['bots'][name]['owner'] or client.username == self._root.battles[battle_id]['host']:
                                        self._root.battles[battle_id]['bots'][name].update({'battlestatus':battlestatus, 'teamcolor':teamcolor})
                                        self._root.broadcast_battle('UPDATEBOT %s %s %s %s'%(battle_id, name, battlestatus, teamcolor), battle_id)
	
	def incoming_REMOVEBOT(self, client, name):
                if client.current_battle:
                        battle_id = client.current_battle
                        if name in self._root.battles[battle_id]['bots']:
                                if client.username == self._root.battles[battle_id]['bots'][name]['owner'] or client.username == self._root.battles[battle_id]['host']:
                                        del self._root.usernames[self._root.battles[battle_id]['bots'][name]['owner']].battle_bots[name]
                                        del self._root.battles[battle_id]['bots'][name]
                        		self._root.broadcast_battle('REMOVEBOT %s %s'%(battle_id, name), battle_id)

	def incoming_EXIT(self, client):
		self._remove(client)

class Protocol_034(Protocol):

	def __init__(self,root):
		self._root = root
		if hasattr(self, 'incoming_SETSCRIPTTAGS'):
			del Protocol.incoming_SETSCRIPTTAGS
        
        def _init(self,client):
  		client.Send('TASServer 0.34 * 8201')

  	def incoming_OPENBATTLE(self, client, type, natType, password, port, maxplayers, startingmetal, startingenergy, maxunits, startpos, gameendcondition, limitdgun, diminishingMMs, ghostedBuildings, hashcode, rank, maphash, sentence_args):
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
			if self._root.clients[user].ip_address == client.ip_address:
				translated_ip = client.local_ip
			else:
				translated_ip = client.ip_address
			self._root.clients[user].Send('BATTLEOPENED %s %s %s %s %s %s %s %s %s %s %s\t%s\t%s' %(battle_id, type, natType, client.username, translated_ip, port, maxplayers, passworded, rank, maphash, map, title, modname))
		self._root.battles[str(battle_id)] = {'type':type, 'natType':natType, 'password':password, 'port':port, 'maxplayers':maxplayers, 'startingmetal':startingmetal, 'startingenergy':startingenergy, 'maxunits':maxunits, 'startpos':startpos, 'gameendcondition':gameendcondition, 'limitdgun':limitdgun, 'diminishingMMs':diminishingMMs, 'ghostedBuildings':ghostedBuildings, 'hashcode':hashcode, 'rank':rank, 'maphash':maphash, 'map':map, 'title':title, 'modname':modname, 'passworded':passworded, 'users':{client.username:''}, 'host':client.username, 'startrects':{}, 'disabled_units':{}}
		client.Send('OPENBATTLE %s'%battle_id)
		client.Send('REQUESTBATTLESTATUS')

	def incoming_JOINBATTLE(self, client, battle_id):
		if battle_id in self._root.battles:
			if not client.username in self._root.battles[battle_id]['users']:
				battle = self._root.battles[battle_id]
				client.Send('JOINBATTLE %s %s %s %s %s %s %s %s %s %s'%(battle_id, battle['startingmetal'], battle['startingenergy'], battle['maxunits'], battle['startpos'], battle['gameendcondition'], battle['limitdgun'], battle['diminishingMMs'], battle['ghostedBuildings'], battle['hashcode']))
				self._root.broadcast('JOINEDBATTLE %s %s'%(battle_id,client.username))
				battle_users = self._root.battles[battle_id]['users']
				for user in battle_users:
					battlestatus = self._calc_battlestatus(self._root.clients[self._root.usernames[user]])
					teamcolor = self._root.clients[self._root.usernames[user]].teamcolor
					if battlestatus and teamcolor:
						client.Send('CLIENTBATTLESTATUS %s %s %s'%(user, battlestatus, teamcolor))
				battle_bots = self._root.battles[battle_id]['bots']
				for bot in battle_bots:
                                        client.Send('ADDBOT %s %s %s %s %s %s'%(bot[battle_id], bot[name], bot[owner], bot[battlestatus], bot[teamcolor], bot[AIDLL]))
				client.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
				client.teamcolor = '0'
				client.current_battle = battle_id
				client.Send('REQUESTBATTLESTATUS')

        def incoming_UPDATEBATTLEDETAILS(self, client, startingmetal, startingenergy, maxunits, startpos, gameendcondition, limitdgun, diminishingMMs, ghostedBuildings):
		if not client.current_battle == None:
			if self._root.battles[client.current_battle]['host'] == client.username:
				updated = {'startingmetal':startingmetal, 'startingenergy':startingenergy, 'maxunits':maxunits, 'startpos':startpos, 'gameendcondition':gameendcondition, 'limitdgun':limitdgun, 'diminishingMMs':diminishingMMs, 'ghostedBuildings':ghostedBuildings}
				self._root.battles[client.current_battle].update(updated)
				self._root.broadcast_battle('UPDATEBATTLEDETAILS %s %s %s %s %s %s %s %s'%(updated['startingmetal'], updated['startingenergy'], updated['maxunits'], updated['startpos'], updated['gameendcondition'], updated['limitdgun'], updated['diminishingMMs'], updated['ghostedBuildings']),client.current_battle)

	
