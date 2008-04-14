import inspect,sys,os,types,time,string

_permissionlist = ['admin','adminchan','mod','modchan','chanowner','chanadmin','chanpublic','public']
_permissiondocs = {
					'admin':'Admin Commands',
					'adminchan':'Admin Commands (channel)',
					'mod':'Moderator Commands',
					'modchan':'Moderator Commands (channel)',
					'chanowner':'Channel Owner Commands (channel)',
					'chanadmin':'Channel Admin Commands (channel)',
					'chanpublic':'Public Commands (channel)',
					'public':'Public Commands',
					}

def _erase():
	l = dict(globals())
	for iter in l:
		if not iter == '_erase':
			del globals()[iter]

global bad_word_dict
global bad_site_list
bad_word_dict = {}
bad_site_list = []

def _update_lists():
	f = open('bad_words.txt', 'r')
	for line in f.readlines():
		if line.count(' ') < 1:
			bad_word_dict[line.strip()] = '***'
		else:
			sline = line.strip().split(' ',1)
			bad_word_dict[sline[0]] = ' '.join(sline[1:])
	f.close()
	f = open('bad_sites.txt', 'r')
	for line in f.readlines():
		line = line.strip()
		if line and not line in bad_site_list: bad_site_list.append(line)
	f.close()

def _clear_lists():
	global bad_word_dict
	global bad_site_list
	bad_word_dict = {}
	bad_site_list = []

_update_lists()

chars = string.ascii_letters + string.digits

def _process_word(word):
	if word == word.upper(): uppercase = True
	else: uppercase = False
	lword = word.lower()
	if lword in bad_word_dict:
		word = bad_word_dict[lword]
	if uppercase: word = word.upper()
	return word

def _word_censor(msg):
	words = []
	word = ''
	letters = True
	for letter in msg:
		if bool(letter in chars) == bool(letters): word += letter
		else:
			letters = not bool(letters)
			words.append(word)
			word = letter
	words.append(word)
	newmsg = []
	for word in words:
		newmsg.append(_process_word(word))
	return ''.join(newmsg)

def _site_censor(msg):
	testmsg1 = ''
	testmsg2 = ''
	testmsg3 = ''
	for letter in msg:
		if not letter: continue
		if letter.isalnum():
			testmsg1 += letter
			testmsg2 += letter
		elif letter in './%':
			testmsg2 += letter
	for site in bad_site_list:
		if site in msg or site in testmsg1 or site in testmsg2:
			return 'I think I can post shock sites, but I am wrong.'
	return msg

def _spam_enum(client, chan, timeout, repeated, unique, bonuslength):
	now = time.time()
	counter = 0
	bonus = False
	already = []
	for when in dict(client.lastsaid[chan]):
		if float(when) > now-timeout:
			message = client.lastsaid[chan][when]
			if message in already: bonus = True
			if len(message) > bonuslength:
				if bonus == True: return True # they just said something really long twice :>
				else: bonus = True
			counter += 1
		else: del client.lastsaid[chan][when]
	if bonus and counter >= repeated or counter >= unique: return True
	else: return False

def _spam_rec(client, chan, msg):
	now = str(time.time())
	if not chan in client.lastsaid: client.lastsaid[chan] = {}
	client.lastsaid[chan][now] = msg

def _chan_msg_filter(self, client, chan, msg):
	username = client.username
	if username in self._root.channels[chan]['mutelist']: return '' # client is muted, no use doing anything else
	antispam = self._root.channels[chan]['antispam']
	if antispam['enabled']:
		_spam_rec(client, chan, msg)
		if _spam_enum(client, chan, antispam['timeout'], antispam['bonus'], antispam['unique'], antispam['bonuslength']):
			self._root.channels[chan]['mutelist'][username] = time.time() + antispam['duration']
			if antispam['quiet']:
				client.Send('CHANNELMESAGE %s You were quietly muted for spamming.'%chan)
			else:
				self._root.broadcast('CHANNELMESSAGE %s %s was muted for spamming.'%(chan, username), chan)
			return ''
	if self._root.channels[chan]['censor']:
		msg = _word_censor(msg)
	if self._root.channels[chan]['antishock']:
		msg = _site_censor(msg)
	return msg

def hook_SAY(self,client,chan,msg):
	user = client.username
	if client.hook and msg.startswith(client.hook):
		access = []
		
		if 'admin' in client.accesslevels: admin = True
		else: admin = False
		if 'mod' in client.accesslevels: mod = True
		else: mod = False
		
		if admin:
			access.append('admin')
			access.append('adminchan')
		if mod:
			access.append('mod')
			access.append('modchan')
		if user == self._root.channels[chan]['owner'] or admin or mod:
			access.append('chanowner')
		if user in self._root.channels[chan]['admins'] or admin or mod:
			access.append('chanadmin')
		access.append('public')
		access.append('chanpublic')
		good, reason = _do(client, chan, user, msg[len(client.hook):], access)
		if not good:
			client.Send('CHANNELMESSAGE %s %s'%(chan, reason))
	else:
		msg = _chan_msg_filter(self, client, chan, msg)
		return msg

def hook_SAYEX(self, client, chan, msg):
	msg = _chan_msg_filter(self, client, chan, msg)
	return msg

def hook_SAYPRIVATE(self, client, target, msg):
	user = client.username
	if client.hook and msg.startswith(client.hook):
		access = []

		if 'admin' in client.accesslevels: admin = True
		else: admin = False
		if 'mod' in client.accesslevels: mod = True
		else: mod = False

		if admin:
			access.append('admin')
		if mod:
			access.append('mod')
		access.append('public')
		good, reason = _do(client, chan, user, msg[len(client.hook):], access)
		if not good:
			client.Send('CHANNELMESSAGE %s %s'%(chan, reason))
	else: return _site_censor(msg)

def _do(client,chan,user,msg,rights):
	#number of words
	numspaces = msg.count(' ')
	args = ''
	if numspaces:
		command,args = msg.split(' ',1)
	else:
		command = msg
	command = command.lower()
	#command = command[1:]
	function,exists = __find_command(rights,command)
	if not exists:
		return False,'no such command!'
	exec 'function_info = inspect.getargspec(%s)' % function
	total_args = len(function_info[0])-4
	#if there are no arguments, just call the function
	if not total_args:
		exec '%s(client,user,chan,rights)' % function
		return True,''
	#check for optional arguments
	optional_args = 0
	if function_info[3]:
		optional_args = len(function_info[3])
	#check if we've got enough words for filling the required args
	required_args = total_args - optional_args
	#print numspaces,'--',required_args
	if numspaces < required_args:
		good, usage, description = _help(command,rights)
		_reply(client,chan,'invalid usage: %s'%usage)
		return False,'invalid usage: '+usage
	#bunch the last words together if there are too many of them
	if numspaces > total_args:
		arguments = args.split(' ',total_args-1)
	else:
		arguments = args.split(' ')
	exec '%s(*([client,user,chan,rights]+arguments))' % function
	return True,''

def __find_command(rights,command):
	function,exists = None,False
	for right in rights:
		function = '%s_%s' %(right,command)
		try:
			exec "exists = type(%s) == types.FunctionType" % function
			exists = True
			break
		except:
			exists = False
	return function,exists

def __find_user(client,user):
	for i in usr.userlist:
		if user.lower() in i.name.lower():
			return i.name
	return 'No such user!'

def _help(funcname,rights):
	function,exists = __find_command(rights,funcname)
	if not exists:
		return False,'',''
	exec 'function_info = inspect.getargspec(%s)' %function
	all_args = function_info[0][4:]
	num_all_args = 0
	if all_args:
		num_all_args = len(all_args)
	num_optional_args = 0
	if function_info[3]:
		num_optional_args = len(function_info[3])
	num_required_args = num_all_args - num_optional_args
	required_args = all_args[:num_required_args]
	optional_args = all_args[num_required_args:]
	usage = '%s '%funcname
	for i in range(0,len(required_args)):
		if required_args[i] == 'state': required_args[i] = 'on|off'
		required_args[i] = '<'+required_args[i]+'>'
	for i in range(0,len(optional_args)):
		if optional_args[i] == 'state': optional_args[i] = 'on|off'
		optional_args[i] = '['+optional_args[i]+']'
	usage += ' '.join(required_args) +' '+ ' '.join(optional_args)
	exec 'description = %s.__doc__' % function
	if not description:
		description = 'No further description'
	return True,usage,description

def _reply(self,chan,msg):
	self.Send('CHANNELMESSAGE %s %s'%(chan,msg))

def public_rights(self,user,chan,rights):
	'lists your rights levels'
	_reply(self,chan,'Your access levels are: %s.'%(', '.join(rights)))

def public_help(self,user,chan,rights,command=None):
	'show command specific help.'
	if not command:
		public_commands(self,user,chan,rights)
		return
	exists,usage,description = _help(command,rights)
	if not exists:
		_reply(self,chan,"No such command (%s)"%command)
	else:
		_reply(self,chan,":::Help on %s:::"%command)
		_reply(self,chan,"Usage: "+usage)
		_reply(self,chan,"Description: "+description)
		if usage.count(' ') > 1: # has arguments
			_reply(self,chan,'Note:')
			_reply(self,chan,'"<arg>" means the argument is required')
			_reply(self,chan,'"[arg]" means the argument is optional')

def public_commands(self,user,chan,rights):
	'shows all commands available to you'
	l = filter(lambda x:not x.startswith('_'),globals())
	_reply(self,chan,'Available commands for level %s:'%rights[0])
	helparray = {}
	for command in l:
		exec 'isfunc = type(%s) == types.FunctionType' % command
		if isfunc:
			level,command = command.split('_',1)
			try:
				exists,usage,description = _help(command,rights)
				if exists:
					try:
						helparray[level].append(' - %s (%s)'%(command, description))
					except KeyError:
						helparray[level] = [' - %s (%s)'%(command, description)]
			except KeyError:
				pass
	for level in _permissionlist:
		if level in helparray:
			_reply(self,chan,'* %s'%_permissiondocs[level])
			for command in helparray[level]:
				_reply(self,chan,command)

def chanpublic_info(self,user,chan,rights):
	ops = self._root.channels[chan]['admins']
	owner = self._root.channels[chan]['owner']
	if owner:
		owner = 'Owner is <%s>, '%self._root.channels[chan]['owner']
	else:
		owner = 'No owner is registered, '
	if ops:
		owner += '%i registered operators are <%s>'%(len(ops),'> <'.join(ops))
	else: owner += 'no operators are registered.'
	spam = 'off'
	if self._root.channels[chan]['censor']: censor = 'on'
	else: censor = 'off'
	if self._root.channels[chan]['antishock']: antishock = 'on'
	else: antishock = 'off'
	_reply(self,chan,'#%s info: Protection status: (spam: %s, shock sites: %s, language: %s). %s'%(chan,spam,antishock,censor,owner))

def chanowner_antishock(self,user,chan,rights,state=''):
	'turn shock site filtering on/off'
	if state.lower() == 'on': self._root.channels[chan]['antishock'] = True
	elif state.lower() == 'off': self._root.channels[chan]['antishock'] = False
	if self._root.channels[chan]['antishock']: state = 'enabled'
	else: state = 'disabled'
	_reply(self,chan,'Shock site censoring is %s.'%state)

def chanowner_censor(self,user,chan,rights,state=''):
	'turn language censoring on/off'
	if state.lower() == 'on': self._root.channels[chan]['censor'] = True
	elif state.lower() == 'off': self._root.channels[chan]['censor'] = False
	if self._root.channels[chan]['censor']: state = 'enabled'
	else: state = 'disabled'
	_reply(self,chan,'Language censoring is %s.'%state)

def chanowner_op(self,user,chan,rights,users):
	'add user(s) to the channel admin list'
	users = users.split(' ')
	for user in users:
		if user and not user in self._root.channels[chan]['admins']:
			self._root.channels[chan]['admins'].append(user)
			_reply(self,chan,'%s added to this channels admin list.')

def chanowner_deop(self,user,chan,rights,users):
	'removes user(s) from the channel admin list'
	users = users.split(' ')
	for user in users:
		if user and user in self._root.channels[chan]['admins']:
			self._root.channels[chan]['admins'].remove(user)
			_reply(self,chan,'%s removed from this channels admin list.')

def chanadmin_topic(self,user,channel,rights,topic):
	if client.username in self._root.channels[channel]['users']:
		topicdict = {'user':client.username, 'text':topic, 'time':'%s'%(int(time.time())*1000)}
		self._root.channels[channel]['topic'] = topicdict
		self._root.broadcast('CHANNELMESSAGE %s Topic changed.'%channel, channel, user)
		_reply(self,chan,'You have successfully changed the topic.')
		self._root.broadcast('CHANNELTOPIC %s %s %s %s'%(channel, client.username, topicdict['time'], topic), channel)

def chanadmin_kick(self,user,channel,rights,username,reason=''):
	if reason: reason = '(%s)'%reason
	users = self._root.channels[channel]['users']
	if username in users:
		self._root.clients[self._root.usernames[username]].Send(('FORCELEAVECHANNEL %s %s %s'%(channel,user,reason)).strip())
		self._root.channels[channel]['users'].remove(username)
		#self._root.broadcast('CHANNELMESSAGE %s %s kicked from channel by <%s>.'%(channel,username,client.username),channel)
		_reply(self,chan,'You have kicked %s from the channel'%username)
		self._root.broadcast('LEFT %s %s kicked from channel by <%s>..'%(channel,username,user),channel)

def chanadmin_chanmsg(self,user,chan,rights,message):
	self._root.broadcast('CHANNELMESSAGE %s %s'%(chan, message), chan)

def modchan_alias(self,user,chan,rights,alias,arg1=None,arg2=None):
	args = (arg1.lower(), arg2.lower())
	if 'blind' in args: blind = True
	else: blind = False
	if 'nokey' in args: nokey = True
	else: nokey = False
	if alias in self._root.channels:
		_reply(self,chan,'Cannot alias #%s to #%s, #%s is a registered channel.'%(alias, chan, alias))
	else:
		self._root.chan_alias[alias] = {'chan':chan, 'blind':blind, 'nolock':nolock}
		_reply(self,chan,'Successfully aliased #%s to #%s.'%(alias, chan))

def modchan_unalias(self,user,chan,rights,alias):
	if alias and alias in self._root.chan_alias:
		del self._root.chan_alias[alias]
		_reply(self,chan,'Successfully removed alias #%s to #%s.'%(alias, chan))
	else:
		_reply(self,chan,'No such alias (#%s)'%alias)

def public_aliaslist(self,user,chan,rights):
	_reply(self,chan,'Channel alias list:')
	for alias in dict(self._root.chan_alias):
		_reply(self,chan,alias)

'''def mod_alias

	def incoming_ALIAS(self, client, alias, chan):
		if not chan in self._root.channels:
			self._root.channels[chan] = self._new_channel(chan)
			self._root.chan_alias[alias] = chan

	def incoming_UNALIAS(self, client, alias):
		if not alias in self._root.chan_alias:
			client.Send('SERVERMSG No existing alias #%s'%alias)
			return
		del self._root.chan_alias[alias]
	
	def incoming_ALIASLIST(self, client):
		aliases = dict(self._root.chan_alias)
		for entry in aliases:
			client.Send('SERVERMSG #%s is aliased to #%s'%(entry, aliases[entry]))'''

def admin_reload(self,user,chan,rights):
	'reload everything'
	for handler in self._root.clienthandlers:
		handler._rebind()
	_reply(self,chan,'Everything was reloaded.')

