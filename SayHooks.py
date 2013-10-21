import inspect, sys, os, types, time, string

_permissionlist = ['admin', 'adminchan', 'mod', 'modchan', 'chanowner', 'chanadmin', 'chanpublic', 'public', 'battlehost', 'battlepublic']
_permissiondocs = {
					'admin':'Admin Commands', 
					'adminchan':'Admin Commands (channel)', 
					'mod':'Moderator Commands', 
					'modchan':'Moderator Commands (channel)', 
					'chanowner':'Channel Owner Commands (channel)', 
					'chanadmin':'Channel Admin Commands (channel)', 
					'chanpublic':'Public Commands (channel)', 
					'public':'Public Commands', 
					'battlepublic':'Public Commands (battle)', 
					'battlehost':'Battle Host Commands', 
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
	try:
		f = open('bad_words.txt', 'r')
		for line in f.readlines():
			if line.count(' ') < 1:
				bad_word_dict[line.strip()] = '***'
			else:
				sline = line.strip().split(' ', 1)
				bad_word_dict[sline[0]] = ' '.join(sline[1:])
		f.close()
	except:
		print 'Error parsing profanity list. It might not exist. Try running fetch_deps.py'
	try:
		f = open('bad_sites.txt', 'r')
		for line in f.readlines():
			line = line.strip()
			if line and not line in bad_site_list: bad_site_list.append(line)
		f.close()
	except:
		print 'Error parsing shock site list. It might not exist. Try running fetch_deps.py'
				
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

def _nasty_word_censor(msg):
	msg = msg.lower()
	for word in bad_word_dict.keys():
		if word.lower() in msg: return False
	return True

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
	for letter in msg:
		if not letter: continue
		if letter.isalnum():
			testmsg1 += letter
			testmsg2 += letter
		elif letter in './%':
			testmsg2 += letter
	for site in bad_site_list:
		if site in msg or site in testmsg1 or site in testmsg2:
			return # 'I think I can post shock sites, but I am wrong.'
	return msg

def _spam_enum(client, chan):
	now = time.time()
	bonus = 0
	already = []
	times = [now]
	for when in dict(client.lastsaid[chan]):
		t = float(when)
		if t > now-5: # check the last five seconds # can check a longer period of time if old bonus decay is included, good for 2-3 second spam, which is still spam.
			for message in client.lastsaid[chan][when]:
				times.append(t)
				if message in already:
					bonus += 2 * already.count(message) # repeated message
				if len(message) > 50:
					bonus += min(len(message), 200) * 0.01 # long message: 0-2 bonus points based linearly on length 0-200
				bonus += 1 # something was said
				already.append(message)
		else: del client.lastsaid[chan][when]
	
	times.sort()
	last_time = None
	for t in times:
		if last_time:
			diff = t - last_time
			if diff < 1:
				bonus += (1 - diff) * 1.5
		last_time = t
	
	if bonus > 7: return True
	else: return False

def _spam_rec(client, chan, msg):
	now = str(time.time())
	if not chan in client.lastsaid: client.lastsaid[chan] = {}
	if not now in client.lastsaid[chan]:
		client.lastsaid[chan][now] = [msg]
	else:
		client.lastsaid[chan][now].append(msg)

def _chan_msg_filter(self, client, chan, msg):
	username = client.username
	channel = self._root.channels[chan]
	
	if channel.isMuted(client): return msg # client is muted, no use doing anything else
	if channel.antispam and not channel.isOp(client): # don't apply antispam to ops
		_spam_rec(client, chan, msg)
		if _spam_enum(client, chan):
			channel.muteUser(self._root.chanserv, client, 15, ip=True, quiet=True)
			# this next line is necessary, because users aren't always muted i.e. you can't mute channel founders or moderators
			if channel.isMuted(client):
				channel.channelMessage('%s was muted for spamming.' % username)
				#if quiet: # maybe make quiet a channel-wide setting, so mute/kick/op/etc would be silent
				#	client.Send('CHANNELMESAGE %s You were quietly muted for spamming.'%chan)
				return ''
			
	if channel.censor:
		msg = _word_censor(msg)
	if channel.antishock:
		msg = _site_censor(msg)
	return msg

def hook_SAY(self, client, chan, msg):
	user = client.username
	channel = self._root.channels[chan]
	if client.hook and msg.startswith(client.hook):
		access = []
		
		if 'admin' in client.accesslevels: admin = True
		else: admin = False
		if 'mod' in client.accesslevels: mod = True
		else: mod = False
		
		if channel.isAdmin(client):
			access.append('admin')
			access.append('adminchan')
		if channel.isMod(client):
			access.append('mod')
			access.append('modchan')
		if channel.isFounder(client):
			access.append('chanowner')
		if channel.isOp(client):
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
	return _site_censor(msg)

def hook_SAYBATTLE(self, client, battle_id, msg):
	return msg # no way to respond in battles atm
	user = client.username
	if client.hook and msg.startswith(client.hook):
		access = []

		if 'admin' in client.accesslevels: admin = True
		else: admin = False
		if 'mod' in client.accesslevels: mod = True
		else: mod = False

		access.append('battlepublic')

		if self._root.battles[battle_id].host == user:
			access.append('battlehost')

		good, reason = _do(client, battle_id, user, msg[len(client.hook):], access)
	else: return msg

def __find_command(rights, command):
	function, exists = None, False
	for right in rights:
		function = '%s_%s' %(right, command)
		try:
			exec "exists = type(%s) == types.FunctionType" % function
			exists = True
			break
		except:
			exists = False
	return function, exists

def _do(client, chan, user, msg, rights):
	# number of words
	numspaces = msg.count(' ')
	args = ''
	if numspaces:
		command, args = msg.split(' ', 1)
	else:
		command = msg
	command = command.lower()
	
	function, exists = __find_command(rights, command)
	if not exists:
		return False, 'no such command!'
	exec 'function_info = inspect.getargspec(%s)' % function
	total_args = len(function_info[0])-4
	# if there are no arguments, just call the function

	if not total_args:
		exec '%s(client, user, chan, rights)' % function
		return True, ''
	# check for optional arguments

	optional_args = 0
	if function_info[3]:
		optional_args = len(function_info[3])

	# check if we've got enough words for filling the required args
	required_args = total_args - optional_args
	# print numspaces, '--', required_args

	if numspaces < required_args:
		good, usage, description = _help(command, rights)
		_reply(client, chan, 'invalid usage: %s'%usage)
		return False, ''#, 'invalid usage: '+usage
	# bunch the last words together if there are too many of them

	if numspaces > total_args:
		arguments = args.split(' ', total_args-1)
	else:
		arguments = args.split(' ')
	exec '%s(*([client, user, chan, rights]+arguments))' % function
	return True, ''

def _help(funcname, rights):
	function, exists = __find_command(rights, funcname)
	if not exists:
		return False, '', ''
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
	for i in range(0, len(required_args)):
		if required_args[i] == 'state': required_args[i] = 'on|off'
		required_args[i] = '<'+required_args[i]+'>'
	for i in range(0, len(optional_args)):
		if optional_args[i] == 'state': optional_args[i] = 'on|off'
		optional_args[i] = '['+optional_args[i]+']'
	usage += ' '.join(required_args) +' '+ ' '.join(optional_args)
	exec 'description = %s.__doc__' % function
	if not description:
		description = 'No further description'
	return True, usage, description

def _reply(self, chan, msg):
	for msg in msg.split('\n'):
		self.Send('CHANNELMESSAGE %s %s'%(chan, msg))

def _replyb(self, msg):
	for msg in msg.split('\n'):
		self.Send('SAIDBATTLEEX %s %s'%(self.username, msg))

def public_rights(self, user, chan, rights):
	'lists your rights levels'
	_reply(self, chan, 'Your access levels are: %s.'%(', '.join(rights)))

def public_raw(self, user, chan, rights, msg):
	'send a raw message to the server'
	self._protocol._handle(self, msg)

def public_help(self, user, chan, rights, command=None):
	'show command-specific help'
	if not command:
		public_commands(self, user, chan, rights)
		return
	exists, usage, description = _help(command, rights)
	if not exists:
		_reply(self, chan, "No such command (%s)"%command)
	else:
		_reply(self, chan, ":::Help on %s:::"%command)
		_reply(self, chan, "Usage: "+usage)
		_reply(self, chan, "Description: "+description)
		if usage.count(' ') > 1: # has arguments
			_reply(self, chan, 'Note:')
			_reply(self, chan, '"<arg>" means the argument is required')
			_reply(self, chan, '"[arg]" means the argument is optional')

def public_commands(self, user, chan, rights):
	'shows all commands available to you'
	l = filter(lambda x:not x.startswith('_'), globals())
	_reply(self, chan, 'Available commands for level %s:'%rights[0])
	helparray = {}
	for command in l:
		exec 'isfunc = type(%s) == types.FunctionType' % command
		if isfunc:
			level, command = command.split('_', 1)
			if not level in rights: continue
			try:
				exists, usage, description = _help(command, [level])
				if exists:
					try:
						helparray[level].append('    - %s (%s)'%(command, description))
					except KeyError:
						helparray[level] = ['    - %s (%s)'%(command, description)]
			except KeyError:
				pass
	for level in _permissionlist:
		if level in helparray:
			_reply(self, chan, '* %s'%_permissiondocs[level])
			for command in helparray[level]:
				_reply(self, chan, command)

def chanpublic_info(self, user, chan, rights):
	'shows general information about a channel'
	channel = self._root.channels[chan]
	
	ops = []
	for admin in list(channel.admins):
		client = self._protocol.clientFromID(admin)
		if client: ops.append(client.username)
		
	owner = self._protocol.clientFromID(channel.owner)
	
	if owner:
		owner = 'Owner is <%s>, ' % owner.username
	else:
		owner = 'No owner is registered, '
	if ops:
		owner += '%i registered operators are <%s>'%(len(ops), '> <'.join(ops))
	else: owner += 'no operators are registered.'
	spam = 'off'
	if channel.censor: censor = 'on'
	else: censor = 'off'
	if channel.antishock: antishock = 'on'
	else: antishock = 'off'
	_reply(self, chan, '#%s info: Protection status: (spam: %s, shock sites: %s, language: %s). %s'%(chan, spam, antishock, censor, owner))

def chanowner_antishock(self, user, chan, rights, state=''):
	'turn shock site filtering on/off'
	channel = self._root.channels[chan]
	if state.lower() == 'on': channel.antishock = True
	elif state.lower() == 'off': channel.antishock = False
	if channel.antishock: state = 'enabled'
	else: state = 'disabled'
	_reply(self, chan, 'Shock site censoring is %s.' % state)

def chanowner_censor(self, user, chan, rights, state=''):
	'turn language censoring on/off'
	channel = self._root.channels[chan]
	if state.lower() == 'on': channel.censor = True
	elif state.lower() == 'off': channel.censor = False
	if channel.censor: state = 'enabled'
	else: state = 'disabled'
	_reply(self, chan, 'Language censoring is %s.' % state)

def chanowner_allowmode(self, user, chan, rights, allowmode):
	'set the allow mode to allow or ban for whitelist or blacklist'
	chan = self._root.channels[chan]
	allowmode = allowmode.lower()
	if allowmode in ('ban', 'allow'):
		chan.autokick = allowmode
	
	_reply(self, chan, 'Allow mode is: %s' % chan.autokick)

def chanowner_op(self, user, chan, rights, users):
	'add user(s) to the channel admin list'
	channel = self._root.channels[chan]
	for username in users.split(' '):
		user = self._protocol.clientFromUsername(username)
		if user:
			channel.opUser(self, user)

def chanowner_deop(self, user, chan, rights, users):
	'removes user(s) from the channel admin list'
	channel = self._root.channels[chan]
	for username in users.split(' '):
		user = self._protocol.clientFromUsername(username)
		if user:
			channel.deopUser(self, user)

def chanowner_register(self, user, chan, rights, owner=None):
	'change the owner of a channel'
	channel = self._root.channels[chan]
	if owner == None: owner = user
	if channel.owner == owner:
		_reply(self, chan, 'Channel #%s already belongs to #%s' % (chan, owner))
		return
	if 'ChanServ' in self._root.usernames: self._root.usernames['ChanServ'].Send('JOIN %s' % chan)
	channel.owner = user
	_reply(self, chan, 'Channel #%s successfully registered to %s' % (chan, user))

def chanowner_unregister(self, user, chan, rights):
	'unregister a channel'
	channel = self._root.channels[chan]
	if not channel.owner:
		_reply(self, chan, 'Channel #%s is not registered' % chan)
		return
	channel.owner = ''
	_reply(self, chan, 'Channel #%s successfully unregistered' % chan)

def chanadmin_topic(self, user, channel, rights, topic):
	'set the channel topic'
	self._root.channels[channel].setTopic(self, topic)

def chanadmin_kick(self, user, chan, rights, username, reason=''):
	'kick a user from the channel'
	channel = self._root.channels[chan]
	target = self._protocol.clientFromUsername(username)
	channel.kickUser(self, target, reason)

def chanadmin_ban(self, user, chan, rights, username, reason=''):
	'ban a user from the channel'
	channel = self._root.channels[chan]
	target = self._protocol.clientFromUsername(username)
	if target:
		channel.banUser(self, target, reason)

def chanadmin_unban(self, user, chan, rights, username):
	'unban a user from the channel'
	channel = self._root.channels[chan]
	target = self._protocol.clientFromUsername(username)
	if target:
		channel.unbanUser(self, target)

def chanadmin_allow(self, user, chan, rights, username):
	'add a user to the channel allow list'
	channel = self._root.channels[chan]
	target = self._protocol.clientFromUsername(username)
	if target:
		channel.allowUser(self, target)

def chanadmin_disallow(self, user, chan, rights, username):
	'remove a user from the channel allow list'
	channel = self._root.channels[chan]
	target = self._protocol.clientFromUsername(username)
	if target:
		channel.disallowUser(self, target)

def chanadmin_chanmsg(self, user, chan, rights, message):
	'send a channel message'
	channel = self._root.channels[chan]
	channel.channelMessage(message)

def modchan_alias(self, user, chan, rights, alias, args=None):
	'add a channel alias. args can be "blind" or "nolock"'
	if args:
		args = args.lower()
		if 'blind' in args: blind = True
		else: blind = False
		if 'nolock' in args: nolock = True
		else: nolock = False
	else: blind = nolock = False
	if alias in self._root.channels and self._root.channels[alias].owner:
		_reply(self, chan, 'Cannot alias #%s to #%s, #%s is a registered channel.'%(alias, chan, alias))
	else:
		self._root.chan_alias[alias] = {'chan':chan, 'blind':blind, 'nolock':nolock}
		_reply(self, chan, 'Successfully aliased #%s to #%s.'%(alias, chan))

def modchan_unalias(self, user, chan, rights, alias):
	'remove a channel alias'
	if alias and alias in self._root.chan_alias:
		del self._root.chan_alias[alias]
		_reply(self, chan, 'Successfully removed alias #%s to #%s.'%(alias, chan))
	else:
		_reply(self, chan, 'No such alias (#%s)'%alias)

def battlehost_ban(self, user, battle_id, rights, username):
	'ban a user from your battles'
	if not username in self.battle_ban:
		self.battle_ban.append(username)
		_replyb(self, 'You have banned <%s> from your battles.'%username)
	else:
		_replyb(self, 'You have already banned <%s> from your battles.'%username)
	if username in self._root.battles[battle_id]['users']:
		self._protool.incoming_KICKFROMBATTLE(self, username)

def battlehost_unban(self, user, battle_id, rights, username):
	'unban a user from your battles'
	if not username in self.battle_ban:
		self.battle_ban.append(username)
		_replyb(self, 'You have unbanned <%s> from your battles.'%username)
	else:
		_replyb(self, '<%s> is already not banned from your battles.'%username)

#def battlehost_autospec(self, user, battle_id, rights, username):

#def battlehost_unautospec(self, user, battle_id, rights, username):

def battlepublic_banlist(self, user, battle_id, rights):
	'view the host banlist'
	battle_id = user.current_battle
	host = self._root.battles[battle_id].host
	bans = ['Battle bans for %s'%host]+self._root.usernames[host].battle_ban
	_replyb(self, bans)

def battlepublic_help(*args, **kwargs):
	'get command-specific help'
	public_help(*args, **kwargs)

def battlepublic_commands(*args, **kwargs):
	'show all commands available to your access level'
	public_commands(*args, **kwargs)

def chanpublic_aliaslist(self, user, chan, rights):
	'show a list of channel aliases'
	_reply(self, chan, 'Channel alias list:')
	for alias in dict(self._root.chan_alias):
		_reply(self, chan, alias)

def chanpublic_banlist(self, user, chan, rights):
	'show the current channel banlist'
	channel = self._root.channels[chan]
	if channel.ban:
		bans = dict(channel.ban)
		_reply(self, chan, '#%s ban list:' % chan)
		for ban in bans:
			try:
				username = self._protocol.clientFromID(ban).username
				_reply(self, chan, '<%s> %s'%(username, bans[ban]))
			except: pass
	else:
		_reply(self, chan, 'No users banned in #%s' % chan)

def chanpublic_allowlist(self, user, chan, rights):
	'show the current channel allow list'
	channel = self._root.channels[chan]
	if channel.allow:
		allows = list(channel.allow)
		_reply(self, chan, '#%s allow list:' % chan)
		for allow in allows:
			_reply(self, chan, '<%s>' % allow)
	else:
		_reply(self, chan, 'No users on the allowlist in #%s' % chan)

def admin_reload(self, user, chan, rights):
	'reload everything'
	self._root.reload()
	_reply(self, chan, 'Everything was reloaded.')
