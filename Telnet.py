out_filter = {'SERVERMSG':'Message from server:', 'LOGININFOEND':'Login finished.', 'MOTD':'Server description:', 'DENIED':'Denied:'}
out_replace = {'ACCEPTED':'Login accepted.'}
out_ignore = ['ADDUSER', 'CLIENTSTATUS']

in_filter = {'/j':'JOIN', '/join':'JOIN', '/part':'/LEAVE', '/quit':'EXIT', '/q':'EXIT', '/me':'SAYEX', '/r':'RAW', '/t':'TELNET'}
in_allowed = ['LOGIN', 'HASH']

def cmd(msg):
	args = ''
	if msg.count(' ') > 0:
		command,args = msg.split(' ',1)
	else:
		command = msg
	return command, args

def rmsg(command, args):
	return ('%s %s'%(command, args)).rstrip(' ')

def filter_in(client, msg):
	while '\b' in msg:
		ix = msg.find('\b')
		if ix>0:
			msg = msg[:ix-1]+msg[ix+1:]
		else:
			msg = msg[1:]
	command, args = cmd(msg)
	if command in in_filter:
		command = in_filter[command]
	elif client.current_channel:
		if not args: args = command
		else: args = '%s %s'%(command, args)
		command = 'SAY'
	elif not command.upper() in in_allowed: return ''
	if command in ['SAY', 'SAYEX'] and client.current_channel:
		args = '%s %s'%(client.current_channel, args)
	if command == 'JOIN':
		response = []
		if client.current_channel: response+=['LEAVE %s'%client.current_channel]
		return response+['JOIN %s'%args]
	if command == 'RAW':
		return args
	#print 'in: %s'%msg
	return rmsg(command, args)

def filter_out(client, msg):
	msg = msg.replace('\b', '')
	command, args = cmd(msg)
	#command = command.upper()
	if command in out_ignore:
		return ''
	if command in out_replace:
		args = ''
		command = out_replace[command]
	if command in out_filter:
		command = out_filter[command]
	if command == 'JOIN':
		client.current_channel = args
		return 'Now talking in #%s'%args
	if command == 'CLIENTS':
		return 'Clients: %s'%', '.join(args.split(' ')[1:])
	if command == 'JOINED':
		return '%s has joined #%s'%(args.split(' ')[1], client.current_channel)
	if command == 'LEFT':
		return '%s has left #%s'%(args.split(' ')[1], client.current_channel)
	if command == 'SAID':
		chan, user, msg = args.split(' ',2)
		if user == client.username: return
		return '| <%s> %s'%(user, msg)
	if command == 'SAIDEX':
		chan, user, msg = args.split(' ',2)
		if user == client.username: return
		return '|  * %s %s'%(user, msg)
	if command == 'CHANNELMESSAGE':
		command = 'Channel message:'
		args = args.split(' ',1)[1]
	if command == 'CHANNELTOPIC':
		command = 'Topic is:'
		chan, set_by, time, topic = args.split(' ',4)
		args = "'%s' by <%s>"%(topic, set_by)
	#print 'out: %s'%msg
	return rmsg(command, args)
