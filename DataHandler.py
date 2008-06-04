import thread, time
import md5, binascii, base64

separator = '-'*60

class DataHandler:
	def __init__(self):
		self.local_ip = None
		self.online_ip = None
		self.LAN = False
		self.channels = {}
		self.chan_alias = {}
		self.usernames = {}
		self.clients = {}
		self.battles = {}
		self.mapgrades = {}
		self.nextbattle = 0
		self.clienthandlers = []
		self.console_buffer = []
		self.lanadmin = {'username':'', 'password':''}
		self.latestspringversion = '*'
		thread.start_new_thread(self.mute_timer,())
		thread.start_new_thread(self.console_loop,())
		#self.output = open('output.log', 'a')
	
	def parseArgv(self, argv):
		'parses command-line options'
		args = {'ignoreme':[]}
		mainarg = 'ignoreme'
		for arg in argv:
			if arg.startswith('-'):
				mainarg = arg.lstrip('-').lower()
				args[mainarg] = []
			else:
				args[mainarg].append(arg)
		del args['ignoreme']
		
		for arg in args:
			argp = args[arg]
			if arg in ['h', 'help']:
				print 'Usage: server.py [OPTIONS]...'
				print 'Starts uberserver.'
				print
				print 'Options:'
				print '  -h, --help'
				print '      { Displays this screen then exits }'
				print '  -p, --port number'
				print '      { Server will host on this port (default is 8200) }'
				print '  -n, --natport number'
				print '      { Server will use this port for NAT transversal (default is 8201) }'
				print '  -l, --lan'
				print '      { Users do not need to be registered to login }'
				print '  -a, --lanadmin username password [hash] }'
				print '      { Hardcoded admin account for LAN. If third arg reads "hash" it will apply the standard hash algorithm to the supplied password }'
				print '  -g, --loadargs filename'
				print '      { Reads command-line arguments from file }'
				print '  -v, --latestspringversion version'
				print '      { Sets latest Spring version to this string. Defaults to "*" }'
				print '  -s, --sqlurl SQLURL'
				print '      { Uses SQL database at the url specified }'
				print
				print 'SQLURL Examples:'
				print '  "sqlite:///:memory:" or "sqlite:///"'
				print '     { both make a temporary database in memory }'
				print '  "sqlite:////absolute/path/to/database.txt"'
				print '     { uses a database in the file specified }'
				print '  "sqlite:///relative/path/to/database.txt"'
				print '     { note sqlite is slower than a real SQL server }'
				print '  "mysql://user:password@server:port/database"'
				print '     { requires the MySQLdb module }'
				print '  "oracle://user:password@server:port/database"'
				print '     { requires the cx_Oracle module }'
				print '  "postgres://user:password@server:port/database"'
				print '     { requires the psycopg2 module }'
				print '  "mssql://user:password@server:port/database"'
				print '     { requires pyodbc (recommended) or adodbapi or pymssql }'
				print '  "firebird://user:password@server:port/database"'
				print '     { requires the kinterbasdb module }'
				print
				print 'Usage example (this is what the test server uses at the moment):'
				print ' server.py -p 8300 -n 8301 -s sqlite:///:memory:'
				print
				exit()
			if arg in ['p', 'port']:
				try: self.port = int(argp[0])
				except: print 'Invalid port specification'
			if arg in ['n', 'natport']:
				try: self.natport = int(argp[0])
				except: print 'Invalid NAT port specification'
			if arg in ['l', 'lan']:
				self.LAN = True
			if arg in ['a', 'lanadmin']:
				try:
					if len(argp) > 2:
						if argp[2] == 'hash':							
							m = md5.new()
							m.update(argp[1])
							argp[1] = base64.b64encode(binascii.a2b_hex(m.hexdigest()))
					self.lanadmin = {'username':argp[0], 'password':argp[1]}
				except: print 'Invalid LAN admin specified'
			if arg in ['g', 'loadargs']:
				try:
					f = file(argp[0], 'r')
					data = file.read().split('\n')
					f.close()
					for line in data: self.parseArgv(line)
				except: print 'Error opening file with command-line args'
			if arg in ['v', 'latestspringversion']:
				try: self.latestspringversion = ' '.join(argp)
				except: print 'Error specifying latest spring version'
	def mute_timer(self):
		while 1:
			now = time.time()
			channels = dict(self.channels)
			for channel in channels:
				mutelist = dict(channels[channel]['mutelist'])
				for user in mutelist:
					expiretime = mutelist[user]
					if 0 <= expiretime and expiretime < now:
						del self.channels[channel]['mutelist'][user]
						self.broadcast('CHANNELMESSAGE %s <%s> has been unmuted (mute expired).'%(channel, user))
			time.sleep(1)

	def error(self, error):
		error = '%s\n%s\n%s'%(separator,error,separator)
		self.console_write(error)
		if 'aegis' in self.usernames: self.usernames['aegis'].Send('SERVERMSG %s'%error)
		elif '[tN]aegis' in self.usernames: self.usernames['[tN]aegis'].Send('SERVERMSG %s'%error)

	def console_write(self, lines):
		if type(lines) == str:
			lines = lines.split('\n')
		elif not type(lines) == list:
			lines = ['Failed to print lines of type %s'%type(lines)]
		self.console_buffer += lines

	def console_loop(self):
		while True:
			if self.console_buffer:
				line = self.console_buffer.pop(0)
				print line
				#output.write(line)
			else:
				time.sleep(0.1)
		
	def broadcast(self, msg, chan=None, ignore=[]):
		if type(ignore) == str:
			ignore = [ignore]
		if chan in self.channels:
			if 'users' in self.channels[chan]:
				if len(self.channels[chan]['users']) > 0:
					users = list(self.channels[chan]['users'])
					for user in users:
						if user in self.usernames and not user in ignore:
							try:
								self.usernames[user].Send(msg)
							except KeyError: pass # user was removed
		else:
			users = dict(self.usernames)
			for user in users:
				if not user in ignore:
					try:
						self.usernames[user].Send(msg)
					except KeyError: pass # user was removed

	def broadcast_battle(self, msg, battle_id, ignore=[]):
		if type(ignore) == str:
			ignore = [ignore]
		if battle_id in self.battles:
			if 'users' in self.battles[battle_id]:
				users = dict(self.battles[battle_id]['users'])
				for user in users:
					if user in self.battles[battle_id]['users'] and not user in ignore:
						try:
							self.usernames[user].Send(msg)
						except KeyError: pass # user was removed

	def admin_broadcast(self, msg):
		for client in dict(self.usernames):
			client = self.clients[client]
			if 'admin' in client.accesslevels:
				client.Send('SERVERMSG Admin broadcast: %s'%msg)
