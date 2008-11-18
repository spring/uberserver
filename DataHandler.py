import thread, time, sys
import md5, binascii, base64
import traceback

from MutexDict import MutexDict

separator = '-'*60

class DataHandler:

	local_ip = None
	online_ip = None
	session_id = 0
	clienthandlers = []
	console_buffer = []
	port = 8200
	natport = port+1
	LAN = False
	lanadmin = {'username':'', 'password':''}
	latestspringversion = '*'
	log = False
	server = 'TASServer'
	server_version = 0.35
	engine = None
	max_threads = 25
	sqlurl = 'sqlite:///sqlite.txt'
	randomflags = False
	nextbattle = 0
	SayHooks = __import__('SayHooks')
	UsersHandler = None
	censor = True
	
	def __init__(self):
		self.channels = MutexDict()
		self.chan_alias = MutexDict()
		self.usernames = MutexDict()
		self.clients = MutexDict()
		self.battles = MutexDict()
		#self.mapgrades = MutexDict()
		thread.start_new_thread(self.mute_timer,()) # maybe make into a single thread
		thread.start_new_thread(self.console_loop,())
	
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
				print '  -r  --randomflags'
				print '      { Randomizes country codes (flags) }'
				print '  -o, --output /path/to/file.log'
				print '      { Writes console output to file (for logging) }'
				print '  -v, --latestspringversion version'
				print '      { Sets latest Spring version to this string. Defaults to "*" }'
				print '  -m, --maxthreads number'
				print '      { Uses the specified number of threads for handling clients }'
				print '  -s, --sqlurl SQLURL'
				print '      { Uses SQL database at the url specified }'
				print '  -c, --no-censor'
				print '      { Disables censoring of #main, #newbies, and usernames (default is to censor) }'
				print
				print 'SQLURL Examples:'
				#print '  "sqlite:///:memory:" or "sqlite:///"'
				#print '     { both make a temporary database in memory }'
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
			if arg in ['r', 'randomcc']:
				try: self.randomflags = True
				except: print 'Error enabling random flags. (weird)'
			if arg in ['o', 'output']:
				try:
					self.output = file(argp[0], 'w')
					print 'Logging enabled at: %s' % argp[0]
					self.log = True
				except: print 'Error specifying log location'
			if arg in ['v', 'latestspringversion']:
				try: self.latestspringversion = argp[0] # ' '.join(argp) # shouldn't have spaces
				except: print 'Error specifying latest spring version'
			if arg in ['m', 'maxthreads']:
				try: self.max_threads = int(argp[0])
				except: print 'Error specifing max threads'
			if arg in ['s', 'sqlurl']:
				try: self.sqlurl = argp[0]
				except: print 'Error specifying SQL URL'
			if arg in ['c', 'no-censor']:
				self.censor = False
				
		if self.sqlurl == 'sqlite:///:memory:' or self.sqlurl == 'sqlite:///':
			print 'In-memory sqlite databases are not supported.'
			print 'Falling back to LAN mode.'
			print
			self.LAN = True
		if not self.LAN:
			try:
				sqlalchemy = __import__('sqlalchemy')
				self.engine = sqlalchemy.create_engine(self.sqlurl)
				if self.sqlurl.startswith('sqlite'):
					print 'Multiple threads are not supported with sqlite, forcing a single thread'
					print 'Please note the server performance will not be optimal'
					print 'You might want to install a real database server or use LAN mode'
					print
					self.max_threads = 1
			except ImportError:
				print 'sqlalchemy not found or invalid SQL URL, reverting to LAN mode'
				self.LAN = True
		if self.LAN or not self.engine:
				self.UsersHandler = __import__('LANUsers').UsersHandler # maybe make an import request to datahandler, then have it reload it too. less hardcoded-ness
		else:
			try:
				self.UsersHandler = __import__('SQLUsers').UsersHandler
				testhandler = self.UsersHandler(self, self.engine)
			except:
				self.LAN = True
				print traceback.format_exc()
				print 'Error importing SQL - reverting to LAN'
				self.UsersHandler = __import__('LANUsers').UsersHandler

	def mute_timer(self):
		while 1:
			try:
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
			except:
				self.error(traceback.format_exc())

	def error(self, error):
		error = '%s\n%s\n%s'%(separator,error,separator)
		self.console_write(error)
		for user in self.usernames:
			if self.usernames[user].debug:
				for line in error.split('\n'):
					if line: self.usernames[user].Send('SERVERMSG %s'%line)

	def console_write(self, lines=''):
		if type(lines) == str or type(lines) == unicode:
			lines = lines.split('\n')
		elif not type(lines) == list:
			try: lines = lines.__repr__()
			except: lines = ['Failed to print lines of type %s'%type(lines)]
		self.console_buffer += lines

	def console_loop(self):
		while True:
			try:
				if self.console_buffer:
					line = self.console_buffer.pop(0)
					print line
					if self.log:
						self.output.write(line+'\n')
						self.output.flush()
				else:
					time.sleep(0.1)
			except:
				print '-'*60
				print traceback.format_exc()
				print '-'*60
		
	def broadcast(self, msg, chan=None, ignore=[]):
		if type(ignore) == str:# or type(ignore) == unicode:
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
		if type(ignore) == str:# or type(ignore) == unicode:
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

	def reload(self):
		reload(sys.modules['SayHooks'])
		reload(sys.modules['Protocol'])
		reload(sys.modules['ChanServ'])
		self.SayHooks = __import__('SayHooks')
		for handler in self.clienthandlers:
			handler._rebind()
