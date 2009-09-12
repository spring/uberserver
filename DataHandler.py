import thread, time, sys, os
import base64
try: from hashlib import md5
except: md5 = __import__('md5').new
import traceback
import time

separator = '-'*60

class DataHandler:
	def __init__(self):
		self.local_ip = None
		self.online_ip = None
		self.session_id = 0
		self.clienthandlers = []
		self.console_buffer = []
		self.port = 8200
		self.natport = self.port+1
		self.LAN = False
		self.lanadmin = {'username':'', 'password':''}
		self.latestspringversion = '*'
		self.log = False
		self.server = 'TASServer'
		self.server_version = 0.35
		self.engine = None
		self.max_threads = 25
		self.sqlurl = 'sqlite:///sqlite.txt'
		self.randomflags = False
		self.nextbattle = 0
		self.SayHooks = __import__('SayHooks')
		self.UsersHandler = None
		self.censor = True
		self.motd = None
		
		self.start_time = time.time()
		self.channels = {}
		self.chan_alias = {}
		self.usernames = {}
		self.clients = {}
		self.db_ids = {}
		self.battles = {}
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
				print '      { Users do not need to be registered to login - breaks rudimentary features like channel ops/founders, channel/battle bans, etc. }'
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
							m = md5(argp[1])
							argp[1] = base64.b64encode(m.digest())
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
				self.engine = sqlalchemy.create_engine(self.sqlurl, pool_size=self.max_threads*2, pool_recycle=300) # hopefully no thread will open more than two sql connections :/
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
		if self.LAN: print 'Warning: LAN mode enabled - many user-specific features will be broken.'
		if os.path.isfile('motd.txt'):
			motd = []
			f = open('motd.txt', 'r')
			data = f.read()
			f.close()
			if data:
				for line in data.split('\n'):
					motd.append(line.strip())
			self.motd = motd
		if not self.log:
			try:
				self.output = open('server.log', 'a')
				self.log = True
			except: pass
	
	def clientFromID(self, db_id):
		if db_id in self.db_ids: return self.db_ids[db_id]
	
	def clientFromUsername(self, username):
		if username in self.usernames: return self.usernames[username]

	def mute_timer(self):
		while True:
			try:
				now = time.time()
				channels = dict(self.channels)
				for chan in channels:
					channel = channels[chan]
					mutelist = dict(channel.mutelist)
					for user in mutelist:
						expiretime = mutelist[user]['expires']
						if 0 < expiretime and expiretime < now:
							del channel.mutelist[user]
							self.broadcast('CHANNELMESSAGE %s <%s> has been unmuted (mute expired).'%(chan, user))
				time.sleep(1)
			except:
				self.error(traceback.format_exc())
				time.sleep(5)

	def error(self, error):
		error = '%s\n%s\n%s'%(separator,error,separator)
		self.console_write(error)
		for user in dict(self.usernames):
			try:
				if self.usernames[user].debug:
					for line in error.split('\n'):
						if line:
							self.usernames[user].Send('SERVERMSG %s'%line)
			except KeyError: pass # the user was removed

	def console_write(self, lines=''):
		if type(lines) == str or type(lines) == unicode:
			lines = lines.split('\n')
		elif not type(lines) == list:
			try: lines = lines.__repr__()
			except: lines = ['Failed to print lines of type %s'%type(lines)]
		self.console_buffer += lines

	def console_loop(self):
		try:
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
		except: print traceback.format_exc()
		
	def broadcast(self, msg, chan=None, ignore=[]):
		try:
			if type(ignore) == str:# or type(ignore) == unicode:
				ignore = [ignore]
			if chan in self.channels:
				channel = self.channels[chan]
				if len(channel.users) > 0:
					users = list(channel.users)
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
		except: self.error(traceback.format_exc())

	def broadcast_battle(self, msg, battle_id, ignore=[]):
		if type(ignore) == str:# or type(ignore) == unicode:
			ignore = [ignore]
		if battle_id in self.battles:
			battle = self.battles[battle_id]
			users = list(battle.users)
			for user in users:
				try:
					self.usernames[user].Send(msg)
				except KeyError: pass # user was removed

	def admin_broadcast(self, msg):
		for user in dict(self.usernames):
			client = self.usernames[user]
			if 'admin' in client.accesslevels:
				client.Send('SERVERMSG Admin broadcast: %s'%msg)

	def _rebind_slow(self):
		for handler in self.clienthandlers:
			handler._rebind()
			
		for channel in dict(self.channels): # hack, but I guess reloading is all a hack :P
			chan = self.channels[channel].copy()
			del chan['chan'] # 'cause we're passing it ourselves
			self.channels[channel] = sys.modules['Protocol'].Channel(self, channel, **chan)

	def reload(self):
		self.admin_broadcast('Reloading...')
		self.console_write('Reloading...')
		reload(sys.modules['SayHooks'])
		reload(sys.modules['Protocol'])
		reload(sys.modules['ChanServ'])
		reload(sys.modules['Client'])
		if 'SQLUsers' in sys.modules: reload(sys.modules['SQLUsers'])
		self.SayHooks = __import__('SayHooks')
		thread.start_new_thread(self._rebind_slow, ()) # why should reloading block the thread? :)
		if os.path.isfile('motd.txt'):
			motd = []
			f = open('motd.txt', 'r')
			data = f.read()
			f.close()
			if data:
				for line in data.split('\n'):
					motd.append(line.strip())
			self.motd = motd
		self.admin_broadcast('Done reloading.')
		self.console_write('Done reloading.')