import thread, time
import md5, binascii, base64

separator = '-'*60

class DataHandler:
	def __init__(self):
		self.local_ip = None
		self.online_ip = None
#		self.channels = {}
#		self.chan_alias = {}
#		self.usernames = {}
#		self.clients = {}
#		self.battles = {}
#		self.mapgrades = {}
		self.channels = MutexDict()
		self.chan_alias = MutexDict()
		self.usernames = MutexDict()
		self.clients = MutexDict()
		self.battles = MutexDict()
		self.mapgrades = MutexDict()
		self.nextbattle = 1 # if it starts at 0, client.current_battle checks are longer (must check against None instead of pure bool)
		self.session_id = 0
		self.clienthandlers = []
		self.console_buffer = []
		self.port = 8200
		self.natport = self.port+1
		print self.natport
		self.LAN = False
		self.lanadmin = {'username':'', 'password':''}
		self.latestspringversion = '*'
		thread.start_new_thread(self.mute_timer,())
		thread.start_new_thread(self.console_loop,())
		self.log = False
		self.server = 'TASServer'
		self.server_version = 0.35
	
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
				print '  -o, --output /path/to/file.log'
				print '      { Writes console output to file (for logging) }'
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
			if arg in ['o', 'output']:
				try:
					self.output = file(argp[0], 'w')
					print 'logging on'
					self.log = True
				except: print 'Error specifying output log'
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
		if 'aegis' in self.usernames:
			for line in error.split('\n'):
				self.usernames['aegis'].Send('SERVERMSG %s'%line)
		elif '[tN]aegis' in self.usernames:
			for line in error.split('\n'):
				self.usernames['[tN]aegis'].Send('SERVERMSG %s'%line)

	def console_write(self, lines=''):
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
				if self.log:
					self.output.write(line+'\n')
					self.output.flush()
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

import thread
# todo:
# I could probably make it detect a finished iteration and unlock properly
class MutexDict:
	def __init__(self, dict=None, **kwargs):
		self.mutex = thread.allocate_lock()
		self.lock_id = 0
		self.data = {}
		if dict is not None:
			self.update(dict)
		if len(kwargs):
			self.update(kwargs)
	
	def __repr__(self, lock=None):
		lock = self.lock(lock)
		data = repr(self.data)
		self.unlock(lock)
		return data
	
	def __cmp__(self, dict, lock=None):
		lock = self.lock(lock)
		if isinstance(dict, UserDict):
			data = cmp(self.data, dict.data)
		else:
			data = cmp(self.data, dict)
		self.unlock(lock)
		return data
	
	def __len__(self, lock=None):
		lock = self.lock(lock)
		data = len(self.data)
		self.unlock(lock)
		return len
	
	def __getitem__(self, key, lock=None):
		lock = self.lock(lock)
		data = None
		if key in self.data:
			data = self.data[key]
		if hasattr(self.__class__, "__missing__"):
			data = self.__class__.__missing__(self, key)
		self.unlock(lock)
		if data: return data
		raise KeyError(key)
	
	def __setitem__(self, key, item, lock=None):
		lock = self.lock(lock)
		self.data[key] = item
		self.unlock(lock)
	
	def __delitem__(self, key, lock=None):
		lock = self.lock(lock)
		del self.data[key]
		self.unlock(lock)
	
	def clear(self, lock=None):
		lock = self.lock(lock)
		self.data.clear()
		self.unlock(lock)
	
	def copy(self, lock=None):
		lock = self.lock(lock)
		if self.__class__ is UserDict:
			data = self.data.copy()
			self.unlock(lock)
			return UserDict(data)
		import copy
		data = self.data
		try:
			self.data = {}
			c = copy.copy(self)
		finally:
			self.data = data
		c.update(self)
		self.unlock(lock)
		return c
	
	def keys(self, lock=None):
		lock = self.lock(lock)
		data = self.data.keys()
		self.unlock(lock)
		return data
	
	def items(self, lock=None):
		lock = self.lock(lock)
		data = self.data.items()
		self.unlock(lock)
		return data
	
	def iteritems(self, lock=None):
		lock = self.lock(lock)
		data = self.data.iteritems()
		self.unlock(lock)
		return data
	
	def iterkeys(self, lock=None):
		lock = self.lock(lock)
		data = self.data.iterkeys()
		self.unlock(lock)
		return data
	
	def itervalues(self, lock=None):
		lock = self.lock(lock)
		data = self.data.itervalues()
		self.unlock(lock)
		return data
	
	def values(self, lock=None):
		lock = self.lock(lock)
		data = self.data.values()
		self.unlock(lock)
		return data
	
	def has_key(self, key, lock=None):
		lock = self.lock(lock)
		data = self.data.has_key(key)
		self.unlock(lock)
		return data
	
	def update(self, dict=None, lock=None, **kwargs):
		lock = self.lock(lock)
		if dict is None:
			pass
		elif isinstance(dict, UserDict):
			self.data.update(dict.data)
		elif isinstance(dict, type({})) or not hasattr(dict, 'items'):
			self.data.update(dict)
		else:
			for k, v in dict.items():
				self[k] = v
		if len(kwargs):
			self.data.update(kwargs)
		self.unlock(lock)
	
	def get(self, key, failobj=None, lock=None):
		lock = self.lock(lock)
		if not self.has_key(key):
			data = failobj
		else:
			data = self[key]
		self.unlock(lock)
		return data
	
	def setdefault(self, key, failobj=None, lock=None):
		lock = self.lock(lock)
		if not self.has_key(key):
			self[key] = failobj
		data = self[key]
		self.unlock(lock)
		return data
	
	def pop(self, key, lock=None, *args):
		lock = self.lock(lock)
		data = self.data.pop(key, *args)
		self.unlock(lock)
		return data
	
	def popitem(self, lock=None):
		lock = self.lock(lock)
		data = self.data.popitem()
		self.unlock(lock)
		return data
	
	def __contains__(self, key, lock=None):
		lock = self.lock(lock)
		data = key in self.data
		self.unlock(lock)
		return data
	
	def __iter__(self):
		lock = self.lock(lock)
		data = iter(self.data, lock=None)
		self.unlock(lock)
		return data
	
	def lock(self, lock):
		if lock == self.lock_id: return None # won't release lock since it was already locked properly
		self.mutex.acquire()
		self.lock_id += 1
		return self.lock_id
	
	def unlock(self, lock):
		if lock == self.lock_id:
			self.mutex.release()
		elif not lock: return # calling code already locked it, will not release lock
		else: raise Exception('Mutex attempted to unlock without correct key',self)
	
#	@classmethod
#	def fromkeys(cls, iterable, value=None, lock=None):
#		lock = self.lock(lock)
#		d = cls()
#		for key in iterable:
#			d[key] = value
#		self.unlock(lock)
#		return d
