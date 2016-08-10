import time, sys, os, socket

import traceback
import SQLUsers
import ChanServ
import ip2country
import datetime
import Protocol

import logging
from logging.handlers import TimedRotatingFileHandler
from twisted.internet import ssl

separator = '-'*60

try:
	from urllib2 import urlopen
except:
	# The urllib2 module has been split across several modules in Python 3.0
	from urllib.request import urlopen

class DataHandler:

	def __init__(self):
		self.logfilename = "server.log"
		self.initlogger(self.logfilename)
		self.local_ip = None
		self.online_ip = None
		self.session_id = 0
		self.dispatcher = None
		self.console_buffer = []
		self.port = 8200
		self.xmlport = 8300
		self.xmlhost = '127.0.0.1'
		self.natport = self.port + 1
		self.latestspringversion = '*'
		self.agreementfile = 'agreement.txt'
		self.agreement = []
		self.server = 'TASServer'
		self.server_version = 0.36
		self.sighup = False

		self.chanserv = None
		self.userdb = None
		self.channeldb = None
		self.engine = None
		self.updatefile = None
		self.trusted_proxyfile = None
		
		self.max_threads = 25
		self.sqlurl = 'sqlite:///server.db'
		self.nextbattle = 0
		self.SayHooks = __import__('SayHooks')
		self.censor = True
		self.motd = None
		self.running = True
		self.redirect = None
		
		self.trusted_proxies = []
		
		self.start_time = time.time()
		self.channels = {}
		self.usernames = {}
		self.clients = {}
		self.db_ids = {}
		self.battles = {}
		self.detectIp()
		self.cert = None

	def initlogger(self, filename):
		# logging
		server_logfile = os.path.join(os.path.dirname(__file__), filename)
		self.logger = logging.getLogger()
		self.logger.setLevel(logging.DEBUG)
		fh = TimedRotatingFileHandler(server_logfile, when="midnight", backupCount=6)
		formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-5s %(module)s.%(funcName)s:%(lineno)d  %(message)s',
						datefmt='%Y-%m-%d %H:%M:%S')
		fh.setFormatter(formatter)
		fh.setLevel(logging.DEBUG)
		self.logger.addHandler(fh)

	def init(self):
		sqlalchemy = __import__('sqlalchemy')
		if self.sqlurl.startswith('sqlite'):
			print('Multiple threads are not supported with sqlite, forcing a single thread')
			print('Please note the server performance will not be optimal')
			print('You might want to install a real database server')
			print('')
			self.max_threads = 1
			self.engine = sqlalchemy.create_engine(self.sqlurl, echo=False)
			def _fk_pragma_on_connect(dbapi_con, con_record):
				dbapi_con.execute('PRAGMA journal_mode = MEMORY')
				dbapi_con.execute('PRAGMA synchronous = OFF')
			## FIXME: "ImportError: cannot import name event"
			from sqlalchemy import event
			event.listen(self.engine, 'connect', _fk_pragma_on_connect)
		else:
			self.engine = sqlalchemy.create_engine(self.sqlurl, pool_size=self.max_threads * 2, pool_recycle=300)

		self.userdb = SQLUsers.UsersHandler(self, self.engine)
		self.channeldb = SQLUsers.ChannelsHandler(self, self.engine)

		channels = self.channeldb.load_channels()

		for name in channels:
			channel = channels[name]

			owner = None
			admins = []
			client = self.userdb.clientFromUsername(channel['owner'])
			if client and client.id: owner = client.id

			for user in channel['admins']:
				client = userdb.clientFromUsername(user)
				if client and client.id:
					admins.append(client.id)

			self.channels[name] = Protocol.Channel.Channel(self, name, chanserv=bool(owner), id = channel['id'], owner=owner, admins=admins, key=channel['key'], antispam=channel['antispam'], topic={'user':'ChanServ', 'text':channel['topic'], 'time':int(time.time())}, store_history = channel['store_history'] )

		#self.dispatcher.addClient(self.chanserv)


		self.parseFiles()
		self.protocol = Protocol.Protocol(self)
		self.chanserv = ChanServ.ChanServClient(self, (self.online_ip, 0), self.session_id)
		self.chanserv.ChanServ.onLogin()

		for name in channels:
			self.chanserv.HandleProtocolCommand('JOIN %s' % name)

	def shutdown(self):
		self.running = False

	def showhelp(self):
		print('Usage: server.py [OPTIONS]...')
		print('Starts uberserver.')
		print('')
		print('Options:')
		print('  -h, --help')
		print('      { Displays this screen then exits }')
		print('  -p, --port number')
		print('      { Server will host on this port (default is 8200) }')
		print('  -n, --natport number')
		print('      { Server will use this port for NAT transversal (default is 8201) }')
		print('  -g, --loadargs filename')
		print('      { Reads additional command-line arguments from file }')
		print('  -o, --output /path/to/file.log')
		print('      { Writes console output to file (for logging) }')
		print('  -u, --sighup')
		print('      { Reload the server on SIGHUP (if SIGHUP is supported by OS) }')
		print('  -v, --latestspringversion version')
		print('      { Sets latest Spring version to this string. Defaults to "*" }')
		print('  -s, --sqlurl SQLURL')
		print('      { Uses SQL database at the specified sqlurl for user, channel, and ban storage. }')
		print('  -c, --no-censor')
		print('      { Disables censoring of #main, #newbies, and usernames (default is to censor) }')
		print('  --proxies /path/to/proxies.txt')
		print('     { Path to proxies.txt, for trusting proxies to pass real IP through local IP }')
		print('   -a --agreement /path/to/agreement.txt')
		print('     { sets the pat to the agreement file which is sent to a client registering at the server }')
		print('   -r --redirect "hostname/ip port"')
		print('     { redirects connecting clients to the given ip and port')
		print('SQLURL Examples:')
		#print('  "sqlite:///:memory:" or "sqlite:///"')
		#print('     { both make a temporary database in memory }')
		print('  "sqlite:////absolute/path/to/database.txt"')
		print('     { uses a database in the file specified }')
		print('  "sqlite:///relative/path/to/database.txt"')
		print('     { note sqlite is slower than a real SQL server }')
		print('  "mysql://user:password@server:port/database?charset=utf8&use_unicode=0"')
		print('     { requires the MySQLdb module }')
		print('  "oracle://user:password@server:port/database"')
		print('     { requires the cx_Oracle module }')
		print('  "postgres://user:password@server:port/database"')
		print('     { requires the psycopg2 module }')
		print('  "mssql://user:password@server:port/database"')
		print('     { requires pyodbc (recommended) or adodbapi or pymssql }')
		print('  "firebird://user:password@server:port/database"')
		print('     { requires the kinterbasdb module }')
		print()
		print('Usage example (this is what the test server uses at the moment):')
		print(' server.py -p 8300 -n 8301')
		print()
		exit()

	def parseArgv(self, argv):
		'parses command-line options'
		args = {'ignoreme':[]}
		mainarg = 'ignoreme'

		tempargv = list(argv)
		while tempargv:
			arg = tempargv.pop(0)
			if arg.startswith('-'):
				mainarg = arg.lstrip('-').lower()

				if mainarg in ['g', 'loadargs']:
					try:
						name = tempargv[0]
						if name.startswith('-'): raise Exception
						f = file(name, 'r')
						lines = f.read().split('\n')
						f.close()

						tempargv += ' '.join(lines).split(' ')
					except:
						pass

				args[mainarg] = []
			else:
				args[mainarg].append(arg)
		del args['ignoreme']

		for arg in args:
			argp = args[arg]

			if arg in ['r', 'redirect']:
				self.redirect = argp[0]
			if arg in ['h', 'help']:
				self.showhelp()
			if arg in ['p', 'port']:
				try: self.port = int(argp[0])
				except: print('Invalid port specification')
			elif arg in ['n', 'natport']:
				try: self.natport = int(argp[0])
				except: print('Invalid NAT port specification')
			elif arg in ['o', 'output']:
				try: self.logfilename = argp[0]
				except: print('Error specifying log location')
			elif arg in ['u', 'sighup']:
				self.sighup = True
			elif arg in ['v', 'latestspringversion']:
				try: self.latestspringversion = argp[0] # ' '.join(argp) # shouldn't have spaces
				except: print('Error specifying latest spring version')
			elif arg in ['s', 'sqlurl']:
				try:
					self.sqlurl = argp[0]
				except:
					print('Error specifying SQL URL')
			elif arg in ['c', 'no-censor']:
				self.censor = False
			elif arg in ['a', 'agreement']:
				try:
					self.argeementfile = argp[0]
				except:
					print('Error reading agreement file')
			elif arg == 'proxies':
				try:
					self.trusted_proxyfile = argp[0]
					open(self.trusted_proxyfile, 'r').close()
				except:
					print('Error opening trusted proxy file.')
					self.trusted_proxyfile = None

	def loadCertificates(self):
		certfile = "server.pem"
		if not os.path.isfile(certfile):
			import certificate
			certificate.create_self_signed_cert(certfile)
		os.chmod(certfile, 0o600)
		f = open(certfile, "r")
		self.cert = ssl.PrivateCertificate.loadPEM(f.read()).options()
		f.close()

	def parseFiles(self):
		if os.path.isfile('motd.txt'):
			motd = []
			f = open('motd.txt', 'r')
			data = f.read()
			f.close()
			if data:
				for line in data.split('\n'):
					motd.append(line.strip())
			self.motd = motd
		
		if self.trusted_proxyfile:
			self.trusted_proxies = set([])
			f = open(self.trusted_proxyfile, 'r')
			data = f.read()
			f.close()
			if data:
				for line in data.split('\n'):
					proxy = line.strip()
					if not proxy.replace('.', '', 3).isdigit():
						proxy = socket.gethostbyname(proxy)
					
					if proxy:
						self.trusted_proxies.add(proxy)
		self.agreement = []
		ins = open(self.agreementfile, "r" )
		for line in ins:
			self.agreement.append(line.rstrip('\r\n'))
		ins.close()
		self.loadCertificates()

	def getUserDB(self):
		return self.userdb
	
	def clientFromID(self, db_id):
		if db_id in self.db_ids: return self.db_ids[db_id]
	
	def clientFromUsername(self, username):
		if username in self.usernames: return self.usernames[username]

	def clientFromSession(self, session_id):
		if session_id in self.clients: return self.clients[session_id]

	def event_loop(self):
		lastmute = lastidle = self.start_time
		while self.running:
			now = time.time()
			try:
				if now - lastmute >= 1: #FIXME: reenable after twisted switch
					lastmute = now
					self.mute_timeout_step(now)
			except:
				self.error(traceback.format_exc())
			time.sleep(max(0.1, 1 - (now - self.start_time)))

	def mute_timeout_step(self, now):
		try:
			channels = self.channels
			for chan in channels:
				channel = channels[chan]
				mutelist = channel.mutelist
				for db_id in mutelist:
					expiretime = mutelist[db_id]['expires']
					if 0 < expiretime and expiretime < now:
						del channel.mutelist[db_id]
						client = self.clientFromID(db_id)
						if client:
							channel.channelMessage('<%s> has been unmuted (mute expired).' % client.username)
		except:
			self.error(traceback.format_exc())

	def error(self, error):
		self.console_write('%s\n%s\n%s'%(separator,error,separator))
		self.logger.error(error)

	def console_write(self, lines=''):
		if type(lines) in(str, unicode):
			lines = lines.split('\n')
		elif not type(lines) in (list, tuple, set):
			try: lines = [lines.__repr__()]
			except: lines = ['Failed to print lines of type %s'%type(lines)]
		for line in lines:
			print(line)
			self.logger.info(line)

	# the sourceClient is only sent for SAY*, and RING commands
	def multicast(self, clients, msg, ignore=(), sourceClient=None):
		if type(ignore) in (str, unicode): ignore = [ignore]
		static = []
		for client in clients:
			if client and not client.username in ignore and \
			    (sourceClient == None or not sourceClient.db_id in client.ignored):
				if client.static: static.append(client)
				else: client.Send(msg)
		
		# this is so static clients don't respond before other people even receive the message
		for client in static:
			client.Send(msg)
	
	# the sourceClient is only sent for SAY*, and RING commands
	def broadcast(self, msg, chan=None, ignore=(), sourceClient=None):
		if type(ignore) in (str, unicode): ignore = [ignore]
		try:
			if chan in self.channels:
				channel = self.channels[chan]
				if len(channel.users) > 0:
					clients = [self.clientFromSession(user) for user in channel.users]
					self.multicast(clients, msg, ignore, sourceClient)
			else:
				clients = [self.clientFromUsername(user) for user in self.usernames]
				self.multicast(clients, msg, ignore, sourceClient)
		except: self.error(traceback.format_exc())

	# the sourceClient is only sent for SAY*, and RING commands
	def broadcast_battle(self, msg, battle_id, ignore=[], sourceClient=None):
		if type(ignore) in (str, unicode): ignore = [ignore]
		if battle_id in self.battles:
			battle = self.battles[battle_id]
			clients = [self.clientFromSession(user) for user in battle.users]
			self.multicast(clients, msg, ignore, sourceClient)

	def admin_broadcast(self, msg):
		for user in self.usernames:
			client = self.usernames[user]
			if user == "ChanServ": # needed to allow "reload"
				continue
			if 'admin' in client.accesslevels:
				client.Send('SERVERMSG Admin broadcast: %s'%msg)

	def _rebind_slow(self):
		try:
			self.protocol = Protocol.Protocol(self)
			for channel in dict(self.channels): # hack, but I guess reloading is all a hack :P
				chan = self.channels[channel].copy()
				del chan['name'] # 'cause we're passing it ourselves
				self.channels[channel] = Protocol.Channel.Channel(self, channel, **chan)
			
			self.userdb = SQLUsers.UsersHandler(self, self.engine)
			self.channeldb = SQLUsers.ChannelsHandler(self, self.engine)
			self.chanserv.reload()
			for clientid, client in self.clients.iteritems():
				client._root = self
		except:
			self.error(traceback.format_exc())

		self.admin_broadcast('Done reloading.')
		self.console_write('Done reloading.')

	def reload(self):
		self.admin_broadcast('Reloading...')
		self.console_write('Reloading...')
		self.parseFiles()
		toreload = [
				"SayHooks",
				"ChanServ",
				"BaseClient",
				"SQLUsers",
				"Client",
				"protocol.AutoDict",
				"protocol.Channel",
				"protocol.Battle",
				"protocol.Protocol",
				"protocol",
			]	
		for module in toreload:
			reload(sys.modules[module])
		self.SayHooks = __import__('SayHooks')
		ip2country.reloaddb()
		self._rebind_slow()

	def get_ip_address(self):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.connect(("springrts.com", 80))
			return s.getsockname()[0]
		except:
			pass
		try:
			return socket.gethostbyname(socket.gethostname())
		except:
			pass
		return '127.0.0.1'

	def detectIp(self):
		self.console_write('\nDetecting local IP:')
		local_addr = self.get_ip_address()
		self.console_write(local_addr)

		self.console_write('Detecting online IP:')


		try:
			timeout = socket.getdefaulttimeout()
			socket.setdefaulttimeout(5)
			web_addr = urlopen('http://springrts.com/lobby/getip.php').read()
			socket.setdefaulttimeout(timeout)
			self.console_write(web_addr)
		except:
			web_addr = local_addr
			self.console_write('not online')
		self.console_write()

		self.local_ip = local_addr
		self.online_ip = web_addr

	def createSocket(self):
		backlog = 100
		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR,
				                server.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) | 1 )
				                # fixes TIME_WAIT :D
		server.bind(("",self.port))
		server.listen(backlog)
		return server


