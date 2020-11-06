import time, sys, os, socket

import subprocess
import traceback
import importlib
import SQLUsers
import ChanServ
import ip2country
import datetime
from protocol import Protocol, Channel, Battle


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
		self.natport = self.port + 1
		self.min_spring_version = '*'
		
		self.agreement = []
		self.motd = []
		self.iphub_xkey = None
		self.mail_user = None		
		self.trusted_proxies = set([])		
		
		self.server = 'TASSERVER'
		self.server_version = 'unknown'
		
		self.sighup = False

		self.userdb = None
		self.bridgeduserdb = None
		self.channeldb = None
		self.verificationdb = None
		self.bandb = None

		self.chanserv = None
		self.engine = None
		self.updatefile = None
		self.trusted_proxyfile = None

		self.pool_size = 50
		self.sqlurl = 'sqlite:///server.db'
		self.nextbattle = 0
		self.SayHooks = __import__('SayHooks')
		self.censor = True
		self.running = True
		self.redirect = None

		self.start_time = time.time()
		self.detectIp()
		self.cert = None
		
		# stats
		self.inbound_command_stats = {}
		self.outbound_command_stats = {}
		self.flag_stats = {}
		self.agent_stats = {}
		self.tls_stats = 0
		self.n_login_stats = 0	

		# lists of online stuff
		self.channels = {} #channame->channel/battle
		self.battles = {} #battle_id->battle
		self.usernames = {} #username->client
		self.user_ids = {} #user_id->client
		self.clients = {} #session_id->client

		self.bridged_locations = {} #location->bridge_user_id
		self.bridged_ids = {} #bridged_id->bridgedClient
		self.bridged_usernames = {} #bridgeUsername->bridgedClient

		# rate limits
		self.nonres_registrations = set() #user_id
		self.ip_type_cache = {} #ip->state (iphub: 0=non-residential, 1=residential, 2=both)
		self.recent_registrations = {} #ip_address->int
		self.recent_renames = {} #user_id->int
		self.flood_limits = {
			'fresh':{'msglength':1000, 'bytespersecond':1000, 'seconds':2}, # also the default
			'user':{'msglength':10000, 'bytespersecond':2000, 'seconds':10},
			'bot':{'msglength':10000, 'bytespersecond':50000, 'seconds':10},
			'mod':{'msglength':10000, 'bytespersecond':2000, 'seconds':10},
			'admin':{'msglength':10000, 'bytespersecond':2000, 'seconds':10},
		}

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
		self.parseFiles()
		self.get_server_version()		
		
		now = datetime.datetime.now()
		sqlalchemy = __import__('sqlalchemy')
		if self.sqlurl.startswith('sqlite'):
			print('Multiple threads are not supported with sqlite, forcing a single thread')
			print('Please note the server performance will not be optimal')
			print('You might want to install a real database server')
			print('')
			self.max_threads = 1
			self.engine = sqlalchemy.create_engine(self.sqlurl, echo=False, pool_recycle=3600)
			def _fk_pragma_on_connect(dbapi_con, con_record):
				dbapi_con.execute('PRAGMA journal_mode = MEMORY')
				dbapi_con.execute('PRAGMA synchronous = OFF')
			from sqlalchemy import event
			event.listen(self.engine, 'connect', _fk_pragma_on_connect)
		else:
			self.engine = sqlalchemy.create_engine(self.sqlurl, pool_size=self.pool_size, pool_recycle=3600)

		self.session_manager = SQLUsers.session_manager(self, self.engine)
		
		self.userdb = SQLUsers.UsersHandler(self)
		self.bandb = SQLUsers.BansHandler(self)
		self.verificationdb = SQLUsers.VerificationsHandler(self)
		self.bridgeduserdb = SQLUsers.BridgedUsersHandler(self)

		self.contentdb = SQLUsers.ContentHandler(self)
		self.min_spring_version = self.contentdb.get_min_spring_version()

		self.protocol = Protocol.Protocol(self)

		self.channeldb = SQLUsers.ChannelsHandler(self)
		channels = self.channeldb.all_channels()

		# set up channels/battles from db
		for name in channels:
			channel = channels[name]

			owner_user_id = None
			client = self.userdb.clientFromID(channel['owner_user_id'])
			if client and client.id:
				owner_user_id = client.id

			assert(name not in self.channels)
			dbchannel = channels[name]
			channel = Channel.Channel(self, name)
			if name.startswith('__battle__'):
				channel = Battle.Battle(self, name)

			owner = self.userdb.clientFromID(dbchannel['owner_user_id'])
			if owner:
				channel.owner_user_id = owner.id

			channel.antispam = dbchannel['antispam']
			channel.store_history = dbchannel['store_history']
			channel.id = dbchannel['id']
			channel.key = dbchannel['key']
			if channel.key in ('', None, '*'):
				channel.key = None
			channel.last_used = dbchannel['last_used']
			if not channel.last_used: # can remove after first run!
				channel.last_used = now
				self.channeldb.recordUse(channel)

			channel.topic_user_id = dbchannel['topic_user_id']
			channel.topic = dbchannel['topic']
			self.channels[name] = channel

		# set up chanserv
		self.chanserv = ChanServ.ChanServClient(self, (self.online_ip, 0), self.session_id)
		for name in channels:
			self.chanserv.HandleProtocolCommand("JOIN %s" %(name))

		if not 'moderator' in channels:
			self.chanserv.Handle(":register moderator ChanServ")

		# set up channel properties
		forwards = self.channeldb.all_forwards()
		for forward in forwards:
			dbchannel_from = self.channeldb.channel_from_id(forward['channel_from_id'])
			dbchannel_to = self.channeldb.channel_from_id(forward['channel_to_id'])
			if dbchannel_from and dbchannel_to:
				self.channels[dbchannel_from.name].forwards.add(dbchannel_to.name)

		operators = self.channeldb.all_operators()
		for op in operators:
			dbchannel = self.channeldb.channel_from_id(op['channel_id'])
			if dbchannel:
				target = self.clientFromID(op['user_id'], True)
				if not target: continue
				self.channels[dbchannel.name].opUser(self.chanserv, target)

		bans = self.channeldb.all_bans()
		for ban in bans:
			dbchannel = self.channeldb.channel_from_id(ban['channel_id'])
			if dbchannel:
				target = self.clientFromID(ban['user_id'], True)
				if not target: continue
				issuer = self.clientFromID(ban['issuer_user_id'], True)
				if not issuer: issuer = self.chanserv
				duration = ban['expires'] - now
				self.channels[dbchannel.name].banUser(issuer, target, ban['expires'], ban['reason'], duration)

		bridged_bans = self.channeldb.all_bridged_bans()
		for ban in bridged_bans:
			dbchannel = self.channeldb.channel_from_id(ban['channel_id'])
			if dbchannel:
				target = self.bridgedClientFromID(ban['bridged_id'], True)
				if not target: continue
				issuer = self.clientFromID(ban['issuer_user_id'], True)
				if not issuer: issuer = self.chanserv
				duration = ban['expires'] - now
				self.channels[dbchannel.name].banBridgedUser(issuer, target, ban['expires'], ban['reason'], duration)

		mutes = self.channeldb.all_mutes()
		for mute in mutes:
			dbchannel = self.channeldb.channel_from_id(mute['channel_id'])
			if dbchannel:
				target = self.clientFromID(mute['user_id'], True)
				if not target: continue
				issuer = self.clientFromID(mute['issuer_user_id'], True)
				if not issuer: issuer = self.chanserv
				duration = mute['expires'] - now
				self.channels[dbchannel.name].muteUser(issuer, target, mute['expires'], mute['reason'], duration)

	def logout_stale_sessions(self):
		to_logout = []
		now = datetime.datetime.now()
		for session_id in self.clients:
			client = self.clients[session_id]
			if client.static or client.bot:
				continue
			login_duration = now - client.last_login
			if login_duration > datetime.timedelta(days=14):
				to_logout.append(session_id)
		logging.info("logging out %d stale sessions" % len(to_logout))
		for session_id in to_logout:
			client = self.clients[session_id]
			client.Remove('reached maximum login duration')
	
	def scheduled_clean(self):
		logging.info("scheduled clean...")
		self.ip_type_cache = {}
		try:
			self.logout_stale_sessions()
			self.userdb.audit_access()
			self.userdb.clean()
			self.bridgeduserdb.clean()
			self.channeldb.clean()
			self.verificationdb.clean()
			self.bandb.clean()
		except:
			logging.error(traceback.format_exc())
		logging.info("scheduled clean finished")

	def shutdown(self):
		if self.chanserv and self.protocol:
			self.protocol.in_STATS(self.chanserv)
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
		print('  -v, --min_spring_version version')
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
		print('  "mysql://user:password@server:port/database?charset=utf8"')
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
					name = tempargv[0]
					f = open(name, 'r')
					lines = f.read().split('\n')
					f.close()
					tempargv += ' '.join(lines).split(' ')

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
			elif arg in ['v', 'min_spring_version']:
				try:
					self.min_spring_version = argp[0] # ' '.join(argp) # shouldn't have spaces
				except Exception as e:
					print('Error specifying spring version: ' + str(e))
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
		with open(certfile, 'r') as data:
			self.cert = ssl.PrivateCertificate.loadPEM(data.read()).options()

	def parseFiles(self):
		self.loadCertificates()
		
		self.motd = []
		try:
			f = open('server_motd.txt', 'r')
			for line in f:
				self.motd.append(line.rstrip('\r\n'))
			f.close()
		except Exception as e:
			logging.error("Could not load motd: %s" % str(e))
			self.motd.append("You have successfully logged into Uberserver!")

		self.agreement = []
		try:
			f = open('server_agreement.txt', 'r')
			for line in f:
				self.agreement.append(line.rstrip('\r\n'))
			f.close()
		except Exception as e:
			logging.error("Could not load user agreement %s" % str(e))
			self.agreement.append("No user agreement detected. If this server is in production, please report this issue immediately!")

		try:
			with open('server_iphub_xkey.txt', 'r') as f:
				lines = f.readlines()
			lines = [l.strip() for l in lines]
			self.iphub_xkey = lines[0]
		except Exception as e:
			logging.error('Could not load server_iphub_xkey.txt: %s' %(e))
		
		try:
			with open('server_email_account.txt', 'r') as f:
				lines = f.readlines()
			lines = [l.strip() for l in lines]
			self.mail_user = lines[0]
			logging.info('Server email account is %s' % self.mail_user)
		except Exception as e:
			logging.error('Could not load server_email_account.txt: %s' %(e))

		
		try:
			if self.trusted_proxyfile:
				f = open(self.trusted_proxyfile, 'r')
				for line in f:
					proxy = line.strip()
					if not proxy.replace('.', '', 3).isdigit():
						proxy = socket.gethostbyname(proxy)
					if proxy:
						self.trusted_proxies.add(proxy)
				f.close()
		except Exception as e:
			logging.error("error whilst loading %s: %s" % (self.trusted_proxyfile, str(e)))		

	def get_server_version(self):
		try:
			self.server_version = subprocess.check_output(["git", "describe"], universal_newlines=True).strip()
		except:
			self.server_version = "unknown"			
			logging.error("Failed to get server version")

	def getUserDB(self):
		return self.userdb

	def getVerificationDB(self):
		return self.verificationdb

	def getBanDB(self):
		return self.bandb
		
	def getContentDB(self):
		return self.contentdb

	def clientFromID(self, user_id, fromdb=False):
		if user_id in self.user_ids: 
			return self.user_ids[user_id]
		if not fromdb: 
			return None
		return self.userdb.clientFromID(user_id)
			
	def clientFromUsername(self, username, fromdb=False):
		if username in self.usernames: 
			return self.usernames[username]
		if not fromdb: 
			return None
		client = self.userdb.clientFromUsername(username)
		if client and username != client.username:
			return None # db side is case insensitive!
		if client:
			self.protocol._calc_access(client)
		return client
		
	def clientFromSession(self, session_id):
		if session_id in self.clients: 
			return self.clients[session_id]
		logging.warning("tried to get client from invalid session_id '%s'" % session_id)
		return None

	def bridgedClient(self, location, external_id, fromdb=False):
		if location in self.bridged_locations:
			bridge_user_id = self.bridged_locations[location]
			bridge_user = self.protocol.clientFromID(bridge_user_id)
			bridge = bridge_user.bridge
			if external_id in bridge[location]:
				bridged_id = bridge[location][external_id]
				return self.bridged_ids[bridged_id]
		if not fromdb:
			return False
		return self.bridgeduserdb.bridgedClient(location, external_id)

	def bridgedClientFromID(self, bridged_id, fromdb=False):
		if bridged_id in self.bridged_ids:
			return self.bridged_ids[bridged_id]
		if not fromdb:
			return
		return self.bridgeduserdb.bridgedClientFromID(bridged_id)

	def bridgedClientFromUsername(self, username, fromdb=False):
		if username in self.bridged_usernames:
			return self.bridged_usernames[username]
		if not fromdb:
			return
		return self.bridgeduserdb.bridgedClientFromUsername(username)

	def channel_mute_ban_timeout(self):
		# remove expired channel/battle mutes/bans
		now = datetime.datetime.now()
		chanserv = self.chanserv
		try:
			channels = self.channels
			for chan in channels:
				channel = channels[chan]
				to_unmute = []
				for user_id in channel.mutelist:
					mute = channel.mutelist[user_id]
					expiretime = mute['expires']
					if expiretime < now:
						to_unmute.append(user_id)
				for user_id in to_unmute:
					target = self.protocol.clientFromID(user_id, True)
					if not target:
						continue
					channel.unmuteUser(chanserv, target, 'mute expired')
					self.channeldb.unmuteUser(channel, target)

				to_unban = []
				for user_id in channel.ban:
					ban = channel.ban[user_id]
					expiretime = ban['expires']
					if expiretime < now:
						to_unban.append(user_id)
				for user_id in to_unban:
					target = self.protocol.clientFromID(user_id, True)
					if not target:
						continue
					self.channeldb.unbanUser(channel, target)
					channel.unbanUser(chanserv, target)

				to_unban_bridged = []
				for bridged_id in channel.bridged_ban:
					ban = channel.bridged_ban[bridged_id]
					expiretime = ban['expires']
					if expiretime < now:
						to_unban_bridged.append(bridged_id)
				for bridged_id in to_unban_bridged:
					target = self.bridgedClientFromID(bridged_id)
					if not target:
						continue
					channel.unbanBridgedUser(chanserv, bridged_id)
					self.channeldb.unbanBridgedUser(channel, bridged_id)
		except:
			logging.error(traceback.format_exc())
			self.session_manager.rollback_guard()
		finally:
			self.session_manager.close_guard()

			
	def decrement_dict(self, d):
		# decrease all values by 1, remove values <=0
		try:
			to_delete = []
			for i in d:
				d[i] -= 1
				if d[i] <= 0:
					to_delete.append(i)
			for i in to_delete:
				del d[i]
		except:
			logging.error(traceback.format_exc())
			self.session_manager.rollback_guard()
		finally:
			self.session_manager.close_guard()
	
	def decrement_recent_registrations(self):
		self.decrement_dict(self.recent_registrations)

	def decrement_recent_renames(self):
		self.decrement_dict(self.recent_renames)

	# the sourceClient is only sent for SAY*, and RING commands
	def multicast(self, session_ids, msg, ignore=(), sourceClient=None, flag=None, not_flag=None):
		assert(type(ignore) == set)
		static = []
		for session_id in session_ids:
			assert(type(session_id) == int)
			client = self.clientFromSession(session_id)

			if not client.logged_in:
				continue
			if client.session_id in ignore:
				continue
			if sourceClient and sourceClient.user_id in client.ignored:
				continue
			if flag and not flag in client.compat: # send to users with compat flag
				continue
			if not_flag and not_flag in client.compat: # send to users without compat flag
				continue

			if client.static:
				static.append(client)
			else:
				client.Send(msg)

		# this is so static clients don't respond before other people even receive the message
		for client in static:
			client.Send(msg)

	# the sourceClient is only sent for SAY*, and RING commands
	def broadcast(self, msg, chan=None, ignore=set(), sourceClient=None, flag=None, not_flag=None):
		assert(type(ignore) == set)
		try:
			if not chan in self.channels:
				self.multicast(self.clients, msg, ignore, sourceClient, flag, not_flag)
				return
			channel = self.channels[chan]
			self.multicast(channel.users, msg, ignore, sourceClient, flag, not_flag)
		except:
			logging.error(traceback.format_exc())

	# the sourceClient is only sent for SAY*, and RING commands
	def broadcast_battle(self, msg, battle_id, ignore=set(), sourceClient=None, flag=None, not_flag=None):
		assert(type(ignore) == set)
		assert(type(battle_id) == int)
		if not battle_id in self.battles:
			return
		battle = self.battles[battle_id]
		self.multicast(battle.users, msg, ignore, sourceClient, flag, not_flag)

	def admin_broadcast(self, msg):
		for user in self.usernames:
			client = self.usernames[user]
			if user == "ChanServ": # needed to allow "reload"
				continue
			if 'admin' in client.accesslevels:
				client.Send('SERVERMSG Admin broadcast: %s'%msg)

	def get_ip_address(self):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.connect(("springrts.com", 80))
			res = s.getsockname()[0]
			s.close()
			return res
		except Exception as e:
			self.logger.debug(e)
			pass
		try:
			return socket.gethostbyname(socket.gethostname())
		except:
			pass
		return '127.0.0.1'

	def detectIp(self):
		logging.info('Detecting local IP:')
		local_addr = self.get_ip_address()
		logging.info(local_addr)

		logging.info('Detecting online IP:')


		try:
			timeout = socket.getdefaulttimeout()
			socket.setdefaulttimeout(5)
			web_addr = urlopen('https://springrts.com/lobby/getip.php').read().decode("utf-8")
			socket.setdefaulttimeout(timeout)
			logging.info(web_addr)
		except:
			web_addr = local_addr
			logging.info('not online')

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

	def stats(self):
		logging.info(" -- STATS -- ")
		logging.info("Command counts (inbound):")
		for k in sorted(self.inbound_command_stats):
			logging.info(" %s %d" % (k, self.inbound_command_stats[k]))
		logging.info("Command counts (outbound):")
		for k in sorted(self.outbound_command_stats):
			logging.info(" %s %d" % (k, self.outbound_command_stats[k]))
		logging.info("Number of logins: %d" % self.n_login_stats)
		logging.info("TLS logins: %d" % self.tls_stats)
		logging.info("Agents:")
		for k in sorted(self.agent_stats):
			count = self.agent_stats[k]
			logging.info(" %s  %d" % (k, count))
		logging.info("Flags sent:")
		for k in sorted(self.flag_stats):
			count = self.flag_stats[k]
			logging.info(" %s %d" % (k, count))
		logging.info(" -- END STATS -- ")		
		
	def client_LoginStats(self, client):
		# record stats for this clients login
		self.n_login_stats += 1
		if client.TLS:
			self.tls_stats += 1
		for flag in client.compat:
			if flag in self.flag_stats:
				self.flag_stats[flag] += 1
			else:
				self.flag_stats[flag] = 1
		if client.agent in self.agent_stats:
			self.agent_stats[client.agent] += 1
		else:
			self.agent_stats[client.agent] = 1
	
	def reload(self, client):
		# reload non-core parts of the server
		logging.info("Reload initiated by <%s>" % client.username)

		try:
			self.parseFiles()
			self.get_server_version()
			importlib.reload(sys.modules['Client'])
			importlib.reload(sys.modules['BridgedClient'])
			importlib.reload(sys.modules['Channel'])
			importlib.reload(sys.modules['Battle'])
			
			proto = importlib.reload(sys.modules['Protocol'])
			sayhooks = importlib.reload(sys.modules['SayHooks'])
			chanserv = importlib.reload(sys.modules['ChanServ'])

			self.protocol = proto.Protocol(self)
			self.SayHooks = sayhooks
			
			self.chanserv = chanserv.ChanServClient(self, (self.online_ip, 0), self.chanserv.session_id)
			for chan in self.channels:
				channel = self.channels[chan]
				if channel.registered():
					self.chanserv.channels.add(chan)				
		
		except Exception as e:
			ret = 'Reload failed'
			logging.error(ret + ":")
			logging.error(e)
			return ret
			
		ret = 'Reload successful'
		logging.info(ret)
		return ret

