# if this is running from the scripts folder, move up a folder.
import os, sys
if not 'server.py' in os.listdir('.') and 'scripts' in os.listdir('..'):
	os.chdir('..')

sys.path.append('.')

import sys
import time
import datetime 
import traceback
from tasserver.LegacyChannels import Parser
from tasserver.LegacyUsers import User

from SQLUsers import Channel

if not len(sys.argv) == 4:
	print 'usage: migrate.py [/path/to/accounts.txt] [/path/to/channels.xml] [dburl]'
	sys.exit()

print
print 'starting migration'
print

accountstxt = sys.argv[1]
channel_xml = sys.argv[2]
dburl = sys.argv[3]

def _bin2dec(s): return int(s, 2)

print 'opening database'
try:
	import sqlalchemy
	engine = sqlalchemy.create_engine(dburl, pool_size=512, pool_recycle=300)
except:
	print '-'*60
	print traceback.format_exc()
	print '-'*60
	print
	print 'could not import sqlalchemy module, try running scripts/fetch_deps.py'
	sys.exit()

UsersHandler = __import__('SQLUsers').UsersHandler
db = UsersHandler(None, engine)

print 'reading accounts'

f = open(accountstxt, 'r')
data = f.read()

f.close()

print 'scanning accounts'
accounts = {}

def fromtimestamp(str):
	if str == 0:
		return None
	if str < 3000:
		return None
	if str > time.time():
		str = str / 1000
	return datetime.datetime.fromtimestamp(str)

defdate = datetime.datetime(2000, 1, 1)

for line in data.split('\n'):
	if line:
		user = User.fromAccountLine(line)
		if not user:
			print 'Invalid line: %s' %(line)
			continue
		register_date = fromtimestamp(user.last_login)
		last_login = fromtimestamp(user.last_login)
		accounts[user.username] = {
			'user':user.username, 'pass':user.password, 'ingame':user.ingame_time,
			'last_login':last_login, 'register_date':register_date, 'uid':user.last_id,
			'last_ip':user.last_ip, 'country':user.country, 'bot':user.bot, 'access':user.access,
			}

print
print 'writing accounts to database'
db.inject_users(accounts.values())

print
print 'reading channels'

p = Parser()
for name, channel in p.parse(channel_xml).items():
	admins = []
	
	client = db.clientFromUsername(channel['owner'])
	if client and client.id: owner = client.id
	
	for user in channel['admins']:
		client = db.clientFromUsername(user)
		if client and client.id:
			admins.append(client.id)
	c = Channel(
			name,
			#chanserv=bool(owner),
			owner = channel['owner'],
			topic = channel['topic'],
			topic_time = defdate,
			topic_owner = 'ChanServ',
			antispam=channel['antispam'],
			#autokick='ban',
			#censor=False
			#antishock=False
			admins=admins,
			key=channel['key'],
		)
	try:
		db.inject_channel(c)
	except sqlalchemy.exc.IntegrityError:
		print "Duplicate channel: " + name
		pass

