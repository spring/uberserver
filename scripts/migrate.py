# if this is running from the scripts folder, move up a folder.
import os, sys
if not 'server.py' in os.listdir('.') and 'scripts' in os.listdir('..'):
	os.chdir('..')

sys.path.append('.')

import sys
import time
import traceback
from tasserver.LegacyChannels import Parser
from Protocol import Channel

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
userdb = UsersHandler(None, accountstxt)

print
print 'writing accounts to database'
accounts = {}
for user in userdb.accounts.values():
	accounts[user.username] = {
		'user':user.username, 'pass':user.password, 'ingame':user.ingame_time,
		'last_login':user.last_login, 'register_date':user.register_date, 'uid':user.last_id,
		'last_ip':user.last_ip, 'country':user.country, 'bot':user.bot, 'access':user.access
	}

db.inject_users()

print
print 'reading channels'

p = Parser()
for name, channel in p.parse(channel_xml).items():
	owner = None
	admins = []
	
	client = userdb.clientFromUsername(channel['owner'])
	if client and client.id: owner = client.id
	
	for user in channel['admins']:
		client = userdb.clientFromUsername(user)
		if client and client.id:
			admins.append(client.id)
	
	c = Channel(None, name, chanserv=bool(owner), owner=owner, admins=admins, key=channel['key'], antispam=channel['antispam'], topic={'user':'ChanServ', 'text':channel['topic'], 'time':int(time.time()*1000)})
	db.save_channel(c)
