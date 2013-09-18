import traceback

import LegacyUsers, LegacyChannels

try:
	import LegacyBans
except:
	print '-'*60
	print traceback.format_exc()
	print '-'*60
	print 'Error importing LegacyBans. You might lack sqlalchemy, which you can get from running scripts/fetch_deps.py'