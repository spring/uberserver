
class BridgedClient():
	'this object represents a user present in an external location, who can speak in (some) channels via a bridging bot'

	def __init__(self):

		#db fields
		self.bridged_id = -1
		self.external_id = ''
		self.location = ''
		self.external_username = ''
		self.last_bridged = ''

		# non-db fields
		self.username = ''
		self.channels = set()
		self.bridge_user_id = -1 # user_id of bridge bot
