
class BridgedClient:
	'this object represents a user present in an external location, who can speak in (some) channels via a bridging bot'
	
	def __init__(self, bridge_client, location, external_id, external_username):
		self.bridge_user_id = bridge_client.user_id 
		self.location = location
		self.bridged_id = external_id + '@' + location # uniquely identifies the bridged client
		self.username = external_username + '@' + location
	
		self.channels = set()