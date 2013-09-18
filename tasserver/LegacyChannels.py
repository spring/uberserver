import xml.dom.minidom as minidom
from xml.sax.saxutils import escape, unescape, quoteattr

import os, re, codecs

class Parser:
	topicRe = re.compile(r'''<channel[^>]*name\s*=\s*(["'])(?P<name>.*?)\1[^>]*topic\s*=\s*(["'])(?P<topic>.+?)\3[^>]*>''')
	entityRe = re.compile(r'(&(?P<entity>[^\s]+?);)')
	
	def replaceAll(self, string, regex, group=None, callback=None):
		match = regex.search(string)
		while match:
			start, end = match.start(group), match.end(group)
			middle = string[start:end]
			if callback:
				middle = callback(middle, match)
			else:
				middle = ''
			
			string = string[:start] + middle + string[end:]
			match = regex.search(string)
		
		return string
	
	def findTopics(self, xml):
		topics = {}
		matches = self.topicRe.finditer(xml)
		for match in matches:
			name, topic = match.group('name'), match.group('topic')
			topics[name] = topic
		
		xml = self.replaceAll(xml, self.topicRe, group='topic')
		return xml, topics
	
	def resolveEntity(self, ref, match):
		entity = match.group('entity')
		
		replacement = unescape(ref)
		if replacement == ref:
			replacement = ''
		
		if not replacement:
			if entity.startswith('#'):
				entity = entity[1:]
				if entity.isdigit():
					entity = int(entity)
					if entity < 127:
						replacement = chr(entity)
		
		return replacement
	
	def resolveEntities(self, string):
		string = self.replaceAll(string, self.entityRe, group=0, callback=self.resolveEntity)
		return string
	
	def _parse(self, string):
		xml, topics = self.findTopics(string)
		for chan in topics:
			topics[chan] = self.resolveEntities(topics[chan])
		
		chans = {}
		
		settings = minidom.parseString(xml)
		channels = settings.getElementsByTagName('channel')
		
		for channel in channels:
			chanops = []
			ops = channel.getElementsByTagName('operator')
			
			for op in ops:
				chanops.append(str(op.getAttribute('name')))
				
			owner = str(channel.getAttribute('founder')) or None
			name = str(channel.getAttribute('name'))
			
			topic = None
			if name in topics:
				topic = topics[name].decode('utf-8').encode('raw_unicode_escape') # chanserv writes double-encoded utf-8, this decodes it
				
			chan = {'owner':str(owner), 'key':str(channel.getAttribute('key')) or None, 'topic':topic or '', 'antispam':(str(channel.getAttribute('antispam')) == 'yes'), 'admins':chanops}
			if chan['key'] == '*': chan['key'] = None
			chans[name] = chan
		
		return chans
	
	def parse(self, filename):
		f = open(filename, 'r')
		data = f.read()
		f.close()
		
		return self.parseString(data)
	
	def parseString(self, string):
		return self._parse(string)

class Writer:
	def dump(self, channels, clientFromID):
		f = codecs.open('channels.xml.tmp', 'w', 'utf-8')
		f.write('<channels>\n')
		for channel in channels.values():
			owner = clientFromID(channel.owner)
			
			if owner:
				topic = channel.topic
				if topic and topic['text']: topic = topic['text'].decode('raw_unicode_escape')
				else: topic = '*'
				f.write('\t<channel antispam="%s" name="%s" founder="%s" topic=%s key=%s>\n' % (('yes' if channel.antispam else 'no'), channel.chan, owner.username, escape(quoteattr(topic)), escape(quoteattr(channel.key or '*'))))
				for admin in channel.admins:
					admin = clientFromID(admin)
					if admin:
						f.write('\t\t<operator name="%s" />\n' % admin.username)
				f.write('\t</channel>\n')
		f.write('</channels>\n')
		f.close()
		
		if os.path.exists('channels.xml') and os.path.exists('channels.xml.tmp'):
			os.remove('channels.xml')
		os.rename('channels.xml.tmp', 'channels.xml')