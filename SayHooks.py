import inspect, sys, os, types, time, string, logging
from datetime import datetime
from datetime import timedelta

bad_word_dict = {}
bad_site_list = []
bad_nick_list = set()
chars = string.ascii_letters + string.digits

def _update_lists():
	try:
		global bad_word_dict
		bad_word_dict = {}
		f = open('bad_words.txt', 'r')
		for line in f.readlines():
			line = line.strip()
			if not line: continue
			if line.count(' ') < 1:
				bad_word_dict[line.lower()] = '***'
			else:
				sline = line.split(' ', 1)
				bad_word_dict[sline[0].lower()] = ' '.join(sline[1:])
		f.close()
	except Exception as e:
		logging.error('Error parsing profanity list: %s' %(e))
	try:
		global bad_site_list
		bad_site_list = []
		f = open('bad_sites.txt', 'r')
		for line in f.readlines():
			line = line.strip().lower()
			if not line: continue
			if line in bad_site_list:
				print("duplicate line in bad_sites.txt: %s" %(line))
			else:
				bad_site_list.append(line)
		f.close()
	except Exception as e:
		logging.error('Error parsing shock site list: %s' %(e))

	try:
		global bad_nick_list
		bad_nick_list = set()
		f = open('bad_nicks.txt', 'r')
		for line in f.readlines():
			line = line.strip().lower()
			if not line:
				continue
			bad_nick_list.add(line)
		f.close()

	except Exception as e:
		logging.error('Error parsing bad nick list: %s' %(e))


_update_lists()


def _process_word(word):
	if word == word.upper(): uppercase = True
	else: uppercase = False
	lword = word.lower()
	if lword in bad_word_dict:
		word = bad_word_dict[lword]
	if uppercase: word = word.upper()
	return word

def _nasty_word_censor(msg):
	msg = msg.lower()
	for word in bad_word_dict.keys():
		if word in msg: return False
	return True

def _word_censor(msg):
	words = []
	word = ''
	letters = True
	for letter in msg:
		if bool(letter in chars) == bool(letters): word += letter
		else:
			letters = not bool(letters)
			words.append(word)
			word = letter
	words.append(word)
	newmsg = []
	for word in words:
		newmsg.append(_process_word(word))
	return ''.join(newmsg)

def _site_censor(msg):
	testmsg1 = ''
	testmsg2 = ''
	for letter in msg:
		if not letter: continue
		if letter.isalnum():
			testmsg1 += letter
			testmsg2 += letter
		elif letter in './%':
			testmsg2 += letter
	for site in bad_site_list:
		if site in msg or site in testmsg1 or site in testmsg2:
			return # 'I think I can post shock sites, but I am wrong.'
	return msg

def _spam_enum(client, chan):
	now = time.time()
	bonus = 0
	already = []
	times = [now]
	for when in dict(client.lastsaid[chan]):
		t = float(when)
		if t > now-5: # check the last five seconds # can check a longer period of time if old bonus decay is included, good for 2-3 second spam, which is still spam.
			for message in client.lastsaid[chan][when]:
				times.append(t)
				if message in already:
					bonus += 2 * already.count(message) # repeated message
				if len(message) > 50:
					bonus += min(len(message), 200) * 0.01 # long message: 0-2 bonus points based linearly on length 0-200
				bonus += 1 # something was said
				already.append(message)
		else: del client.lastsaid[chan][when]

	times.sort()
	last_time = None
	for t in times:
		if last_time:
			diff = t - last_time
			if diff < 1:
				bonus += (1 - diff) * 1.5
		last_time = t

	if bonus > 7: return True
	else: return False

def _spam_rec(client, chan, msg):
	now = str(time.time())
	if not chan in client.lastsaid: client.lastsaid[chan] = {}
	if not now in client.lastsaid[chan]:
		client.lastsaid[chan][now] = [msg]
	else:
		client.lastsaid[chan][now].append(msg)

def hook_SAY(self, client, channel, msg):
	username = client.username

	if channel.isMuted(client): return msg # client is muted, no use doing anything else
	if channel.antispam and not channel.isOp(client): # don't apply antispam to ops
		_spam_rec(client, channel.name, msg)
		now = datetime.now()
		duration = timedelta(minutes=5)
		expires = now + duration
		if _spam_enum(client, channel.name):
			channel.muteUser(self._root.chanserv, client, expires, 'spamming', duration)
	return msg

def hook_OPENBATTLE(self, client, title):
	title = _word_censor(title)
	title = _site_censor(title)
	return title

def isNasty(msg):
	msg = msg.lower()

	cleaned = msg
	for ch in ["[", "]", "_"]:
		cleaned = cleaned.replace(ch, "")
	for word in bad_nick_list:
		if word in msg: return True
		if word in cleaned: return True
	return False

