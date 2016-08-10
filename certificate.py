
from OpenSSL import crypto, SSL
from socket import gethostname
import time
from os.path import exists, join

CERT_FILE = "server.crt"
KEY_FILE = "server.key"

def timestr():
	return time.strftime("%Y%m%d%H%M%SZ", time.gmtime())

def create_self_signed_cert(filename):
	# creates a serlf-signed certificate
	# to verify run openssl x509 -in server.key -text -noout
	print("Generating self-signed certificate %s" % (filename))


	# create a key pair
	k = crypto.PKey()
	k.generate_key(crypto.TYPE_RSA, 4096)

	# create a self-signed cert
	cert = crypto.X509()
	cert.get_subject().C = "DE"
	cert.get_subject().ST = "uberserver self-signed certificate"
	cert.get_subject().L = "-"
	cert.get_subject().O = "-"
	cert.get_subject().OU = "spring rts"
	cert.get_subject().CN = "-"
	cert.set_serial_number(1000)
	when = timestr()
	cert.set_notBefore(when)
	cert.set_notAfter(when)
	cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60) # 10 years
	cert.set_issuer(cert.get_subject())
	cert.set_pubkey(k)
	cert.sign(k, 'sha1')

	f = open(filename, "wt")
	f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
	f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
	f.close()

#create_self_signed_cert("server.key")
