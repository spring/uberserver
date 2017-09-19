#!/usr/bin/env python3
# coding=utf-8

import socket, ssl, hashlib

context = ssl.SSLContext()
#context.verify_mode = ssl.CERT_REQUIRED

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('lobby.springrts.com', 8200))

print(s.recv(1024))
s.send(b"STARTTLS\n")

s = context.wrap_socket(s)

print(s.recv(1024))
cert = s.getpeercert(True)

m = hashlib.sha256()
m.update(cert)
print("Certificate:")
print(ssl.DER_cert_to_PEM_cert(cert))
print("Certificate fingerprint: %s" %(m.hexdigest()))

s.send(b"PING\n")
print(s.recv(1024))

s.shutdown(socket.SHUT_RDWR)
s.close()

