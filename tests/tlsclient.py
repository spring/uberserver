#!/usr/bin/env python3
# coding=utf-8

import socket, ssl, hashlib

context = ssl.SSLContext()
#context.verify_mode = ssl.CERT_REQUIRED

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('lobby.springrts.com', 8200))

print(s.recv(1024))
s.send(b"STLS\n")
assert(s.recv(1024).startswith(b"OK"))

s = context.wrap_socket(s)

print(s.recv(1024))
cert = s.getpeercert(True)

m = hashlib.sha256()
m.update(cert)
print("Certificate:")
print(ssl.DER_cert_to_PEM_cert(cert))
print("Certificate fingerprint: %s" %(m.hexdigest()))

assert(m.hexdigest() == "0124dc0f4295b401a2d81ade3dc81b7a467eb9a70b0a4912b5e15fede735fe73")

s.send(b"PING\n")
print(s.recv(1024))

s.shutdown(socket.SHUT_RDWR)
s.close()

