#!/usr/bin/env python
# coding=utf-8
# This file is part of the uberserver (GPL v2 or later), see LICENSE

import xmlrpclib

proxy = xmlrpclib.ServerProxy("http://localhost:8300/")
print(proxy.get_account_info("ubertest01", "KeepItSecretKeepItSafe01"))
print(proxy.get_account_info("doesn'texist", "nope"))


