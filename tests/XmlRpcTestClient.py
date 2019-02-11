#!/usr/bin/env python3
# coding=utf-8
# This file is part of the uberserver (GPL v2 or later), see LICENSE

import xmlrpc.client

proxy = xmlrpc.client.ServerProxy("http://localhost:8300/")

print(proxy.get_account_info("ubertest01", "KeepItSecretKeepItSafe01"))
print(proxy.get_account_info("doesn'texist", "nope"))
print(proxy.get_account_id("ubertest01"))
