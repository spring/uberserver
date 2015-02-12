#!/usr/bin/env python
# coding=utf-8

import xmlrpclib

proxy = xmlrpclib.ServerProxy("http://localhost:8300/")
print(proxy.get_account_info("testing", "test"))


