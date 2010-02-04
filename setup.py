from distutils.core import setup
import py2exe

setup(
	console = ['server.py'],
	options = {'py2exe': {'compressed': 1,
							'optimize': 1,
							'bundle_files': 1,
							'excludes': ['_ssl',
										'fetch_deps',
										],
							'includes': ['ChanServ',
								'Client',
								'ClientHandler',
								'DataHandler',
								'ip2country',
								'LANUsers',
								'Multiplexer',
								'NATServer',
								'Protocol',
								'SayHooks',
								'SQLUsers',
								'Telnet'],
						}},
	zipfile = None,
	ascii = True,
	)