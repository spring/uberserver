# Requirements
- sqlalchemy
- ip2c

# Installation
```
# git clone git@github.com:spring/uberserver.git
# virtualenv virtenvs/uberserver
# source virtenvs/uberserver/bin/activate
# pip install pycrypto
# pip install SQLAlchemy
```

Without further configuration this will create a SQLite database (server.db).
Performance will be OK for testing and small setups. For production use,
setup MySQL/PostgreSQL/etc.

# Usage

./server.py

# Logs
- `$PWD/server.log`
