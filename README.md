# Requirements
- python 2.7
- sqlalchemy
- ip2c
- GeoIP

# Installation
```
# git clone git@github.com:spring/uberserver.git
# virtualenv ~/virtenvs/uberserver
# source ~/virtenvs/uberserver/bin/activate
# pip install SQLAlchemy pycrypto twisted GeoIP
```

Without further configuration this will create a SQLite database (server.db).
Performance will be OK for testing and small setups. For production use,
setup MySQL/PostgreSQL/etc.

# Usage
```
# source ~/virtenvs/uberserver/bin/activate
# ./server.py
```

# Logs
- `$PWD/server.log`
