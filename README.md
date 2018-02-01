# Requirements
- python 3
- sqlalchemy
- GeoIP
- twisted

# Installation

Install OpenSSL, Geoip headers. Optional MariaDB | Mysql client headers

Debian / Ubuntu:

- libssl-1.0-dev
- libgeoip-dev
- libmariadbclient-dev | libmysqlclient-dev

```
# apt update
# apt install libssl1.0-dev libgeoip-dev libmariadbclient-dev
```


Clone uberserver sources


```
$ git clone git@github.com:spring/uberserver.git
```

Create a Python virtualenv

```
$ virtualenv ~/virtenvs/uberserver
$ source ~/virtenvs/uberserver/bin/activate
```

Install Python requirements

```
$ pip install -r requirements.txt
```

Without further configuration this will create a SQLite database (server.db).
Performance will be OK for testing and small setups. For production use,
setup MySQL/PostgreSQL/etc.

# Usage
```
$ source ~/virtenvs/uberserver/bin/activate
$ ./server.py
```

# Logs
- `$PWD/server.log`
