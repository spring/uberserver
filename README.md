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

# Run local server via Docker
Build and run local server
```
$ cd docker
$ docker-compose build
$ docker-compose up
```
To obtain container id execute and search for uberserver
```
$ docker ps
```
Adding users. Directory will be /root/uberserver.
```
$ docker exec -it your_container_id bash
$ sqlite3 local_server.db
```
Add user to the database. Choose name you prefer to login. Role can be changed, see predefined values in the server code. Password will be 123. E-mail can be arbitrary, but uniq.
```
insert into users(username, password, register_date, ingame_time, access, email, bot) values ('user1', 'ICy5YqxZB1uWSwcVLSNLcA==', DATE('NOW'), 0, 'user', 'user1@mail.com', 0);
```
Use your local machine address or find private uberserver address via Docker logs command
```
$ docker logs your_container_id
```
The address looks like "private: 192.168.100.17:8200"
For now you can login to local uberserver 192.168.100.17:8200 user/password user1/123
