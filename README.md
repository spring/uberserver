# Project Overview
Uberserver is a lobbyserver written in python for spring lobby clients. It is currently used as the main lobby server running at lobby.springrts.com port 8200.

## Prerequisites
This project is built using Python 3. Make sure you have the following installed before proceeding:
- `Python 3`
- `SQLAlchemy`
- `GeoIP`
- `Twisted`

### System Packages Required
For Debian/Ubuntu:
- `libssl-1.0-dev`
- `libgeoip-dev`
- `libmariadbclient-dev` or `libmysqlclient-dev`

```
# apt update
# apt install libssl1.0-dev libgeoip-dev libmariadbclient-dev
```


## Installation Steps
### Option 1: Manual Installation
1. Clone the uberserver source code:
    ```bash
    git clone git@github.com:spring/uberserver.git
    ```
2. Create a Python virtual environment:
    ```bash
    virtualenv ~/virtenvs/uberserver
    source ~/virtenvs/uberserver/bin/activate
    ```
3. Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4. SQLite is used by default. For production, consider setting up MySQL or PostgreSQL.

### Option 2: Using Docker for Local Server
1. Build and run the local server:
    ```bash
    cd docker
    docker-compose build
    docker-compose up
    ```
2. To find the container ID:
    ```bash
    docker ps
    ```
3. Access the database and add users:
    ```bash
    docker exec -it your_container_id bash
    sqlite3 local_server.db
    ```

4. Use the following command to log in:
    ```bash
    docker logs your_container_id
    ```

The address will look like "private: 192.168.100.17:8200". Use it to log in with `user1/123`.

## Usage
Activate the virtual environment and start the server:
```bash
source ~/virtenvs/uberserver/bin/activate
./server.py
```

## Logs
- Log file: `$PWD/server.log`

## External Documents
Refer to https://springrts.com/wiki/Uberserver for more details.

## Help and Support
For any issues or questions, refer to the server logs or Docker logs. You can also raise issues on the [GitHub Repository](https://github.com/spring/uberserver).




