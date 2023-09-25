FROM ubuntu:22.04
RUN apt-get update -y

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get install -y software-properties-common \
                    wget \
                    python3-pip \
                    python3-venv \
                    python3-dev \
                    build-essential \
                    libssl-dev \
                    libffi-dev \
                    make \
                    vim \
                    git \
                    openssl \
                    autogen \
                    libssl-dev \
                    less \
                    mysql-server \
                    libmysqlclient-dev \
                    libgeoip-dev \
                    default-libmysqlclient-dev \
                    pkg-config \
                    sqlite3

RUN cd /root && \
    git clone https://github.com/a-pavlov/uberserver.git && \
    cd uberserver && \
    echo "GeoIP==1.3.2\n#mysqlclient==1.3.10\npyOpenSSL==23.0.0\nSQLAlchemy==1.3.0\nTwisted==22.10.0" > ./requirements.txt && \
    pip install -r requirements.txt

WORKDIR "/root/uberserver"

ENTRYPOINT [ "./server.py", "-s", "sqlite:///local_server.db" ]
