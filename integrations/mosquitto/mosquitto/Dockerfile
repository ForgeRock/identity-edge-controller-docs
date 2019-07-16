FROM golang:1.12

RUN	apt-get update --yes && \
	apt-get install --yes \
	curl \
	vim \
	build-essential \
    libjson-c-dev \
    libssl-dev \
    uuid-dev && \
    apt-get clean --yes

# download and install mosquitto
RUN	curl http://mosquitto.org/files/source/mosquitto-1.5.8.tar.gz | tar zxf - && \
    cd mosquitto-1.5.8 && make && make install && cd - && rm -rf mosquitto-1.5.8

# get gomozzie plugin for mosquitto
COPY local /go
RUN go get -d github.com/limaechocharlie/gomozzie

WORKDIR /mosquitto

# create directories and copy across config and plugin
RUN mkdir -p config plugin log

# build gomozzie
ENV CGO_CFLAGS="-I/usr/local/include"
ENV CGO_ENABLED=1
RUN go build -o plugin/gomozzie.so -buildmode=c-shared github.com/limaechocharlie/gomozzie

# copy across configuration
COPY config/mosquitto.conf config/

# add a "human" user to the mosquitto password file
RUN touch config/passwd && mosquitto_passwd -b config/passwd human password

# add user for mosquitto
RUN	useradd mosquitto && chown -R mosquitto: /mosquitto

# add the mosquitto library to the path for mosquitto_pub/sub
ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

VOLUME ["/mosquitto/log"]
CMD ["mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
