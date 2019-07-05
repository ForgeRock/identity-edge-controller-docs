FROM golang:1.12.6 as builder

RUN go get -d github.com/limaechocharlie/gomozzie
RUN git clone --branch v1.5.8 --depth 1 https://github.com/eclipse/mosquitto.git
ENV CGO_CFLAGS="-I/go/mosquitto/lib -I/go/mosquitto/src" CGO_ENABLED=1
RUN go build -o dist/gomozzie.so -buildmode=c-shared github.com/limaechocharlie/gomozzie

FROM debian:stretch-slim

WORKDIR /mosquitto

# install dependencies
RUN	apt-get update --yes && \
	apt-get install --yes \
	curl \
	vim \
	build-essential \
    libjson-c-dev \
    libssl-dev \
    uuid-dev && \
    apt-get clean --yes

# download mosquitto
RUN	curl http://mosquitto.org/files/source/mosquitto-1.5.8.tar.gz | tar zxf -

# install
RUN	cd mosquitto-1.5.8 && make && make install && cd - && rm -rf mosquitto-1.5.8

# create directories and copy across config and plugin
RUN mkdir -p config plugin log
COPY --from=builder /go/dist/gomozzie.so plugin/
COPY config/mosquitto.conf config/

# add user for mosquitto
RUN	useradd mosquitto && chown -R mosquitto: /mosquitto

VOLUME ["/mosquitto/log"]
CMD ["mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
