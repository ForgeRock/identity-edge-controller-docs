FROM golang:1.12.3-stretch

RUN apt-get update --yes && \
    apt-get install --yes \
    curl \
    build-essential \
    libtool \
    autoconf \
    automake \
    vim && \
    apt-get clean --yes

# Add IEC resources
WORKDIR /root/forgerock
COPY resources/iec-sdk-linux-x86_64-lr-richos-*.tgz .

# Add C client examples
COPY examples ./examples

# Add helper commands
ADD commands.sh /opt/forgerock/iec/commands.sh
RUN chmod a+x /opt/forgerock/iec/commands.sh
RUN /bin/bash -c "echo \"source /opt/forgerock/iec/commands.sh\" >> /root/.bashrc"

# Install SDK dependencies on container for compiling Golang client applications
ADD https://github.com/jedisct1/libsodium/releases/download/1.0.15/libsodium-1.0.15.tar.gz .
RUN tar xf libsodium-1.0.15.tar.gz && \
    cd libsodium-1.0.15 && \
    ./configure && \
    make install
ADD https://github.com/zeromq/libzmq/releases/download/v4.2.2/zeromq-4.2.2.tar.gz .
RUN tar xf zeromq-4.2.2.tar.gz && \
    cd zeromq-4.2.2 && \
    ./autogen.sh && \
    ./configure --with-libsodium --without-docs --enable-drafts && \
    make install
ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

# Set bash as the default command in the new container
CMD ["bash"]
