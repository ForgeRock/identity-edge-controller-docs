FROM ubuntu:16.04

RUN apt-get update --yes && \
    apt-get install --yes \
    curl \
    build-essential \
    vim && \
    apt-get clean --yes

# Add IEC resources
WORKDIR /root/forgerock
COPY resources/iec-sdk-linux-x86_64-lr-richos-*.tgz .
ADD commands.sh /opt/forgerock/iec/commands.sh
RUN chmod a+x /opt/forgerock/iec/commands.sh
RUN /bin/bash -c "echo \"source /opt/forgerock/iec/commands.sh\" >> /root/.bashrc"

# Set bash as the default command in the new container
CMD ["bash"]
