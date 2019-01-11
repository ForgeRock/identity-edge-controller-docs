FROM ubuntu:16.04

RUN apt-get update --yes && \
    apt-get install --yes \
    curl \
    vim && \
    apt-get clean --yes

# Add IEC resources
WORKDIR /root/forgerock
COPY resources/iec-service-linux-x86_64-lr-richos-*.tgz .

# Set bash as the default command in the new container
CMD ["bash"]
