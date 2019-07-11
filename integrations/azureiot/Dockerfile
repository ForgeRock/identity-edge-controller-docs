FROM maven:3.6.1-jdk-11-slim

# Add IEC SDK
WORKDIR /root/forgerock
ADD resources/iec-sdk-linux-x86_64-lr-richos-*.tgz .

# Add the edge client example code
COPY examples/azure_client examples/azure_client

# Add helper commands
ADD commands.sh /opt/forgerock/iec/commands.sh
RUN chmod a+x /opt/forgerock/iec/commands.sh
RUN /bin/bash -c "echo \"source /opt/forgerock/iec/commands.sh\" >> /root/.bashrc"

# Set the C library path, which will be picked up by the Java process
ENV LD_LIBRARY_PATH="/root/forgerock/lib"

# Prepare the SDK
RUN /bin/bash -c "source /opt/forgerock/iec/commands.sh && prepare_azure_client"

# Set bash as the default command in the new container
CMD ["bash"]
