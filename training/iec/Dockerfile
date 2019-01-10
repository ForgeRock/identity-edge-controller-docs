#
# Copyright 2019 ForgeRock AS. All Rights Reserved
#
# Use of this code requires a commercial software license with ForgeRock AS.
# or with one of its affiliates. All use shall be exclusively subject
# to such license between the licensee and ForgeRock AS.
#

FROM ubuntu:16.04

RUN apt-get update --yes && \
    apt-get install --yes \
    curl \
    vim && \
    apt-get clean --yes

# Add IEC resources
WORKDIR /root/forgerock
COPY resources/iec-edge-*-service-linux-x86_64-lr-richos.tar .

# Set bash as the default command in the new container
CMD ["bash"]