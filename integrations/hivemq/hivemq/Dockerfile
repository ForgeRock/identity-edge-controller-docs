FROM hivemq/hivemq4:latest

ARG PLUGIN_NAME=hivemq-forgerock-example-extension
ARG PLUGIN_VERSION=0.1

ADD ${PLUGIN_NAME}/target/${PLUGIN_NAME}-${PLUGIN_VERSION}-distribution.zip /opt/hivemq/extensions/
RUN unzip /opt/hivemq/extensions/${PLUGIN_NAME}-${PLUGIN_VERSION}-distribution.zip  -d /opt/hivemq/extensions\
    && rm -f /opt/hivemq/extensions/${PLUGIN_NAME}-${PLUGIN_VERSION}-distribution.zip
