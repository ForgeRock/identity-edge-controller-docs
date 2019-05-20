#!/bin/bash

#
# Copyright 2019 ForgeRock AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# AM configuration variables
export AM_HOST="am.iec.com"
export AM_URL="http://${AM_HOST}:8080/openam"
export AM_HOME="/root/openam"
export AM_PASSWORD="password"
export AMSTER_HOME="/opt/forgerock/amster"

# Environment variables
export TOMCAT_HOME="/usr/local/tomcat"
export JAVA_HOME="/docker-java-home/jre"
export WORK_DIR="/root/forgerock"

#
# Start tomcat and wait until startup is complete
#
function start_tomcat() {
    # Clean the logs so we don't read the previous startup message
	rm -f ${TOMCAT_HOME}/logs/catalina.out

    # Start tomcat
    ${TOMCAT_HOME}/bin/catalina.sh start

    # Wait for tomcat to complete startup
    count=30
    printf "\nWaiting for server startup"
    while [[ -z "$(cat ${TOMCAT_HOME}/logs/catalina.out | grep "Server startup")" && count -gt 0 ]]; do
        sleep 2 && printf "."
        ((count--))
    done

    # If tomcat does not start in 1 minute then kill the process and cat the log
    if [[ count -eq 0 ]]; then
        printf "\nServer failed to startup normally. Tomcat log:\n\n"
        cat ${TOMCAT_HOME}/logs/catalina.out
        pkill -9 -f tomcat
    else
        printf "\nServer started\n"
    fi
}

#
# Stop tomcat and wait until shutdown is complete
#
function stop_tomcat() {
    # Stop tomcat
    ${TOMCAT_HOME}/bin/catalina.sh stop

    # Wait for tomcat to complete shutdown
    count=30
    printf "\nWaiting for server shutdown"
    while [[ -z "$(cat ${TOMCAT_HOME}/logs/catalina.out | grep "Destroying ProtocolHandler")" && count -gt 0 ]]; do
        sleep 2 && printf "."
        ((count--))
    done

    # If tomcat does not stop in 1 minute then kill the process and cat the log
    if [[ count == 0 ]]; then
        echo "Server failed to shutdown normally. Tomcat log:\n\n"
        cat ${TOMCAT_HOME}/logs/catalina.out
        pkill -9 -f tomcat
    else
        printf "\nServer stopped\n"
    fi
}

#
# Restart tomcat
#
function restart_tomcat() {
    stop_tomcat
    sleep 5
    start_tomcat
}

#
# Start tomcat and install AM with Amster
#
function install_am() {
    start_tomcat

    echo "Installing AM"
    cd ${AMSTER_HOME}
    ./amster install-am.amster -D AM_URL=${AM_URL} -D AM_PASSWORD=${AM_PASSWORD} -D AM_HOME=${AM_HOME}
    # Execute and notify the caller if this fails.
    if [[ $? -ne 0 ]]; then
        echo "Amster Installation failed"
        exit 1
    fi
    cd - &>/dev/null
}

#
# Extract plugin tarball and copy IEC Plugin libs to AM
#
function install_iec_plugin() {
    echo "Installing IEC Plugin"
    cd ${WORK_DIR}
    tar -xzf iec-am-plugin-*.tgz
    cp am-iec-plugin-*.jar ${TOMCAT_HOME}/webapps/openam/WEB-INF/lib
    cp config/* ${TOMCAT_HOME}/webapps/openam/config/auth/default
    cd - &>/dev/null
}

#
# Modify DS configuration and add IoT identity attributes
#
function configure_ds() {
    echo "Configuring DS"
    ${AM_HOME}/opends/bin/dsconfig set-global-configuration-prop \
    --set single-structural-objectclass-behavior:accept \
    -p 4444 -X -D "cn=Directory Manager" -w "${AM_PASSWORD}" -n

    ${AM_HOME}/opends/bin/ldapmodify --port 50389 --hostname localhost \
    --bindDN "cn=Directory Manager" --bindPassword ${AM_PASSWORD} \
    ${WORK_DIR}/ds/iot-device.ldif
}

#
# Use Amster to import training configuration for AM
#
function configure_am() {
    echo "Configuring AM"
    cd ${AMSTER_HOME}
    ./amster import-config.amster \
        -D AM_URL=${AM_URL} \
        -D AM_HOST=${AM_HOST} \
        -D AMSTER_KEY=${AM_HOME}/amster_rsa \
        -D AM_CONFIG_PATH=/opt/forgerock/am/configuration
    cd - &>/dev/null
}

#
# Copy Edge Identity Manager to tomcat
#
function install_edge_id_manager() {
    echo "Installing Edge Identity Manager"
    cd ${WORK_DIR}
    cp edge-identity-manager-*.war ${TOMCAT_HOME}/webapps/identitymanager.war
    cd - &>/dev/null
}

#
# Quick install will bring the cloud environment to the state
# it would be in after the installation guide has been completed
#
function quick_install() {
    install_iec_plugin
    start_tomcat
    configure_ds
    configure_am
    install_edge_id_manager
    restart_tomcat
}
