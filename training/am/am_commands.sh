#!/bin/bash

# AM configuration variables
export AM_HOST="am.iec.com"
export AM_URL="http://${AM_HOST}:8080/openam"
export AM_HOME="/root/openam"
export AM_PASSWORD="password"
export AMSTER_HOME="/opt/forgerock/amster"

# Environment variables
export TOMCAT_HOME="/usr/local/tomcat"
export JAVA_HOME="/docker-java-home/jre"

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
# Add AM host to /etc/hosts if it's not already there
#
function configure_host() {
    if [[ $(cat /etc/hosts | grep "${AM_HOST}") == "" ]]; then
        echo 127.0.0.1 "${AM_HOST}" >> /etc/hosts
    fi
}

#
# Start tomcat and install AM with Amster
#
function install_am() {
    configure_host
    start_tomcat

    echo "Installing OpenAM"
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
# Add commands to bashrc to modify the container startup
#
function modify_startup() {
    # install the am_commands.sh file so that it is sourced when entering bash
    echo "# source the AM commands file" >> /root/.bashrc
    echo "source /opt/forgerock/am/am_commands.sh" >> /root/.bashrc

    # Add the AM host to the hosts file
    echo "# Add the AM host to the hosts file if it's not there already" >> /root/.bashrc
    echo "if ! (grep -q '${AM_HOST}' /etc/hosts); then" >> /root/.bashrc
    echo "    echo 127.0.0.1 ${AM_HOST} >> /etc/hosts" >> /root/.bashrc
    echo "fi" >> /root/.bashrc
}
