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

# Environment variables
export WORK_DIR="/root/forgerock"

#
# Initialise the SDK. The database needs to be placed in the Java bin directory
# to allow the client process access to it. This has been addressed in OPENIEC-13.
#
function prepare_azure_client() {
    echo "Preparing Azure Client"
    cd ${WORK_DIR}/examples/azure_client
    ../../iecutil -initialise sdk -file sdk-config.json -output ${JAVA_HOME}/bin/iec-sdk.db
    chmod 777 ${JAVA_HOME}/bin/iec-sdk.db
    cd - &>/dev/null
}

#
# Build the Azure Client
#
function build() {
    cd ${WORK_DIR}/examples/azure_client
    mvn clean install
    cd - &>/dev/null
}

#
# Run the Azure Client
#
function run() {
    cd ${WORK_DIR}/examples/azure_client
    mvn exec:java -Dexec.mainClass="org.forgerock.iot.examples.AzureClientExample" -Dorg.slf4j.simpleLogger.defaultLogLevel="off"
    cd - &>/dev/null
}