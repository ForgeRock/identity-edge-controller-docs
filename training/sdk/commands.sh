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
# Unpack IEC SDK and modify configuration
#
function prepare_iec_sdk() {
    echo "Preparing IEC SDK"
    cd ${WORK_DIR}
    tar -xzf iec-sdk-*.tgz
    sed -i 's/127.0.0.1/172.16.0.11/g' sdk-config.json examples/*/*.c
    cd - &>/dev/null
}

#
# Quick install will bring the gateway environment to the state
# it would be in after the installation guide has been completed
#
function quick_install() {
	prepare_iec_sdk
}
