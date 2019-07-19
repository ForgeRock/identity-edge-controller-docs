#!/usr/bin/env bash
set -e

#
# Copyright 2019 ForgeRock AS
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

export GOPATH=$(pwd)/dep:$(pwd):${GOPATH}

go get -d -t stash.forgerock.org/iot/identity-edge-controller-core/...
go get -d github.com/eclipse/paho.mqtt.golang

source dep/src/stash.forgerock.org/iot/identity-edge-controller-core/version/platform-linux-x86_64.txt
source dep/src/stash.forgerock.org/iot/identity-edge-controller-core/version/version.txt

go build -ldflags "${VERSION_INFO}" -tags 'logicrichos securerichos' -o dist/device-mqtt forgerock.org/cmd/device-mqtt