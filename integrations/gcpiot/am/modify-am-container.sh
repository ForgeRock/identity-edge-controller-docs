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

function add_gcp_client_libraries() {
	curl -O -J -L https://developers.google.com/resources/api-libraries/download/cloudiot/v1/java
	unzip google-api-services-cloudiot-v1-*.zip
	cp cloudiot/google-api-services-cloudiot-v1-*.jar ${TOMCAT_HOME}/webapps/openam/WEB-INF/lib/
	cp cloudiot/libs/* ${TOMCAT_HOME}/webapps/openam/WEB-INF/lib/
	rm -rf cloudiot
}

source /root/.bashrc
add_gcp_client_libraries
restart_tomcat


