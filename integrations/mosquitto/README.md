## Mosquitto Integration
### Introduction

TBD

### Prerequisites

- ForgeRock BackStage account with access to AM, DS and the IEC
- [Docker](https://docs.docker.com/install/) and [Docker Compose](https://docs.docker.com/compose/install/)
- ForgeRock IEC Training Environment installed as described in [training](../../training)

### Build and run the mosquitto container

Build a container that has the Mosquitto server and the AM Mosquitto plugin (gomozzie) installed with all the relevant
configuration for Mosquitto to communicate with the training environment:

	cd mosquitto 	
	docker build -t mosquitto .
	cd -

Run the `mosquitto` container in the background:

	docker run --rm -v $(pwd)/log:/mosquitto/log \
		-p 1883:1883 --network training_iec_net \
		--ip 172.16.0.13 --add-host am.iec.com:172.16.0.10 \
		--name mosquitto -d mosquitto
		
The debug logs for the broker (mosquitto.log) and the plugin (gomozzie.log) will appear in the `mosquitto/log` folder.
Confirm that the server has started correctly:

	cat mosquitto/log/mosquitto.log
	
	1563543348: mosquitto version 1.5.8 starting

### Modify the OAuth2 Client Group

Authentication and authorisation within the Mosquitto plugin is controlled by OAuth 2.0 access token scopes.
To ensure that all devices get this authority by default, modify the `DeviceOAuth2Group` OAuth 2.0 group in AM. 

1. Open the `DeviceOAuth2Group` [editor](http://am.iec.com:8080/openam/XUI/#realms/%2Fedge/applications-oauth2/groups/edit/DeviceOAuth2Group)
in the AM Admin Console.
1. Add `mqtt:write:#` to *Scope(s)* and *Default Scope(s)*.
1. Add `mqtt:read:#` to *Scope(s)* and *Default Scope(s)*.
1. Click *Save Changes*.

### Modify the OAuth2 Service

In order to make a running example client more responsive to OAuth2 client changes, it is recommended that the lifetime
of an access token is decreased for this example.

1. Open the OAuth2 [provider](http://am.iec.com:8080/openam/XUI/#realms/%2Fedge/services/edit/oauth-oidc) 
in the AM Admin Console.
1. Change *Access Token Lifetime (seconds)* to `20`.
1. Click *Save Changes*.
 

### Build and run the example client

Copy the Go client examples into the `sdk` container:

	docker cp ../../examples/go sdk:/root/forgerock/go-examples

Enter the `sdk` container:

    docker exec -it sdk bash

Build the client application:

    cd ~/forgerock/go-examples
    ./build-mqtt-device.sh

Run the client application in publisher mode:

    ./dist/device-mqtt --deviceID wildcat
    
Use the subscriber flag to run in subscriber mode:

    ./dist/device-mqtt --subscribe --deviceID wildcat
    
In both cases a topic name (or topic filter for the subscribe mode) can be supplied via the topic flag.
The default topic is `/devices/{deviceID}`.

This example will:
1. register a device (with deviceID) with AM via the IEC.
1. create a MQTT client that uses the IEC as a credentials provider. 
1. connect the MQTT client to the Mosquitto broker
1. Mosquitto passes the client credentials to the AM auth plugin. 
The plugin will call out to AM to introspect the access token.
If the token is valid and has the correct scopes, the data is cached and the connection is authorised. 
1. in publish mode, the client will publish dummy telemetry every two seconds to the topic.
1. or in subscribe mode, the client will subscribe to the topic and print out any received messages.
1. the client runs a process that reconnects the MQTT client when the access token expires.
Triggering a call out to the IEC to provide new credentials.

### Communicate with the example client

A single `human` user has been added to the internal Mosquitto database to enable communication with the device.

The `human` user can only connect from within the `mosquitto` container:

	docker exec -it mosquitto bash
	
Use mosquitto_sub to listen to a publishing device:	

	mosquitto_sub -p 1884 -u human -P password -t /devices/#

and mosquitto_pub to send a message to a device in subscribe mode:	

	mosquitto_pub -p 1884 -u human -P password -t /devices/wildkat -m hello
