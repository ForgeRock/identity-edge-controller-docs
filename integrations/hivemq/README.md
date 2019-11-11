## HiveMQ Integration

IN DEVELOPMENT

### Prerequisites

- ForgeRock BackStage account with access to AM, IEC and the Token Validation Microservice.
- [Docker](https://docs.docker.com/install/) and [Docker Compose](https://docs.docker.com/compose/install/)
- ForgeRock IEC Training Environment installed as described in [training](../../training)

### Register an OAuth2 Client

Register an OAuth 2.0 client with the AM OAuth 2.0 authorisation service that is allowed to introspect access tokens
issued to other clients in the `edge` realm:

1. In the AM console, navigate to the OAuth2 client applications
[view](http://am.iec.com:8080/openam/XUI/#realms/%2Fedge/applications-oauth2) for the `edge` realm.
Ensure the *Clients* tab is selected.
1. Select *Add Client*
1. Enter the following values:
	* Client ID: `mqtt_oidc_client`
	* Client Secret: `password`
	* Scope(s): `am-introspect-all-tokens`
1. Select *Create*

Refer to the AM documentation for more information about
[registering](https://backstage.forgerock.com/docs/am/6.5/oauth2-guide/#register-oauth2-client) and
[configuring](https://backstage.forgerock.com/docs/am/6.5/oauth2-guide/#configure-oauth2-client) OAuth2 Clients.

### Prepare the environment

Download the Token Validation Microservice resources,

* to `mstokval/resources`
  * [Token Validation Microservice](https://backstage.forgerock.com/downloads/browse/ig/latest)

### Build and run the Token Validation Microservice container

Build a container that has the ForgeRock Token Validation Microservice installed with all the relevant
configuration to introspect tokens against the AM in the the training environment:

    cd mstokval
    docker build -t mstokval .
    cd -

Run the `mstokval` container:

    docker run --rm  -p 9090:9090 --network training_iec_net \
        --ip 172.16.0.14 --add-host am.iec.com:172.16.0.10 \
        --name mstokval -d mstokval

### Build and package the HiveMQ ForgeRock Example Extension

Build the ForgeRock Example Extension for HiveMQ:

    cd hivemq/hivemq-forgerock-example-plugin
    mvn clean
    mvn package
    cd -

### Build and run the HiveMQ container

Build a container that contains a HiveMQ server with the ForgeRock Example Extension installed:

    cd hivemq
    docker build -t hivemq .
    cd -

Run the `hivemq` container:

    docker run --rm  -p 1883:1883 -p 8090:8080 --network training_iec_net \
        --ip 172.16.0.13 --add-host mstokval.example.com:172.16.0.14 \
        --name hivemq -d hivemq

You can check that HiveMQ is running by navigating to the HiveMQ Control Center at `http://localhost:8090/`.
The default login is the username `admin` with the password `hivemq`.

### Build and run the example device mqtt client

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
1. connect the MQTT client to HiveMQ
1. HiveMQ passes the client credentials to the HiveMQ ForgeRock Example Extension.
    1. The extension will call out to the Token Validation Microservice with the access token.
    1. The Token Validation Microservice returns the introspection of the access token.
    1. If the token is valid and has the correct scopes, then the connection is authorised.
1. in publish mode, the client will publish dummy telemetry every two seconds to the topic.
1. or in subscribe mode, the client will subscribe to the topic and print out any received messages.
1. the client runs a process that reconnects the MQTT client when the access token expires.
Triggering a call out to the IEC to provide new credentials.

### Communicate with the example device in subscriber mode

It is possible to send a message to the example device over MQTT from the command line on the host machine.
The following assumes that the host machine has the following:

* curl
* jq
* mosquitto client (any MQTT client can be used)

An OAuth 2.0 access token is required to connect\publish to the MQTT server, so create an OAuth 2.0 client to
request access tokens:

1. In the AM console, navigate to the OAuth2 client applications
[view](http://am.iec.com:8080/openam/XUI/#realms/%2Fedge/applications-oauth2) for the `edge` realm.
Ensure the *Clients* tab is selected.
1. Select *Add Client*
1. Enter the following values:
    * Client ID: `human_client`
    * Client secret: `password`
    * Scope(s): `mqtt`
1. Select *Create*
1. On the Advanced tab, select the following option:
    * Grant Types: `Client Credentials`
1. Select *Save Changes*

Request a token:

    human_token=$(curl --request POST \
        --url http://am.iec.com:8080/openam/oauth2/realms/root/realms/edge/introspect/access_token \
        --user human_client:password \
        --data grant_type=client_credentials  \
        --data scope=mqtt \
        --silent | jq -r .access_token)

Send a message to the subscribed device:

    mosquitto_pub -t /devices/wildcat \
        -u human -P ${human_token} \
        -m "hello from the human"