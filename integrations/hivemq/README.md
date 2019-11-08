## HiveMQ Integration

IN DEVELOPMENT

### Prerequisites

- ForgeRock BackStage account with access to AM, IEC and the Token Validation Microservice.
- [Docker](https://docs.docker.com/install/) and [Docker Compose](https://docs.docker.com/compose/install/)
- ForgeRock IEC Training Environment installed as described in [training](../../training)

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
        --ip 172.16.0.13 --add-host am.iec.com:172.16.0.10 \
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

    docker run --rm  -p 1883:1883 --network training_iec_net \
        --ip 172.16.0.14 --add-host mstokval.example.com:172.16.0.13 \
        --name hivemq -d hivemq

