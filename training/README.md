## ForgeRock Identity Edge Controller Training Environment

### Prerequisites

* ForgeRock BackStage account with access to AM, DS and the IEC
* [Docker](https://docs.docker.com/install/) and [Docker Compose](https://docs.docker.com/compose/install/)

### Prepare the environment

Download the AM and IEC resources,

* to `am/resources`
  * [Access Management](https://backstage.forgerock.com/downloads/get/familyId:am/productId:am/minorVersion:6.5/version:6.5.0/releaseType:full/distribution:war)
  * [Amster](https://backstage.forgerock.com/downloads/get/familyId:am/productId:amster/minorVersion:6.5/version:6.5.0/releaseType:full/distribution:zip)
  * [AM Plugin for the IEC](http://abondance.internal.forgerock.com/pkg/servers/forgerock/IEC/6.5.0/iec-am-plugin-6.5.0.tgz)
  * [Edge Identity Manager](http://abondance.internal.forgerock.com/pkg/servers/forgerock/IEC/6.5.0/edge-identity-manager-6.5.0.war)
* to `iec/resources`
  * [IEC Service](http://abondance.internal.forgerock.com/pkg/servers/forgerock/IEC/6.5.0/iec-service-linux-x86_64-lr-richos-6.5.0.tgz)
* to `sdk/resources`
  * [IEC SDK](http://abondance.internal.forgerock.com/pkg/servers/forgerock/IEC/6.5.0/iec-sdk-linux-x86_64-lr-richos-6.5.0.tgz)

### Build and Run

We use `docker-compose` to start containers for AM, IEC Service and IEC SDK on the same network.

Build and start the environment in the background:

    docker-compose up -d --build

Stop the environment:

    docker-compose down


### Install and configure AM

In a new terminal run:

    docker exec -it am bash

The Tomcat server will not start up by default. To control the server you can use the bash functions:

* `start_tomcat`
* `stop_tomcat`
* `restart_tomcat`

The container has been set up with the following properties:

* IP address: `172.16.0.10`
* AM URL: `http://am.iec.com:8080/openam`
* AM admin username: `amadmin`
* AM admin password: `password`

The resources for installing the AM plugin for the IEC is in `/root/forgerock`. Follow the installation instructions
in the [Installation Guide](../docs/iec-installation-guide.md) to install the plugin and configure AM. In order to access AM's admin console and the Edge Identity Manager ensure that the host system's `/etc/hosts` file contains the network address of the `am` container: `172.16.0.10 am.iec.com`.

### Install and configure the IEC Service

In a new terminal run:

    docker exec -it iec bash

The resources for installing the IEC Service is in `/root/forgerock`. Follow the installation instructions
in the [Installation Guide](../docs/iec-installation-guide.md) to configure and install the service.

The container has been set up with the following properties:

* IP address: `172.16.0.11`

### Install and configure the IEC SDK

In a new terminal run:

    docker exec -it sdk bash

The resources for installing the IEC SDK is in `/root/forgerock`. Follow the installation instructions
in the [Installation Guide](../docs/iec-installation-guide.md) to configure and install the SDK.

The container has been set up with the following properties:

* IP address: `172.16.0.12`
