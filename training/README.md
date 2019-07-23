## ForgeRock Identity Edge Controller Training Environment

### Prerequisites

* ForgeRock BackStage account with access to AM and the IEC
* [Docker](https://docs.docker.com/install/) and [Docker Compose](https://docs.docker.com/compose/install/)
* [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)

### Prepare the environment

Once you have installed the prerequisite software, clone this repository to your local machine and change to the
training directory:

    git clone https://github.com/ForgeRock/identity-edge-controller-docs.git
    cd identity-edge-controller-docs/training/

Download the AM and IEC resources,

* to `am/resources`
  * [Access Management](https://backstage.forgerock.com/downloads/get/familyId:am/productId:am/minorVersion:6.5/version:6.5.0/releaseType:full/distribution:war)
  * [Amster](https://backstage.forgerock.com/downloads/get/familyId:am/productId:amster/minorVersion:6.5/version:6.5.0/releaseType:full/distribution:zip)
  * [IEC AM Plugin](https://backstage.forgerock.com/downloads/get/familyId:edge/productId:iec/subProductId:am-plugin/minorVersion:6.5/version:6.5.0/distribution:tar)
  * [Edge Identity Manager](https://backstage.forgerock.com/downloads/get/familyId:edge/productId:iec/subProductId:manager/minorVersion:6.5/version:6.5.0/distribution:war)
* to `iec/resources`
  * [IEC Service](https://backstage.forgerock.com/downloads/get/familyId:edge/productId:iec/subProductId:service/minorVersion:6.5/version:6.5.0/architecture:x86-64/os:linux/distribution:tar)
* to `sdk/resources`
  * [IEC SDK](https://backstage.forgerock.com/downloads/get/familyId:edge/productId:iec/subProductId:sdk/minorVersion:6.5/version:6.5.0/architecture:x86-64/distribution:tar)

Before you build the docker environment you must add the AM host name to your system's `/etc/hosts` file, for example run:

    echo 127.0.0.1 am.iec.com >> /etc/hosts

### Build and Run

We use `docker-compose` to start containers for AM, IEC Service and IEC SDK on the same network.

Build and start the environment in the background:

    docker-compose up -d --build

There are many ways to interact with the environment after it has started. To see a list of commands run:

    docker-compose --help

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

The resources for installing the IEC AM Plugin are in `/root/forgerock`. Follow the installation instructions
in the [install guide](https://backstage.forgerock.com/docs/iec/6.5/install-guide/#install-AM-plugin) to install the
IEC AM Plugin and configure AM. In order to access AM's admin console and the Edge Identity Manager ensure that the
host system's `/etc/hosts` file contains the network address of the `am` container: `127.0.0.1	am.iec.com`, using
localhost in this case.

If you are already familiar with the installation process then you can quickly prepare a new environment by running
the below command in the container:

    quick_install

This command will perform all the instructions in the installation guide and use Amster to configure AM. It will leave
the environment in the same state as it would be in after manually performing the steps in the installation guide.

### Install and configure the IEC Service

In a new terminal run:

    docker exec -it iec bash

The container has been set up with the following properties:

* IP address: `172.16.0.11`

The resources for installing the IEC Service is in `/root/forgerock`. Follow the installation instructions
in the [install guide](https://backstage.forgerock.com/docs/iec/6.5/install-guide/#installing-iec-service) to configure and install the IEC Service.

If you are already familiar with the installation process then you can quickly prepare a new environment by running
the below command in the container:

    quick_install

This command will perform all the instructions in the installation guide and start the IEC Service. It will leave
the environment in the same state as it would be in after manually performing the steps in the installation guide.

### Install and configure the IEC SDK

In a new terminal run:

    docker exec -it sdk bash

The container has been set up with the following properties:

* IP address: `172.16.0.12`

The resources for installing the IEC SDK are in `/root/forgerock`. Follow the installation instructions
in the [install guide](https://backstage.forgerock.com/docs/iec/6.5/install-guide/#install-client) to configure and install the IEC SDK.

If you are already familiar with the installation process then you can quickly prepare a new environment by running
the following command in the container:

    quick_install

This command will perform all the instructions in the installation guide to unpack the IEC SDK and modify the
configuration for the training environment. It will leave the environment in the same state as it would be in after
manually performing the steps in the installation guide.

### Client application developers guide

Now that all the components are installed and configured, follow the
[developers guide](https://backstage.forgerock.com/docs/iec/6.5/dev-guide) to learn how to build client applications
using the IEC SDK. The developers guide can be used alongside the training environment.
