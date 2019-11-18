/*
 * Copyright 2019 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <mosquitto.h>

#include <libiecclient.h>

const bool debug = false;

#define DEVICE_ID "bongo"
#define CLIENT_ID DEVICE_ID"_client"
#define CLIENT_LOG CLIENT_ID".log"

/* MQTT connection parameters */
#define MQTT_HOST "172.16.0.13"
#define MQTT_PORT 1883
#define MQTT_KEEPALIVE 100
#define MQTT_TOPIC "device/data"
#define MQTT_QOS 2
#define MESSAGE_LENGTH 4

typedef struct {
    bool received_connack;
    bool connected;
    unsigned int pub_count;
} mqtt_client_data;

/**
 * get_access_token gets an OAuth 2.0 access token from the ForgeRock Platform
 */
int get_access_token(char** access_token){
    int result;
    char* tokens;
    printf("Requesting access token for device (id: %s)... ", DEVICE_ID);
    result = iec_device_tokens(DEVICE_ID, &tokens);
    if (result < 0) {
        char* error = iec_last_error();
        printf("Access token request failed: %s\n", error);
        free(error);
        return result;
    }
    printf("Done\n");

    if (iec_json_parse(tokens) != 0 || iec_json_get_string("access_token", access_token) != 0 ) {
        char* error = iec_last_error();
        printf("Failed to extract access token: %s\n", error);
        free(error);
        return -1;
    }
    printf("access token: %s\n", *access_token);
    return result;
}

/**
 * mosq_log_cb is a logging callback function for the mosquitto client
 */
void mosq_log_cb(__attribute__((unused)) struct mosquitto *mosq, __attribute__((unused)) void *userdata, int level, const char *str)
{
    const char* log_level;
    switch(level){
        case MOSQ_LOG_DEBUG:
            log_level = "DEBUG";
            break;
        case MOSQ_LOG_INFO:
            log_level = "INFO";
            break;
        case MOSQ_LOG_NOTICE:
            log_level = "NOTICE";
            break;
        case MOSQ_LOG_WARNING:
            log_level = "WARNING";
            break;
        case MOSQ_LOG_ERR:
            log_level = "ERR";
            break;
    }
    printf("MOSQ LOG %s: %s\n", log_level, str);
}

/**
 * mosq_publish_cb defines a publish callback function
 * This is called when a message initiated with mosquitto_publish has been sent to the broker successfully
 */
void mosq_publish_cb(__attribute__((unused)) struct mosquitto *mosq, void *userdata, int mid)
{
    mqtt_client_data *mdata = (mqtt_client_data*) userdata;
    mdata->pub_count++;
    printf("Published (mid: %d)\n", mid);
}

/**
 * mosq_connect_cb is a connection response callback for the mosquitto client
 */
void mosq_connect_cb(struct mosquitto *mosq, void *userdata, int result)
{
    mqtt_client_data *data = (mqtt_client_data*) userdata;
    if( debug ) printf("MOSQ CONNECT: %d\n", result);
    data->received_connack = true;
    data->connected = result == 0;     // result code is 0 if connection was a success
}

/**
 * mosq_disconnect_cb is a disconnect callback for the mosquitto client
 */
void mosq_disconnect_cb(struct mosquitto *mosq, __attribute__((unused)) void *userdata, int result)
{
    char* access_token;
    printf("Client has become disconnected from MQTT server: %d\n", result);
    if( result != 0){
        // disconnect initiated by the server, try to reconnect
        result = get_access_token(&access_token);
        if (result < 0) {
            return;
        }
        /* use the access token as the password */
        mosquitto_username_pw_set(mosq, "unused", access_token);
        // disconnected by server, try to reconnect
        mosquitto_reconnect_async(mosq);
    }
}

/**
 * wait_for_connack will wait until a connection acknowledgement is received
 */
int wait_for_connack(mqtt_client_data* data)
{
    printf( "Waiting for connection acknowledgment");
    int loop = 0;
    do {
        sleep(1);
        printf(".");
        fflush(stdout);
        if( loop ++ > 60 )
        {
            printf( " No ACK from server\n");
            return 1;
        }
    }
    while( !data->received_connack );
    printf(" Received\n");
}

int main()
{
    int result;
    char* access_token;
    struct mosquitto *mosq = NULL;
    mqtt_client_data mdata = {}; /* use mqtt_client_data to hold callback data. */
    char message[MESSAGE_LENGTH];

    printf("\n*** Running device_mqtt_pub\n\n");
    printf("* Publishes messages to a MQTT server\n");
    printf("* using an OAuth 2.0 access token obtained from the IEC\n\n");

    printf("Setting attributes ... ");
    if ( iec_set_attribute(IEC_ENDPOINT, "tcp://172.16.0.11:5556") < 0
        || iec_set_attribute(IEC_SECRETKEY, "zZZfS7BthsFLMv$]Zq{tNNOtd69hfoBsuc-lg1cM") < 0
        || iec_set_attribute(IEC_PUBLICKEY, "uH&^{aIzDw5<>TRbHcu0q#(zo]uLl6Wyv/1{/^C+") < 0
        || iec_set_attribute(IEC_SERVERPUBLICKEY, "9m27tKf3aoNWQ(G-f[>W]gP%f&+QxPD:?mX*)hdJ") < 0
        || iec_set_attribute(IEC_MSGTIMEOUTSEC, "5") < 0
        || iec_set_attribute(IEC_CLIENT_ID, CLIENT_ID) < 0
        || iec_set_attribute(IEC_LOGGING_ENABLED, "true") < 0
        || iec_set_attribute(IEC_LOGGING_DEBUG, "true") < 0
        || iec_set_attribute(IEC_LOGGING_LOGFILE, CLIENT_LOG) < 0
     ) {
        char* error = iec_last_error();
        printf("Attribute setting failed: %s\n", error);
        free(error);
        return result;
    }
    printf("Done\n");

    printf("Initialising sdk... ");
    result = iec_initialise();
    if (result < 0) {
        char* error = iec_last_error();
        printf("Initialisation request failed: %s\n", error);
        free(error);
        return result;
    }
    printf("Done\n");

    /* Initialize the Mosquitto library */
    printf("Initialising mosquitto... ");
    mosquitto_lib_init();
    printf("Done\n");

    printf("Registering device (id: %s)... ", DEVICE_ID);
    result = iec_device_register(DEVICE_ID, NULL);
    if (result < 0) {
        char* error = iec_last_error();
        printf("Registration request failed: %s\n", error);
        free(error);
        return result;
    }
    printf("Done\n");

    result = get_access_token(&access_token);
    if (result < 0) {
        return result;
    }

    /* create a new Mosquitto runtime instance with a random client ID */
    mosq = mosquitto_new(DEVICE_ID, true, &mdata);
    if (!mosq) {
        printf("Can't create Mosquitto instance\n");
        return -1;
    }

    /* set callbacks */
    if( debug ) mosquitto_log_callback_set(mosq, mosq_log_cb);
    mosquitto_publish_callback_set(mosq, mosq_publish_cb);
    mosquitto_connect_callback_set(mosq, mosq_connect_cb);
    mosquitto_disconnect_callback_set(mosq, mosq_disconnect_cb);

    /* use the access token as the password */
    mosquitto_username_pw_set(mosq, "unused", access_token);

    /* start a new thread to process network traffic */
    mosquitto_loop_start(mosq);

    /* connect to the MQTT server */
    result = mosquitto_connect_async(mosq, MQTT_HOST, MQTT_PORT, MQTT_KEEPALIVE);
    if (result != 0) {
        printf("Can't connect to MQTT server\n");
        mosquitto_destroy(mosq);
        return -1;
    }

    /* wait for connection acknowledgement */
    wait_for_connack(&mdata);

    /* check that connection was successful */
    if (!mdata.connected) {
        printf("Unable to connect\n");
        mosquitto_loop_stop(mosq, false);
        mosquitto_destroy(mosq);
        return -1;
    }

    /* start publishing messages to the topic */
    printf("Start publishing\n");
    for(int i=0; i<=1000; i++){
        sprintf(message, "%c", 'a'+(i%26));
        int mid = 0;
        result = mosquitto_publish(mosq, &mid, MQTT_TOPIC, MESSAGE_LENGTH, message, MQTT_QOS, true);
        if (result != 0) {
            printf("Can't publish to MQTT server\n");
            mosquitto_disconnect(mosq);
            mosquitto_loop_stop(mosq, false);
            mosquitto_destroy(mosq);
            return -1;
        }
        printf("Publishing (mid: %d) \"%s\"... ", mid, message);
        sleep(1);
    }
    printf("Done\n");

    /* give some time for network operations to finish */
    sleep(2);

    /* tidy up */
    mosquitto_disconnect(mosq);
    mosquitto_loop_stop(mosq, false);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    free(access_token);

    printf("\n*** Completed device_mqtt_pub\n\n");
    return result;
}
