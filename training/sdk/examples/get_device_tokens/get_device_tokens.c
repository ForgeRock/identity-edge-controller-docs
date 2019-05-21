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
#include <stdlib.h>

#include <libiecclient.h>

int main() {
    int result = -1;
    char deviceId[] = "Rhino";
    char* registrationData = NULL;

    printf("\n*** Registering a device\n");
    printf("*** SDK function(s): iec_initialise, iec_device_register, iec_device_tokens, iec_json_*\n\n");

    printf("Setting dynamic attributes... ");
    if( iec_set_attribute(IEC_ENDPOINT, "tcp://172.16.0.11:5556") < 0
        || iec_set_attribute(IEC_SECRETKEY, "zZZfS7BthsFLMv$]Zq{tNNOtd69hfoBsuc-lg1cM") < 0
        || iec_set_attribute(IEC_PUBLICKEY, "uH&^{aIzDw5<>TRbHcu0q#(zo]uLl6Wyv/1{/^C+") < 0
        || iec_set_attribute(IEC_SERVERPUBLICKEY, "9m27tKf3aoNWQ(G-f[>W]gP%f&+QxPD:?mX*)hdJ") < 0
        || iec_set_attribute(IEC_MSGTIMEOUTSEC, "5") < 0
        || iec_set_attribute(IEC_CLIENT_ID, "get-device-tokens-client") < 0
        || iec_set_attribute(IEC_LOGGING_ENABLED, "true") < 0
        || iec_set_attribute(IEC_LOGGING_DEBUG, "true") < 0
        || iec_set_attribute(IEC_LOGGING_LOGFILE, "client.log") < 0
     ) {
        char* error = iec_last_error();
        printf("Attribute setting failed: %s\n\n", error);
        free(error);
        return result;
    }
    printf("Done\n\n");

    printf("Initialising sdk... ");
    result = iec_initialise();
    if (result < 0) {
        char* error = iec_last_error();
        printf("Initialisation request failed: %s\n\n", error);
        free(error);
        return result;
    }
    printf("Done\n\n");

    printf("Registering device (id: %s)... ", deviceId);
    result = iec_device_register(deviceId, registrationData);
    if (result < 0) {
        char* error = iec_last_error();
        printf("Registration request failed: %s\n", error);
        free(error);
        return result;
    }
    printf("Done\n\n");

    printf("Requesting OAuth 2.0 ID token for device (id: %s)... ", deviceId);
    char* tokens;
    result = iec_device_tokens(deviceId, &tokens);
    if (result < 0) {
        char* error = iec_last_error();
        printf("Access token request failed: %s\n", error);
        free(error);
        return result;
    }
    printf("Done\n\n");

    printf("Extracting access and id tokens...\n");
    char* idToken;
    char* accessToken;
    if (iec_json_parse(tokens) != 0
        || iec_json_get_string("access_token", &accessToken) != 0
        || iec_json_get_string("id_token", &idToken) != 0 ) {
        char* error = iec_last_error();
        printf("Failed to extract access and id tokens: %s\n", error);
        free(error);
        return -1;
    }
    printf("\taccess token: %s\n", accessToken);
    printf("\tid token: %s\n", idToken);
}
