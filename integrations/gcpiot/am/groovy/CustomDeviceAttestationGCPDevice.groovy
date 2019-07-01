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

import groovy.json.JsonSlurper
import org.forgerock.am.iec.identity.IotIdentity

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport
import com.google.api.services.cloudiot.v1.CloudIot
import com.google.api.services.cloudiot.v1.CloudIotScopes
import com.google.api.services.cloudiot.v1.model.Device
import com.google.api.services.cloudiot.v1.model.DeviceCredential
import com.google.api.services.cloudiot.v1.model.PublicKeyCredential
import com.google.api.client.json.jackson2.JacksonFactory
import com.google.api.client.http.HttpBackOffIOExceptionHandler
import com.google.api.client.http.HttpResponse
import com.google.api.client.http.HttpRequest
import com.google.api.client.http.HttpRequestInitializer
import com.google.api.client.http.HttpBackOffUnsuccessfulResponseHandler
import com.google.api.client.auth.oauth2.Credential
import com.google.api.client.util.ExponentialBackOff
import com.google.api.client.util.Sleeper

/*
 *    Start project data
 */
String projectID = ""
String region = ""
String registryID = ""
String serviceAccountCredentials = ""
/*
 *    End project data
 */


class RetryHttpInitializerWrapper implements HttpRequestInitializer {
    final Credential wrappedCredential
    /** One minutes in milliseconds. */
    final int ONE_MINUTE_MILLIS = 60 * 1000
    final Sleeper sleeper

    RetryHttpInitializerWrapper(wrappedCredential) {
        this.wrappedCredential = wrappedCredential
        this.sleeper = Sleeper.DEFAULT
    }

    void initialize(HttpRequest request) {
        request.readTimeout = 2 * ONE_MINUTE_MILLIS
        request.interceptor = wrappedCredential

        def backoffHandler = new HttpBackOffUnsuccessfulResponseHandler(new ExponentialBackOff()).setSleeper(sleeper)

        request.unsuccessfulResponseHandler = { HttpRequest httpRequest, HttpResponse response, boolean supportsRetry ->
            // If credential decides it can handle it, the return code or message indicated
            // something specific to authentication, and no backoff is desired.
            // Otherwise, leave to backoff
            wrappedCredential.handleResponse(httpRequest, response, supportsRetry) ||
                backoffHandler.handleResponse(httpRequest, response, supportsRetry)
        }
        request.IOExceptionHandler = new HttpBackOffIOExceptionHandler(new ExponentialBackOff()).setSleeper(sleeper)
    }
}

CloudIot buildClient(String appName, String credentials){
    def credential =
            GoogleCredential.fromStream(new ByteArrayInputStream(credentials.bytes)).createScoped(CloudIotScopes.all())
    def builder = new CloudIot.Builder(
            GoogleNetHttpTransport.newTrustedTransport(),
            JacksonFactory.getDefaultInstance(),
            new RetryHttpInitializerWrapper(credential))
    builder.applicationName = appName
    builder.build()
}

Device createDevice(CloudIot client, String registryPath, String deviceId, String publicKey){
    def publicKeyCredential = new PublicKeyCredential().setKey(publicKey).setFormat("ES256_PEM")
    def deviceCredentials = [new DeviceCredential().setPublicKey(publicKeyCredential)]
    def device = new Device().setId(deviceId).setCredentials(deviceCredentials)
    client.projects().locations().registries().devices().create(registryPath, device).execute()
}


logger.info("Custom Device Attestation script")
authState = SUCCESS

// Pre-defined variables passed to the script
IotIdentity identity = identity as IotIdentity

// Only do custom attestation for devices, not for the IEC or clients
if (!identity.isDevice()) {
    return
}

// Registration data is mandatory in this example so return error if it is undefined
if (!verifiedClaims.isDefined("registration_data")) {
    logger.error("Registration data not defined")
    authState = FAILURE
    return
}

// registration data is sent as a base64 encoded string
def registrationData = verifiedClaims.get("registration_data")
def decoded = registrationData.asString().decodeBase64()
def regJson = new JsonSlurper().parse(decoded)
if (!regJson || !regJson.public_key) {
    logger.error("Registration data is not in the correct form")
    authState = FAILURE
    return
}

// build a cloud iot client and use it to register the device in IoT Core
def client = buildClient("iot-plugin", serviceAccountCredentials)
def registryPath = "projects/${projectID}/locations/${region}/registries/${registryID}"
def device = createDevice(client, registryPath, identity.name, regJson.public_key)

// store MQTT connection information in the device's user configuration (at the IEC level)
// so the device can obtain it via a get configuration call
Optional<IotIdentity> iec = identity.iec
if (!iec.isPresent()) {
    logger.error("Can't find IEC for device")
    authState = FAILURE
    return
}
iec.get().setUserConfiguration("""{
    \"mqtt_server_url\":\"tls://mqtt.googleapis.com:8883\",
    \"protocol_version\":4,
    \"project_id\":\"$projectID\",
    \"region\":\"$region\",
    \"registry_id\":\"$registryID\"}""")

logger.info("Attestation for device '$identity.name' succeeded.")