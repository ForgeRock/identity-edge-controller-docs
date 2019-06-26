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
import com.google.api.services.cloudiot.v1.model.*
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
 *	Start project data
 */
String projectId = ""
String cloudRegion = ""
String registryName = ""
String serviceAccountCredentials = ""
/*
 *	End project data
 */


class retryHttpInitializerWrapper implements HttpRequestInitializer {
    final Credential wrappedCredential
    /** One minutes in milliseconds. */
    final int ONE_MINUTE_MILLIS = 60 * 1000
    final Sleeper sleeper

    retryHttpInitializerWrapper(wrappedCredential) {
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
            new retryHttpInitializerWrapper(credential))
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

// Registration data is not mandatory so return if not present
if (!verifiedClaims.isDefined("registration_data")) {
    logger.info("Registration data not defined")
    return
}

// registration data is sent as a base64 encoded string
def registrationData = verifiedClaims.get("registration_data")
def decoded = registrationData.asString().decodeBase64()
def regJson = new JsonSlurper().parse(decoded)
if (regJson) {
	// This is where the registration data can be processed
	if (regJson.public_key) {
		def service = buildClient("iot-plugin", serviceAccountCredentials)
		def registryPath = "projects/${projectId}/locations/${cloudRegion}/registries/${registryName}"
		def device = createDevice(service, registryPath, identity.name, regJson.public_key)
    }
}
logger.info("Attestation for device '$identity.name' succeeded.")