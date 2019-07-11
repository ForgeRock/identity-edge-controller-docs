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

import org.forgerock.am.iec.identity.IotIdentity
import com.microsoft.azure.sdk.iot.service.Device
import com.microsoft.azure.sdk.iot.service.RegistryManager

logger.info("Custom Device Attestation script")
authState = SUCCESS

// Pre-defined variables passed to the script
IotIdentity identity = identity as IotIdentity

// The Azure IoT hub connection string required to add devices to the hub
String iotHubConnectionString = "[IoT hub connection string goes here]"

// Only do custom attestation for devices, not for the IEC or clients
if (!identity.isDevice()) {
    return
}

// Add the device to the Azure IoT Hub
RegistryManager registryManager = RegistryManager.createFromConnectionString(iotHubConnectionString)
Device device = Device.createFromId(identity.getName(), null, null)
try {
    device = registryManager.addDevice(device)
} catch (Exception e) {
    logger.error("Failed to add device to Azure IoT Hub.", e)
    authState = FAILED
    return
} finally {
    registryManager.close()
}

// Store the device's Azure connection string in the FR identity configuration
def deviceCS = registryManager.getDeviceConnectionString(device)
identity.setUserConfiguration("{\"deviceConnectionString\": \"$deviceCS\"}")

logger.info("Attestation for device '$identity.name' succeeded.")
