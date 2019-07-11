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

package org.forgerock.iot.examples;

import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.google.gson.Gson;
import com.microsoft.azure.sdk.iot.device.DeviceClient;
import com.microsoft.azure.sdk.iot.device.IotHubClientProtocol;
import com.microsoft.azure.sdk.iot.device.Message;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.PointerByReference;

public class AzureClientExample {
    private static final String deviceId = "CityCentre";
    private static final IotHubClientProtocol protocol = IotHubClientProtocol.MQTT;

    private static DeviceClient deviceClient;

    public interface IecClient extends Library {
        IecClient INSTANCE = (IecClient) Native.load("libiecclient.so", IecClient.class);

        int iec_initialise();

        String iec_last_error();

        int iec_device_register(String deviceId, String registrationData);

        int iec_device_configuration(String deviceId, PointerByReference configuration);
    }

    private static class SmartCityTelemetry {
        private static final int minNoiseLevel = 30;
        private static final int maxNoiseLevel = 100;
        private static final int minIlluminance = 100;
        private static final int maxIlluminance = 400;
        private static final Random rand = new Random();

        double noiseLevel;
        double illuminance;

        static SmartCityTelemetry next() {
            SmartCityTelemetry sct = new SmartCityTelemetry();
            sct.noiseLevel = ((long)((minNoiseLevel + rand.nextDouble() * (maxNoiseLevel - minNoiseLevel))*10))/10d;
            sct.illuminance = ((long)((minIlluminance + rand.nextDouble() * (maxIlluminance - minIlluminance))*10))/10d;
            return sct;
        }

        String serialize() {
            Gson gson = new Gson();
            return gson.toJson(this);
        }
    }

    private static class Publisher implements Runnable {
        public void run() {
            try {
                while (true) {
                    String telemetry = SmartCityTelemetry.next().serialize();
                    System.out.println("Sending message: " + telemetry);
                    deviceClient.sendEventAsync(new Message(telemetry), (status, context) ->
                            System.out.println("IoT Hub response status: " + status.name()), null);
                    Thread.sleep(2000);
                }
            } catch (InterruptedException e) {
                // exiting the publisher
            }
        }
    }

    private static class DeviceConfiguration {
        String deviceConnectionString;
    }

    public static void main(String[] args) throws Exception {
        System.out.print("\nInitialising client... ");
        if (IecClient.INSTANCE.iec_initialise() < 0) {
            throw new Exception("Failed to initialise the client: " + IecClient.INSTANCE.iec_last_error());
        }
        System.out.println("Done.");

        System.out.print("Registering device (ID=" + deviceId + ")... ");
        if (IecClient.INSTANCE.iec_device_register(deviceId, null) < 0) {
            throw new Exception("Failed to register the device: " + IecClient.INSTANCE.iec_last_error());
        }
        System.out.println("Done.");

        System.out.print("Retrieving configuration for device (ID=" + deviceId + ")... ");
        PointerByReference configPointer = new PointerByReference();
        if (IecClient.INSTANCE.iec_device_configuration(deviceId, configPointer) < 0) {
            throw new Exception("Failed to retrieve device configuration: " + IecClient.INSTANCE.iec_last_error());
        }
        System.out.println("Done.");

        DeviceConfiguration deviceConfiguration =
                new Gson().fromJson(configPointer.getValue().getString(0), DeviceConfiguration.class);
        System.out.println("Device configuration: " + deviceConfiguration.deviceConnectionString + "\n");

        deviceClient = new DeviceClient(deviceConfiguration.deviceConnectionString, protocol);
        deviceClient.open();

        System.out.println("\nPublishing telemetry for device (ID=" + deviceId + ")");
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        executorService.execute(new Publisher());

        System.out.println("\nPress ENTER to exit.\n");
        System.in.read();
        executorService.shutdownNow();
        deviceClient.closeNow();
    }

}