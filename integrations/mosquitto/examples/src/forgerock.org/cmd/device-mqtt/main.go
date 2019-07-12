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

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/eclipse/paho.mqtt.golang"
	"log"
	"math/rand"
	"os"
	"time"
)

var (
	//sdkConfig = configuration.SDKConfig{
	//	ZMQClient: configuration.ZMQClient{
	//		Endpoint:                  "tcp://172.16.0.11:5556",
	//		SecretKey:                 "zZZfS7BthsFLMv$]Zq{tNNOtd69hfoBsuc-lg1cM",
	//		PublicKey:                 "uH&^{aIzDw5<>TRbHcu0q#(zo]uLl6Wyv/1{/^C+",
	//		ServerPublicKey:           "9m27tKf3aoNWQ(G-f[>W]gP%f&+QxPD:?mX*)hdJ",
	//		MessageResponseTimeoutSec: 5,
	//	},
	//	ClientConfig: configuration.ClientConfig{"go-client"},
	//	Logging: configuration.Logging{
	//		Enabled: true,
	//		Debug:   true,
	//		Logfile: "client.log",
	//	},
	//}
)

// sensorData holds dummy sensor data to publish to the 'event' topic
type sensorData struct {
	NoiseLevel         float64 `json:"noise_level"`
	Illuminance        int     `json:"illuminance"`
	TimeAliveInSeconds int     `json:"time_alive_in_seconds"`
}

// fluctuate randomly fluctuates the values in the sensorData
func (d *sensorData) fluctuate(timeAlive int) {
	d.Illuminance += rand.Intn(10) - 5
	d.NoiseLevel += rand.Float64() - 0.5
	d.TimeAliveInSeconds = timeAlive
}

func (d *sensorData) String() string {
	return fmt.Sprintf("{Noise Level %f, Illuminance %d, Time Alive %d}", d.NoiseLevel, d.Illuminance,
		d.TimeAliveInSeconds)
}

// mqttLogger implements the logger interface used by the MQTT package
type mqttLogger struct{}

func (mqttLogger) Println(v ...interface{}) {
	fmt.Println(v)
}
func (mqttLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format, v)
}

// device topic
func deviceTopic(deviceID, subtopic string) string {
	return fmt.Sprintf("/devices/%s/%s", deviceID, subtopic)
}

// mqttMustConnect creates a new client and connects it to the server
// panics if it cannot connect
func mqttMustConnect(opts *mqtt.ClientOptions) mqtt.Client {
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		panic("failed to connect client")
	}
	return client
}

func main() {
	const qos = 1

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deviceID := flag.String("deviceID", "", "Device ID (required)")
	serverURI := flag.String("serverURI", "tcp://127.0.0.1:1883", "URI of MQTT server")
	debug := flag.Bool("debug", false, "Switch on debug output (optional)")
	flag.Parse()

	if *deviceID == "" {
		log.Fatal("Please provide a Device ID")
	}

	if *debug {
		mqtt.DEBUG = mqttLogger{}
	}

	// initialise SDK client
	//if result := zmqclient.Initialise(zmqclient.UseDynamicConfig(sdkConfig)); result.Failure() {
	//	log.Fatal(result.Error.String())
	//}

	// register device with ForgeRock IEC
	//if result := zmqclient.DeviceRegister(*deviceID, registrationData); result.Failure() {
	//	log.Fatal(result.Error.String())
	//}

	c := make(chan time.Time, 10)
	defer close(c)

	// set MQTT client options
	opts := mqtt.NewClientOptions()
	opts.AddBroker(*serverURI)
	opts.SetClientID(*deviceID)
	opts.SetDefaultPublishHandler( func(client mqtt.Client, message mqtt.Message) {
		fmt.Printf("Published: topic= %s; message= %s\n", message.Topic(), message.Payload())
	})
	opts.SetConnectionLostHandler(func(client mqtt.Client, e error) {
		log.Fatalf("client disconnected, %s", e)
	})
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		fmt.Printf("Client connected: %t\n", client.IsConnected())
	})
	opts.SetCredentialsProvider(func() (username string, password string) {
		// get OAuth2 access token ForgeRock IEC
		//tokens, result := zmqclient.DeviceTokens(*deviceID)
		//if result.Failure(){
		//	panic(result.String())
		//}
		c <- time.Now().Add(10 * time.Second)
		return "unused", "password"
	})
	client := mqttMustConnect(opts)

	go func() {
		var timer *time.Timer
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case expire := <-c:
				timer = time.AfterFunc(expire.Sub(time.Now()), func() {
					if client.IsConnected() {
						client.Disconnect(20)
					}
					client = mqttMustConnect(opts)
				})
			}
		}
	}()

	// create a goroutine to regularly publish telemetry events
	go func() {
		timeInterval := 2
		data := sensorData{
			NoiseLevel:         10.0, // leaf rustling
			Illuminance:        400,  // sunrise
			TimeAliveInSeconds: 0,
		}
		for timeAlive := 0; ; timeAlive += timeInterval {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(time.Duration(timeInterval) * time.Second)
				data.fluctuate(timeAlive)
				dataBytes, err := json.Marshal(data)
				if err != nil {
					continue
				}
				fmt.Println("Publishing sensor data:", data)
				if token := client.Publish(deviceTopic(*deviceID, "data"), qos, false, dataBytes); token.Wait() && token.Error() != nil {
					log.Println(token.Error())
				}
			}
		}
	}()

	// listen for commands
	if token := client.Subscribe(deviceTopic(*deviceID, "commands"), qos, nil); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	fmt.Println("Publishing and listening. Enter any key to exit")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		break
	}
}
