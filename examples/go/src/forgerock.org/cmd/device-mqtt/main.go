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
	"stash.forgerock.org/iot/identity-edge-controller-core/configuration"
	"stash.forgerock.org/iot/identity-edge-controller-core/logging"
	"stash.forgerock.org/iot/identity-edge-controller-core/zmqclient"
	"strconv"
	"sync"
	"time"
)

var (
	sdkConfig = configuration.SDKConfig{
		ZMQClient: configuration.ZMQClient{
			Endpoint:                  "tcp://172.16.0.11:5556",
			SecretKey:                 "zZZfS7BthsFLMv$]Zq{tNNOtd69hfoBsuc-lg1cM",
			PublicKey:                 "uH&^{aIzDw5<>TRbHcu0q#(zo]uLl6Wyv/1{/^C+",
			ServerPublicKey:           "9m27tKf3aoNWQ(G-f[>W]gP%f&+QxPD:?mX*)hdJ",
			MessageResponseTimeoutSec: 5,
		},
		ClientConfig: configuration.ClientConfig{"go-client"},
		Logging: configuration.Logging{
			Enabled: true,
			Debug:   true,
			Logfile: "client.log",
		},
	}
)

// sensorData holds dummy sensor data to publish to the 'event' topic
type sensorData struct {
	NoiseLevel  float64 `json:"noise_level"`
	Illuminance int     `json:"illuminance"`
	UnixTime    int64   `json:"unix_time"`
}

// fluctuate randomly fluctuates the values in the sensorData
func (d *sensorData) fluctuate(u int64) {
	d.Illuminance += rand.Intn(10) - 5
	d.NoiseLevel += rand.Float64() - 0.5
	d.UnixTime = u
}

func (d *sensorData) String() string {
	return fmt.Sprintf("{Noise Level %f, Illuminance %d, Time %d}", d.NoiseLevel, d.Illuminance,
		d.UnixTime)
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

// mustParseTokens extracts the access token and the expiry time (in seconds) from the tokens string
// panics if it cannot extract the token or the expiry time
func mustParseTokens(s string) (string, int64) {
	// extract the access token from the string
	tokens := struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   string `json:"expires_in"`
	}{}
	if err := json.Unmarshal([]byte(s), &tokens); err != nil {
		panic(err)
	}
	expiry, err := strconv.ParseInt(tokens.ExpiresIn, 10, 64)
	if err != nil {
		panic(err)
	}
	return tokens.AccessToken, expiry
}

func main() {
	const qos = 1
	var mux sync.Mutex

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deviceID := flag.String("deviceID", "", "Device ID (required)")
	serverURI := flag.String("serverURI", "tcp://172.16.0.13:1883", "URI of MQTT server")
	topic := flag.String("topic", "", "MQTT topic (default \"/devices/{deviceID}\")")
	subscribe := flag.Bool("subscribe", false, "client subscribes to topic instead of publishing")
	debug := flag.Bool("debug", false, "Switch on debug output")
	flag.Parse()

	if *deviceID == "" {
		log.Fatal("Please provide a Device ID")
	}

	if *topic == "" {
		*topic = "/devices/" + *deviceID
	}

	if *debug {
		mqtt.DEBUG = mqttLogger{}
	}

	// initialise SDK client
	if result := zmqclient.Initialise(zmqclient.UseDynamicConfig(sdkConfig)); result.Failure() {
		log.Fatal(result.Error.String())
	}

	// register device with ForgeRock IEC
	if result := zmqclient.DeviceRegister(*deviceID, "{}"); result.Failure() {
		log.Fatal(result.Error.String())
	}

	reconnectIn := make(chan int64, 1)
	defer close(reconnectIn)

	// set MQTT client options
	opts := mqtt.NewClientOptions()
	opts.AddBroker(*serverURI)
	opts.SetClientID(*deviceID)
	opts.SetCleanSession(false) // set clean session to false so subscriptions are retained after reconnect
	opts.SetDefaultPublishHandler(func(client mqtt.Client, message mqtt.Message) {
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
		var (
			tokens string
			result logging.Result
		)
		for {
			tokens, result = zmqclient.DeviceTokens(*deviceID)
			if result.Success() {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		accessToken, nSeconds := mustParseTokens(tokens)
		// send the expiry time to the reconnect channel
		reconnectIn <- nSeconds
		return "unused", accessToken
	})

	client := mqttMustConnect(opts)

	// create a goroutine that reconnects the mqtt client at expiry time
	go func() {
		var timer *time.Timer
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case nSeconds := <-reconnectIn:
				fmt.Printf("Reconnect MQTT client in %d seconds\n", nSeconds)
				timer = time.AfterFunc(time.Duration(nSeconds)*time.Second, func() {
					mux.Lock()
					defer mux.Unlock()
					if client.IsConnected() {
						client.Disconnect(20)
					}
					client = mqttMustConnect(opts)
				})
			}
		}
	}()

	if *subscribe {
		fmt.Println("Subscribing to ", *topic)
		if token := client.Subscribe(*topic, qos, nil); token.Wait() && token.Error() != nil {
			log.Fatal(token.Error())
		}
	} else {
		fmt.Println("Publishing to ", *topic)
		// create a goroutine to regularly publish telemetry events
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			data := sensorData{
				NoiseLevel:  10.0, // leaf rustling
				Illuminance: 400,  // sunrise
			}
			for {
				select {
				case <-ctx.Done():
					return
				case c := <-ticker.C:
					data.fluctuate(c.Unix())
					dataBytes, err := json.Marshal(data)
					if err != nil {
						continue
					}
					mux.Lock()
					fmt.Println("Publishing sensor data:", data)
					if token := client.Publish(*topic, qos, false, dataBytes); token.Wait() && token.Error() != nil {
						log.Println(token.Error())
					}
					mux.Unlock()
				}
			}
		}()
	}

	fmt.Println("Enter any key to exit")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		break
	}

	if *subscribe {
		// unsubscribe so that subscriptions don't leak between program runs
		client.Unsubscribe(*topic).Wait()
	}
}
