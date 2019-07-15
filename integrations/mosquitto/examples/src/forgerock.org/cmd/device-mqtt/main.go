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
	"encoding/base64"
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
	"strings"
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

// parseTokens extracts the access token from the tokens string
// if the token is stateless, then the expiry time from the token is returned
// if the token is stateful, then the zero time instant is returned
func parseTokens(s string) (string, time.Time) {
	var expiry time.Time
	// extract the access token from the string
	tokens := struct {
		AccessToken string `json:"access_token"`
	}{}
	if err := json.Unmarshal([]byte(s), &tokens); err != nil {
		panic(err)
	}

	// check if the token looks like a jwt
	array := strings.Split(tokens.AccessToken, ".")
	if len(array) != 3 {
		return tokens.AccessToken, expiry
	}
	payload, err := base64.RawURLEncoding.DecodeString(array[1])
	if err != nil {
		return tokens.AccessToken, expiry
	}

	// extract the expiry time from the payload
	statelessToken := struct {
		Exp int64 `json:"exp"`
	}{}
	err = json.Unmarshal(payload, &statelessToken)
	if err != nil && statelessToken.Exp == 0 {
		return tokens.AccessToken, expiry
	}
	return tokens.AccessToken, time.Unix(statelessToken.Exp, 0)
}

func main() {
	const qos = 1
	var mux sync.Mutex

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deviceID := flag.String("deviceID", "", "Device ID (required)")
	serverURI := flag.String("serverURI", "tcp://172.16.0.13:1883", "URI of MQTT server")
	reconnectTime := flag.Int("reconnectTime", 10, "Default time (in seconds) used to reconnect client")
	debug := flag.Bool("debug", false, "Switch on debug output")
	flag.Parse()

	if *deviceID == "" {
		log.Fatal("Please provide a Device ID")
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

	c := make(chan time.Time, 1)
	defer close(c)

	// set MQTT client options
	opts := mqtt.NewClientOptions()
	opts.AddBroker(*serverURI)
	opts.SetClientID(*deviceID)
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
		accessToken, expiry := parseTokens(tokens)
		if expiry.IsZero() {
			expiry = time.Now().Add(time.Duration(*reconnectTime) * time.Second)
			fmt.Println("Using DEFAULT expiry time", expiry)
		} else {
			fmt.Println("Using TOKEN expiry time", expiry)
		}
		c <- expiry
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
			case expire := <-c:
				timer = time.AfterFunc(expire.Sub(time.Now()), func() {
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
				if token := client.Publish(deviceTopic(*deviceID, "data"), qos, false, dataBytes); token.Wait() && token.Error() != nil {
					log.Println(token.Error())
				}
				mux.Unlock()
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
