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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/eclipse/paho.mqtt.golang"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"stash.forgerock.org/iot/identity-edge-controller-core/configuration"
	"stash.forgerock.org/iot/identity-edge-controller-core/zmqclient"
	"time"
)

var (
	configRE  = regexp.MustCompile(`/devices/\w*/config`)
	commandRE = regexp.MustCompile(`/devices/\w*/command`)
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

// readRegistrationData reads the public key of the device and formats it so that it can be passed to the device
// register call
func readRegistrationData(publicKeyPath string) (dataString string, err error) {
	// load public key into JSON object
	keyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return
	}
	data := struct {
		PublicKey string `json:"public_key"`
	}{string(keyBytes)}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return
	}

	return string(dataBytes), nil
}

// createJWT returns a signed JWT that can be used to as a password for the MQTT server
// In Google IoT Core, the maximum lifetime of a token is 24 hours + skew
func createJWT(projectID string, privateKeyPath string, expiration time.Duration) (string, error) {
	if expiration > 24*time.Hour {
		return "", fmt.Errorf("expiration duration of %s is too long", expiration)
	}
	claims := jwt.StandardClaims{
		Audience:  projectID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(expiration).Unix(),
	}

	keyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}
	privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(privateKey)
}

// mqttLogger implements the logger interface used by the MQTT package
type mqttLogger struct{}

func (mqttLogger) Println(v ...interface{}) {
	fmt.Println(v)
}
func (mqttLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format, v)
}

// mqttConnectionData holds the data needed to connect to the MQTT bridge of the IoT Core project that the device
// is registered to
type mqttConnectionData struct {
	MQTTServerURL string `json:"mqtt_server_url"`
	ProtocolVersion uint `json:"protocol_version"`
	ProjectID string `json:"project_id"`
	Region string `json:"region"`
	RegistryID string `json:"registry_id"`
}

// connectToIOTCore creates a MQTT client and connects it to the Google IoT Core MQTT server
func connectToIOTCore(conn mqttConnectionData, rootCAPath, id, jwt string, debug bool) (client mqtt.Client, err error) {
	// onConnect defines the on connect handler
	var onConnect mqtt.OnConnectHandler = func(client mqtt.Client) {
		fmt.Printf("Client connected: %t\n", client.IsConnected())
	}

	// onMessage defines the default message handler
	var onMessage mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
		switch {
		case configRE.MatchString(msg.Topic()):
			fmt.Printf("Received config: %s\n", msg.Payload())
		case commandRE.MatchString(msg.Topic()):
			fmt.Printf("Received command: %s\n", msg.Payload())
		default:
			fmt.Printf("Topic: %s\n", msg.Topic())
			fmt.Printf("Message: %s\n", msg.Payload())
		}
	}

	// onDisconnect defines the connection lost handler
	var onDisconnect mqtt.ConnectionLostHandler = func(client mqtt.Client, err error) {
		fmt.Println("Client disconnected")
	}

	// load server certificate and add to certificate pool
	serverBytes, err := ioutil.ReadFile(rootCAPath)
	if err != nil {
		fmt.Printf("failed to read server cert: %v", err)
		return nil, err
	}
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(serverBytes)
	if !ok {
		fmt.Printf("failed to append cert from PEM")
		return nil, err
	}

	cfg := &tls.Config{
		ClientCAs: certPool,
	}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(conn.MQTTServerURL)
	opts.SetClientID(fmt.Sprintf("projects/%s/locations/%s/registries/%s/devices/%s", conn.ProjectID, conn.Region,
		conn.RegistryID, id))
	opts.SetUsername("unused")
	opts.SetPassword(jwt)
	opts.SetProtocolVersion(conn.ProtocolVersion)
	opts.SetOnConnectHandler(onConnect)
	opts.SetDefaultPublishHandler(onMessage)
	opts.SetConnectionLostHandler(onDisconnect)
	opts.SetTLSConfig(cfg)
	if debug {
		mqtt.DEBUG = mqttLogger{}
	}

	// Create and connect a client using the above options.
	client = mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		fmt.Println("failed to connect client")
		return nil, token.Error()
	}
	return client, nil
}

// stateTopic returns the state topic for the given device
func stateTopic(deviceID string) string {
	return fmt.Sprintf("/devices/%s/state", deviceID)
}

// eventTopic returns the event topic for the given device
func eventTopic(deviceID string) string {
	return fmt.Sprintf("/devices/%s/events", deviceID)
}

// commandTopic returns the command topic for the given device
func commandTopic(deviceID string) string {
	return fmt.Sprintf("/devices/%s/commands/#", deviceID)
}

// configTopic returns the config topic for the given device
func configTopic(deviceID string) string {
	return fmt.Sprintf("/devices/%s/config", deviceID)
}

func main() {
	const qos = 1

	// get working directory
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	deviceID := flag.String("deviceID", "", "Device ID (required)")
	privateKey := flag.String("privateKey", "", "Path to private key of device")
	publicKey := flag.String("publicKey", "", "Path to public key of device")
	rootCA := flag.String("rootCA", "", "Path to Google root CA certificate")
	debug := flag.Bool("debug", false, "Switch on debug output (optional)")
	flag.Parse()

	if *deviceID == "" {
		log.Fatal("Please provide a Device ID")
	}
	if *privateKey == "" {
		*privateKey = filepath.Join(dir, "resources", "ec_private.pem")
	}
	if *publicKey == "" {
		*publicKey = filepath.Join(dir, "resources", "ec_public.pem")
	}
	if *rootCA == "" {
		*rootCA = filepath.Join(dir, "resources", "roots.pem")
	}

	// initialise SDK client
	if result := zmqclient.Initialise(zmqclient.UseDynamicConfig(sdkConfig)); result.Failure() {
		log.Fatal(result.Error.String())
	}

	// register device with ForgeRock IEC
	registrationData, err := readRegistrationData(*publicKey)
	if err != nil {
		log.Fatal(err)
	}
	if result := zmqclient.DeviceRegister(*deviceID, registrationData); result.Failure() {
		log.Fatal(result.Error.String())
	}

	// get device configuration from ForgeRock IEC
	deviceConfig, result := zmqclient.DeviceConfiguration(*deviceID)
	if result.Failure() {
		log.Fatal(result.Error.String())
	}
	connectionData := mqttConnectionData{}
	if err := json.Unmarshal([]byte(deviceConfig), &connectionData); err != nil {
		log.Fatal(err)
	}

	// create jwt for MQTT password
	deviceJWT, err := createJWT(connectionData.ProjectID, *privateKey, time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// connect to GCP IoT Core
	client, err := connectToIOTCore(connectionData, *rootCA, *deviceID, deviceJWT, *debug)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		fmt.Println("Disconnecting client")
		client.Disconnect(20)
	}()

	state := "alive"
	event := "demo in process"

	// publishing device state
	if token := client.Publish(stateTopic(*deviceID), qos, false, state); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	// publishing telemetry event
	if token := client.Publish(eventTopic(*deviceID), qos, false, event); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	// listen for commands
	if token := client.Subscribe(commandTopic(*deviceID), qos, nil); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	// listen for configuration
	if token := client.Subscribe(configTopic(*deviceID), qos, nil); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	fmt.Println("Listening... enter 'q' to exit")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() == "q" {
			break
		}
	}
}
