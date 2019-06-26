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
)

// registerWithIEC initialises a SDK client and registers a device with FR IEC
// The public key of the device is loaded from file and passed in with the registration call
func registerWithIEC(deviceID, publicKeyPath string) (err error) {
	// initialise client
	config := configuration.SDKConfig{
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
	if result := zmqclient.Initialise(zmqclient.UseDynamicConfig(config)); result.Failure() {
		return fmt.Errorf(result.Error.String())
	}

	// load public key into JSON object
	keyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}
	data := struct {
		PublicKey string `json:"public_key"`
	}{string(keyBytes)}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// register device with IEC
	if result := zmqclient.DeviceRegister(deviceID, string(dataBytes)); result.Failure() {
		return fmt.Errorf(result.Error.String())
	}
	return nil
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

// connectToIOTCore creates a MQTT client and connects it to the Google IoT Core MQTT server
func connectToIOTCore(rootCAPath, clientID, jwt string, debug bool) (client mqtt.Client, err error) {
	const (
		mqttBrokerURL   = "tls://mqtt.googleapis.com:8883"
		protocolVersion = 4 // corresponds to MQTT 3.1.1
		username        = "unused"
	)

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
	opts.AddBroker(mqttBrokerURL)
	opts.SetClientID(clientID)
	opts.SetUsername(username)
	opts.SetPassword(jwt)
	opts.SetProtocolVersion(protocolVersion)
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

// mqttClientID creates a MQTT client ID in the format expected by IoT Core
func mqttClientID(projectID, region, registryID, deviceID string) string {
	return fmt.Sprintf("projects/%s/locations/%s/registries/%s/devices/%s", projectID, region, registryID, deviceID)
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

	deviceID := flag.String("deviceID", "", "Device ID")
	projectID := flag.String("projectID", "", "GCP Project ID")
	region := flag.String("region", "", "GCP Project Region of IoT Core Registry")
	registryID := flag.String("registryID", "", "GCP IoT Core Registry ID")
	privateKey := flag.String("privateKey", "", "Path to private key of device")
	publicKey := flag.String("publicKey", "", "Path to public key of device")
	rootCA := flag.String("rootCA", "", "Path to Google root CA certificate")
	debug := flag.Bool("debug", false, "Switch on debug output (optional)")
	flag.Parse()

	if *deviceID == "" {
		log.Fatal("Please provide a Device ID")
	}
	if *projectID == "" {
		log.Fatal("Please provide a GCP Project ID")
	}
	if *region == "" {
		log.Fatal("Please provide a GCP Region")
	}
	if *registryID == "" {
		log.Fatal("Please provide a GCP Registry ID")
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

	// register device with ForgeRock IEC
	if err := registerWithIEC(*deviceID, *publicKey); err != nil {
		log.Fatal(err)
	}

	// create jwt for MQTT password
	deviceJWT, err := createJWT(*projectID, *privateKey, time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// connect to GCP IoT Core
	clientID := mqttClientID(*projectID, *region, *registryID, *deviceID)
	client, err := connectToIOTCore(*rootCA, clientID, deviceJWT, *debug)
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
