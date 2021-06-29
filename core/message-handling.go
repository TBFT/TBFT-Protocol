// Copyright (c) 2018 NEC Laboratories Europe GmbH.
//
// Authors: Sergey Fedorov <sergey.fedorov@neclab.eu>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package minbft

import (
	"fmt"
	"sync"

	"github.com/hyperledger-labs/minbft/api"
	"github.com/hyperledger-labs/minbft/common/logger"
	"github.com/hyperledger-labs/minbft/core/internal/clientstate"
	"github.com/hyperledger-labs/minbft/core/internal/messagelog"
	"github.com/hyperledger-labs/minbft/core/internal/peerstate"
	"github.com/hyperledger-labs/minbft/core/internal/requestlist"
	"github.com/hyperledger-labs/minbft/core/internal/viewstate"
	"github.com/hyperledger-labs/minbft/messages"
)

// messageStreamHandler fetches serialized messages from in channel,
// handles the received messages, and sends a serialized reply
// message, if any, to reply channel.
type messageStreamHandler func(in <-chan []byte, reply chan<- []byte)

// messageHandler fully handles message.
//
// If there are any messages produced in reply, they will be sent to
// reply channel, otherwise nil channel is returned. The return value
// new indicates that the message has not been processed before.
type messageHandler func(msg messages.Message) (reply <-chan messages.Message, new bool, err error)

// peerConnector initiates message exchange with a peer replica.
//
// Given a channel of outgoing messages to supply to the replica, it
// returns a channel of messages produced by the replica in reply.
type peerConnector func(out <-chan []byte) (in <-chan []byte, err error)

// messageValidator validates a message.
//
// It authenticates and checks the supplied message for internal
// consistency. It does not use replica's current state and has no
// side-effect. It is safe to invoke concurrently.
type messageValidator func(msg messages.Message) ([]byte, error)

// messageProcessor processes a valid message.
//
// It fully processes the supplied message in the context of the
// current replica's state. The supplied message is assumed to be
// authentic and internally consistent. The return value new indicates
// if the message had any effect. It is safe to invoke concurrently.
type messageProcessor func(msg messages.Message, bb []byte) (new bool, err error)

// peerMessageProcessor processes a valid peer message.
//
// It continues processing of the supplied peer message. The return
// value new indicates if the message had any effect. It is safe to
// invoke concurrently.
type peerMessageProcessor func(msg messages.PeerMessage, bb []byte) (new bool, err error)

// embeddedMessageProcessor processes embedded messages.
//
// It recursively processes messages embedded into the supplied
// message. The supplied message and its embedded messages are assumed
// to be authentic and internally consistent. It is safe to invoke
// concurrently.
type embeddedMessageProcessor func(msg messages.PeerMessage, bb []byte)

// uiMessageProcessor processes a valid message with UI.
//
// It continues processing of the supplied message with UI. Messages
// originated from the same replica are guaranteed to be processed
// once only and in the sequence assigned by the replica USIG. The
// return value new indicates if the message had any effect. It is
// safe to invoke concurrently.
type uiMessageProcessor func(msg messages.CertifiedMessage, bb []byte) (new bool, err error)

// viewMessageProcessor processes a valid message in current view.
//
// It continues processing of the supplied message, according to the
// current view number. The message is guaranteed to be processed in a
// corresponding view, or not processed at all. The return value new
// indicates if the message had any effect. It is safe to invoke
// concurrently.
type viewMessageProcessor func(msg messages.PeerMessage, bb []byte) (new bool, err error)

// peerMessageApplier applies a peer message to current replica state.
//
// The supplied message is applied to the current replica state by
// changing the state accordingly and producing any required messages
// or side effects. The supplied message is assumed to be authentic
// and internally consistent. Parameter active indicates if the
// message refers to the active view. It is safe to invoke
// concurrently.
type peerMessageApplier func(msg messages.PeerMessage, bb []byte, active bool) error

// generatedMessageHandler finalizes and handles generated message.
//
// It finalizes the supplied message by attaching an authentication
// tag to the message, then takes further steps to handle the message.
// It is safe to invoke concurrently.
type generatedMessageHandler func(msg messages.ReplicaMessage)

// generatedMessageConsumer receives generated message.
//
// It arranges the supplied message to be delivered to peer replicas
// or the corresponding client, as well as to be handled locally,
// depending on the message type. The message should be ready to
// serialize and deliver to the recipients. It is safe to invoke
// concurrently.
type generatedMessageConsumer func(msg messages.ReplicaMessage)

// defaultMessageHandlers constructs standard message handlers using
// id as the current replica ID and the supplied interfaces.
func defaultMessageHandlers(id uint32, log messagelog.MessageLog, unicastLogs map[uint32]messagelog.MessageLog, config api.Configer, stack Stack, logger logger.Logger) (handleOwnMessage, handlePeerMessage, handleClientMessage messageHandler) {
	n := config.N()
	f := config.F()

	reqTimeout := makeRequestTimeoutProvider(config)
	prepTimeout := makePrepareTimeoutProvider(config)

	verifyMessageSignature := makeMessageSignatureVerifier(stack, messages.AuthenBytes)
	signMessage := makeMessageSigner(stack, messages.AuthenBytes)
	verifyUI := makeUIVerifier(id, stack, messages.AuthenBytes)
	assignUI := makeUIAssigner(stack, messages.AuthenBytes)

	clientStates := clientstate.NewProvider(reqTimeout, prepTimeout)
	peerStates := peerstate.NewProvider()
	viewState := viewstate.New()

	captureSeq := makeRequestSeqCapturer(clientStates)
	prepareSeq := makeRequestSeqPreparer(clientStates)
	retireSeq := makeRequestSeqRetirer(clientStates)
	pendingReq := requestlist.New()
	captureUI := makeUICapturer(peerStates)

	consumeGeneratedMessage := makeGeneratedMessageConsumer(log, clientStates, logger)
	handleGeneratedMessage := makeGeneratedMessageHandler(id, signMessage, assignUI, consumeGeneratedMessage)

	requestViewChange := makeViewChangeRequestor(id, viewState, handleGeneratedMessage)
	handleReqTimeout := makeRequestTimeoutHandler(requestViewChange, logger)
	startReqTimer := makeRequestTimerStarter(clientStates, handleReqTimeout, logger)
	stopReqTimer := makeRequestTimerStopper(clientStates)
	startPrepTimer := makePrepareTimerStarter(n, clientStates, unicastLogs, logger)
	stopPrepTimer := makePrepareTimerStopper(clientStates)

	acceptVote := makeVoteAcceptor()
	countVote := makeVoteCounter(f)
	executeRequest := makeRequestExecutor(id, retireSeq, pendingReq, stopReqTimer, stack, handleGeneratedMessage)
	collectVote := makeVoteCollector(acceptVote, countVote, executeRequest)

	validateRequest := makeRequestValidator(verifyMessageSignature)
	validatePrepare := makePrepareValidator(n, verifyUI, validateRequest)
	validateVote := makeVoteValidator(verifyMessageSignature)
	validateMessage := makeMessageValidator(validateRequest, validatePrepare, validateVote)

	applyVote := makeVoteApplier(id, collectVote)
	applyPrepare := makePrepareApplier(id, prepareSeq, collectVote, handleGeneratedMessage, stopPrepTimer, executeRequest)
	applyPeerMessage := makePeerMessageApplier(applyPrepare, applyVote)
	applyRequest := makeRequestApplier(id, n, handleGeneratedMessage, startReqTimer, startPrepTimer)

	var processMessage messageProcessor

	// Due to recursive nature of message processing, an instance
	// of messageProcessor is eventually required for it to be
	// constructed itself. On the other hand, it will actually be
	// invoked only after getting fully constructed. This "thunk"
	// delays evaluation of processMessage variable, thus
	// resolving this circular dependency.
	processMessageThunk := func(msg messages.Message, bb []byte) (new bool, err error) {
		return processMessage(msg, bb)
	}

	processRequest := makeRequestProcessor(captureSeq, pendingReq, viewState, applyRequest)
	processViewMessage := makeViewMessageProcessor(viewState, applyPeerMessage)
	processUIMessage := makeUIMessageProcessor(captureUI, processViewMessage)
	processEmbedded := makeEmbeddedMessageProcessor(processMessageThunk, logger)
	processPeerMessage := makePeerMessageProcessor(processEmbedded, processUIMessage, processViewMessage)
	processMessage = makeMessageProcessor(processRequest, processPeerMessage)
	handleOwnMessage = makeOwnMessageHandler(id, validateMessage, processMessage)
	handlePeerMessage = makePeerMessageHandler(validateMessage, processMessage)

	replyRequest := makeRequestReplier(clientStates)
	handleClientMessage = makeClientMessageHandler(validateRequest, processRequest, replyRequest)

	return
}

// makeMessageStreamHandler construct an instance of
// messageStreamHandler using the supplied abstract handler.
func makeMessageStreamHandler(handleMessage messageHandler, remote string, logger logger.Logger) messageStreamHandler {
	return func(in <-chan []byte, out chan<- []byte) {
		for msgBytes := range in {
			msg, err := messageImpl.NewFromBinary(msgBytes)
			if err != nil {
				logger.Warningf("Error unmarshaling message from %s: %s", remote, err)
				return
			}

			replyChan, _, _ := handleMessage(msg)

			if replyChan != nil {
				for m := range replyChan {
					replyBytes, err := m.MarshalBinary()
					if err != nil {
						panic(err)
					}
					out <- replyBytes
				}
			}
		}
	}
}

// startPeerConnections initiates asynchronous message exchange with
// peer replicas.
func startPeerConnections(ownID, n uint32, connector api.ReplicaConnector, handleMessage messageHandler, logger logger.Logger) error {
	for peerID := uint32(0); peerID < n; peerID++ {
		if peerID == ownID {
			continue
		}
		if peerID != 0 && ownID != 0 {
			continue
		}
		remote := fmt.Sprintf("replica %d", peerID)
		connect := makePeerConnector(peerID, connector)
		handleReplyStream := makeMessageStreamHandler(handleMessage, remote, logger)
		if err := startPeerConnection(ownID, connect, handleReplyStream); err != nil {
			return fmt.Errorf("cannot connect to replica %d: %s", peerID, err)
		}
	}

	return nil
}

// startPeerConnection initiates asynchronous message exchange with a
// peer replica.
func startPeerConnection(ownID uint32, connect peerConnector, handleReplyStream messageStreamHandler) error {
	out := make(chan []byte)
	in, err := connect(out)
	if err != nil {
		return err
	}

	go func() {
		defer close(out)

		h := messageImpl.NewHello(ownID)
		msgBytes, err := h.MarshalBinary()
		if err != nil {
			panic(err)
		}
		out <- msgBytes

		handleReplyStream(in, nil)
	}()

	return nil
}

// handleOwnPeerMessages handles messages generated by the local
// replica for the peer replicas.
func handleOwnPeerMessages(log messagelog.MessageLog, handleOwnMessage messageHandler, logger logger.Logger) {
	for msg := range log.Stream(nil) {
		if _, _, err := handleOwnMessage(msg); err != nil {
			panic(fmt.Errorf("error handling own message: %s", err))
		}
	}
}

// makePeerConnector constructs a peerConnector using the supplied
// peer replica ID and a general replica connector.
func makePeerConnector(peerID uint32, connector api.ReplicaConnector) peerConnector {
	return func(out <-chan []byte) (in <-chan []byte, err error) {
		sh := connector.ReplicaMessageStreamHandler(peerID)
		if sh == nil {
			return nil, fmt.Errorf("connection not possible")
		}
		return sh.HandleMessageStream(out), nil
	}
}

func makeHelloHandler(ownID, n uint32, messageLog messagelog.MessageLog, unicastLogs map[uint32]messagelog.MessageLog) messageHandler {
	return func(msg messages.Message) (<-chan messages.Message, bool, error) {
		h, ok := msg.(messages.Hello)
		if !ok {
			return nil, false, fmt.Errorf("unexpected message type")
		}
		peerID := h.ReplicaID()
		if peerID >= n || peerID == ownID {
			return nil, false, fmt.Errorf("unexpected peer ID")
		}

		var replyChan = make(chan messages.Message)
		var bcChan, ucChan <-chan messages.Message

		bcChan = messageLog.Stream(nil)
		if ucLog := unicastLogs[peerID]; ucLog != nil {
			ucChan = ucLog.Stream(nil)
		}

		go func() {
			for {
				var msg messages.Message

				select {
				case msg = <-bcChan:
				case msg = <-ucChan:
				}

				replyChan <- msg
			}
		}()

		return replyChan, true, nil
	}
}

func makeOwnMessageHandler(id uint32, validate messageValidator, process messageProcessor) messageHandler {
	return func(msg messages.Message) (_ <-chan messages.Message, new bool, err error) {
		if id == 0 {
			return nil, false, nil
		}
		switch msg.(type) {
		case messages.Vote:
			return nil, false, nil
		}
		bb, er := validate(msg)
		if er != nil {
			return nil, false, fmt.Errorf("error validating own message: %s", er)
		}
		new, err = process(msg, bb)
		if err != nil {
			return nil, false, fmt.Errorf("error processing message: %s", err)
		}

		return nil, new, nil
	}
}

func makePeerMessageHandler(validate messageValidator, process messageProcessor) messageHandler {
	return func(msg messages.Message) (_ <-chan messages.Message, new bool, err error) {
		bb, err := validate(msg)
		if err != nil {
			return nil, false, fmt.Errorf("validation failed: %s", err)
		}
		new, er := process(msg, bb)
		if er != nil {
			return nil, false, fmt.Errorf("error processing message: %s", er)
		}

		return nil, new, nil
	}
}

func makeClientMessageHandler(validateRequest requestValidator, processRequest requestProcessor, replyRequest requestReplier) messageHandler {
	return func(msg messages.Message) (_ <-chan messages.Message, new bool, err error) {
		req, ok := msg.(messages.Request)
		if !ok {
			return nil, false, fmt.Errorf("unexpected message type")
		}

		err = validateRequest(req)
		if err != nil {
			return nil, false, fmt.Errorf("invalid Reqeust: %s", err)
		}

		new, err = processRequest(req)
		if err != nil {
			return nil, false, fmt.Errorf("error processing Request: %s", err)
		}

		replyChan := make(chan messages.Message, 1)
		defer close(replyChan)

		if m, ok := <-replyRequest(req); ok {
			replyChan <- m
		}

		return replyChan, new, nil
	}
}

// makeMessageValidator constructs an instance of messageValidator
// using the supplied abstractions.
func makeMessageValidator(validateRequest requestValidator, validatePrepare prepareValidator, validateVote voteValidator) messageValidator {
	return func(msg messages.Message) ([]byte, error) {
		switch msg := msg.(type) {
		case messages.Request:
			return nil, validateRequest(msg)
		case messages.Prepare:
			return validatePrepare(msg)
		case messages.Vote:
			return nil, validateVote(msg)
		case messages.ReqViewChange:
			return nil, fmt.Errorf("not implemented")
		default:
			panic("Unknown message type")
		}
	}
}

// makeMessageProcessor constructs an instance of messageProcessor
// using the supplied abstractions.
func makeMessageProcessor(processRequest requestProcessor, processPeerMessage peerMessageProcessor) messageProcessor {
	return func(msg messages.Message, bb []byte) (new bool, err error) {
		switch msg := msg.(type) {
		case messages.Request:
			return processRequest(msg)
		case messages.PeerMessage:
			return processPeerMessage(msg, bb)
		default:
			panic("Unknown message type")
		}
	}
}

func makePeerMessageProcessor(processEmbedded embeddedMessageProcessor, processUIMessage uiMessageProcessor, processViewMessage viewMessageProcessor) peerMessageProcessor {
	return func(msg messages.PeerMessage, bb []byte) (new bool, err error) {
		processEmbedded(msg, bb)

		switch msg := msg.(type) {
		case messages.Prepare:
			return processUIMessage(msg, bb)
		case messages.Vote:
			return processViewMessage(msg, bb)
		default:
			panic("Unknown message type")
		}
	}
}

func makeEmbeddedMessageProcessor(process messageProcessor, logger logger.Logger) embeddedMessageProcessor {
	return func(msg messages.PeerMessage, bb []byte) {
		processOne := func(m messages.Message, bb []byte) {
			if _, err := process(m, bb); err != nil {
				logger.Warningf("Failed to process %s extracted from %s: %s",
					messages.Stringify(m), messages.Stringify(msg), err)
			}
		}

		switch msg := msg.(type) {
		case messages.Prepare:
			processOne(msg.Request(), bb)
		case messages.Vote:
			processOne(msg.Prepare(), bb)
		case messages.ReqViewChange:
		default:
			panic("Unknown message type")
		}
	}
}

func makeUIMessageProcessor(captureUI uiCapturer, processViewMessage viewMessageProcessor) uiMessageProcessor {
	return func(msg messages.CertifiedMessage, bb []byte) (new bool, err error) {
		new, release := captureUI(msg)
		if !new {
			return false, nil
		}
		defer release()

		switch msg := msg.(type) {
		case messages.PeerMessage:
			return processViewMessage(msg, bb)
		default:
			panic("Unknown message type")
		}
	}
}

func makeViewMessageProcessor(viewState viewstate.State, applyPeerMessage peerMessageApplier) viewMessageProcessor {
	return func(msg messages.PeerMessage, bb []byte) (new bool, err error) {
		var active bool

		switch msg := msg.(type) {
		case messages.Prepare, messages.Vote:
			var messageView uint64

			switch msg := msg.(type) {
			case messages.Prepare:
				messageView = msg.View()
			case messages.Vote:
				messageView = msg.Prepare().View()
			}

			currentView, expectedView, release := viewState.HoldView()
			defer release()

			if currentView == expectedView {
				active = true
			}

			if messageView < currentView {
				return false, nil
			} else if messageView > currentView {
				// A correct peer replica would ensure
				// that this replica would transition
				// into the new view before processing
				// the message.
				return false, fmt.Errorf("message refers to unexpected view")
			}
		default:
			panic("Unknown message type")
		}

		if err := applyPeerMessage(msg, bb, active); err != nil {
			return false, fmt.Errorf("failed to apply message: %s", err)
		}

		return true, nil
	}
}

// makePeerMessageApplier constructs an instance of peerMessageApplier using
// the supplied abstractions.
func makePeerMessageApplier(applyPrepare prepareApplier, applyVote voteApplier) peerMessageApplier {
	return func(msg messages.PeerMessage, bb []byte, active bool) error {
		switch msg := msg.(type) {
		case messages.Prepare:
			return applyPrepare(msg, bb, active)
		case messages.Vote:
			return applyVote(msg, active)
		default:
			panic("Unknown message type")
		}
	}
}

// makeGeneratedMessageHandler constructs generatedMessageHandler
// using the supplied abstractions.
func makeGeneratedMessageHandler(id uint32, sign messageSigner, assignUI uiAssigner, consume generatedMessageConsumer) generatedMessageHandler {
	var uiLock sync.Mutex

	return func(msg messages.ReplicaMessage) {
		switch msg.(type) {
		case messages.Reply:
			if id != 0 {
				return
			}
		}
		switch msg := msg.(type) {
		case messages.CertifiedMessage:
			uiLock.Lock()
			defer uiLock.Unlock()

			assignUI(msg)
		case messages.SignedMessage:
			sign(msg)
		}

		consume(msg)
	}
}

func makeGeneratedMessageConsumer(log messagelog.MessageLog, provider clientstate.Provider, logger logger.Logger) generatedMessageConsumer {
	return func(msg messages.ReplicaMessage) {
		switch msg := msg.(type) {
		case messages.Reply:
			clientID := msg.ClientID()
			if err := provider(clientID).AddReply(msg); err != nil {
				// Erroneous Reply must never be supplied
				panic(fmt.Errorf("failed to consume generated Reply: %s", err))
			}
		case messages.ReplicaMessage:
			log.Append(msg)
		default:
			panic("Unknown message type")
		}
	}
}
