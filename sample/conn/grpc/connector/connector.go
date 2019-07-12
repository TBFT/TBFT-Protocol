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

// Package connector implements ReplicaConnector interface using gRPC
// as a mechanism to exchange messages with replicas over the network
package connector

import (
	"context"
	"fmt"
	"io"
	"log"

	"google.golang.org/grpc"

	"github.com/hyperledger-labs/minbft/api"
	"github.com/hyperledger-labs/minbft/sample/conn/grpc/proto"
)

// ReplicaConnector implements connectivity API using gRPC as a
// network communication mechanism.
//
// ConnectReplica method establishes a connection to a replica by its
// gRPC target address.
type ReplicaConnector interface {
	api.ReplicaConnector
	ConnectReplica(replicaID uint32, target string, dialOpts ...grpc.DialOption) error
}

// ConnectManyReplicas helps to establish connections to multiple
// replicas. It invokes ConnectReplica on the specified connector for
// each replica in the supplied map. The map holds gRPC target
// addresses indexed by replica ID.
func ConnectManyReplicas(conn ReplicaConnector, targets map[uint32]string, dialOpts ...grpc.DialOption) error {
	for id, target := range targets {
		err := conn.ConnectReplica(id, target, dialOpts...)
		if err != nil {
			return err
		}
	}
	return nil
}

type connector struct {
	clients map[uint32]proto.ChannelClient
}

// New creates a new instance of ReplicaConnector.
func New() ReplicaConnector {
	return &connector{
		clients: make(map[uint32]proto.ChannelClient),
	}
}

// ReplicaMessageStreamHandler returns MessageStreamHandler interface
// to connect to gRPC stream established with the specified replica.
func (c *connector) ReplicaMessageStreamHandler(replicaID uint32) (api.MessageStreamHandler, error) {
	client, ok := c.clients[replicaID]
	if !ok {
		return nil, fmt.Errorf("No client connection to replica %d", replicaID)
	}

	return &messageStreamHandler{replicaID, client}, nil
}

// SetReplicaClient assigns an instance of gRPC client to use for
// establishing message stream with the specified replica.
func (c *connector) SetReplicaClient(replicaID uint32, client proto.ChannelClient) {
	c.clients[replicaID] = client
}

// ConnectReplica establishes a connection to a replica by its gRPC
// target (address).
func (c *connector) ConnectReplica(replicaID uint32, target string, dialOpts ...grpc.DialOption) error {
	connection, err := grpc.Dial(target, dialOpts...)
	if err != nil {
		return fmt.Errorf("Failed to dial replica: %s", err)
	}

	client := proto.NewChannelClient(connection)
	c.SetReplicaClient(replicaID, client)
	return nil
}

// messageStramHandler is a local representation of the replica for
// the purpose of message exchange.
type messageStreamHandler struct {
	replicaID uint32
	client    proto.ChannelClient
}

// HandleMessageStream implements actual communication with remote
// replica by means of the gRPC connection established to the replica.
func (h *messageStreamHandler) HandleMessageStream(in <-chan []byte) <-chan []byte {
	var stream proto.Channel_ChatClient
	ready := make(chan struct{})
	out := make(chan []byte)

	go func() {
		defer close(ready)
		var err error
		stream, err = h.client.Chat(context.Background(), grpc.WaitForReady(true))
		if err != nil {
			log.Printf("Error initializing client stream to replica %d: %s\n",
				h.replicaID, err)
		}
	}()

	go func() {
		<-ready
		for msg := range in {
			err := stream.Send(&proto.Message{Payload: msg})
			if err != nil {
				log.Printf("Error sending to replica %d's client stream: %s\n",
					h.replicaID, err)
				break
			}
		}
		err := stream.CloseSend()
		if err != nil {
			log.Printf("Error closing replica %d's client stream: %s\n",
				h.replicaID, err)
		}
	}()

	go func() {
		defer close(out)
		<-ready
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Printf("Error receiving from replica %d's client stream: %s\n",
					h.replicaID, err)
				break
			}
			out <- msg.Payload

		}
	}()

	return out
}
