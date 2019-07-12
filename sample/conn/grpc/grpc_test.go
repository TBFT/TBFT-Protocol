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

package grpc

import (
	"math/rand"
	"net"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"github.com/hyperledger-labs/minbft/api"
	"github.com/hyperledger-labs/minbft/sample/conn/grpc/connector"
	"github.com/hyperledger-labs/minbft/sample/conn/grpc/server"

	mock_api "github.com/hyperledger-labs/minbft/api/mocks"
)

const (
	nrReplicas = 3
	nrMessages = 5
	msgSize    = 32
)

func TestGRPCConnector(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	conn := connector.New()

	replicas, stop := setupConnector(ctrl, conn, nrReplicas)
	defer stop()

	testConnector(t, conn, replicas)
}

func setupConnector(ctrl *gomock.Controller, conn connector.ReplicaConnector, n int) (replicas []*mock_api.MockMessageStreamHandler, stop func()) {
	done := make(chan struct{})
	stop = func() { close(done) }

	addrs := make(map[uint32]string)

	for i := 0; i < n; i++ {
		r := mock_api.NewMockMessageStreamHandler(ctrl)
		replicas = append(replicas, r)

		addrs[uint32(i)] = startNewServer(r, done)
	}

	if err := connector.ConnectManyReplicas(conn, addrs, grpc.WithInsecure()); err != nil {
		panic(err)
	}

	return
}

func testConnector(t *testing.T, conn connector.ReplicaConnector, replicas []*mock_api.MockMessageStreamHandler) {
	wg := new(sync.WaitGroup)
	defer wg.Wait()

	wg.Add(len(replicas))
	for i := range replicas {
		i := i
		go func() {
			defer wg.Done()

			sh, err := conn.ReplicaMessageStreamHandler(uint32(i))
			assert.NoError(t, err)
			testConnection(t, sh, replicas[i])
		}()
	}
}

func testConnection(t *testing.T, sh api.MessageStreamHandler, mockReplica *mock_api.MockMessageStreamHandler) {
	wg := new(sync.WaitGroup)
	defer wg.Wait()

	mockIn := make(chan []byte)
	mockOut := make(chan []byte)

	mockReplica.EXPECT().HandleMessageStream(gomock.Any()).DoAndReturn(
		func(in <-chan []byte) <-chan []byte {
			go func() {
				for m := range in {
					mockIn <- m
				}
			}()

			return mockOut
		},
	)

	out := make(chan []byte)
	in := sh.HandleMessageStream(out)

	wg.Add(1)
	go func() {
		defer wg.Done()
		testStream(t, out, mockIn)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		testStream(t, mockOut, in)
	}()
}

func testStream(t *testing.T, out chan<- []byte, in <-chan []byte) {
	wg := new(sync.WaitGroup)
	defer wg.Wait()

	msgs := makeMessages(nrMessages)

	wg.Add(1)
	go func() {
		defer close(out)
		defer wg.Done()

		for _, m := range msgs {
			out <- m
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for _, m := range msgs {
			assert.Equal(t, m, <-in)
		}
	}()
}

func makeMessages(n int) (msgs [][]byte) {
	for i := 0; i < n; i++ {
		m := make([]byte, msgSize)
		rand.Read(m)
		msgs = append(msgs, m)
	}

	return
}

func startNewServer(replica api.MessageStreamHandler, done chan struct{}) (addr string) {
	srv := server.New(replica)

	go func() {
		<-done
		srv.Stop()
	}()

	return listenAndServe(srv)
}

func listenAndServe(srv server.ReplicaServer) (addr string) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	go func() {
		if err := srv.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return lis.Addr().String()
}
