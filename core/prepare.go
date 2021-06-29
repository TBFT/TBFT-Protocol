// Copyright (c) 2018 NEC Laboratories Europe GmbH.
//
// Authors: Wenting Li <wenting.li@neclab.eu>
//          Sergey Fedorov <sergey.fedorov@neclab.eu>
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
	"crypto/sha256"
	"encoding/asn1"
	"fmt"

	"github.com/hyperledger-labs/minbft/messages"
)

// prepareValidator validates a Prepare message.
//
// It authenticates and checks the supplied message for internal
// consistency. It does not use replica's current state and has no
// side-effect. It is safe to invoke concurrently.
type prepareValidator func(prepare messages.Prepare) ([]byte, error)

// prepareApplier applies Prepare message to current replica state.
//
// The supplied message is applied to the current replica state by
// changing the state accordingly and producing any required messages
// or side effects. The supplied message is assumed to be authentic
// and internally consistent. Parameter active indicates if the
// message refers to the active view. It is safe to invoke
// concurrently.
type prepareApplier func(prepare messages.Prepare, bb []byte, active bool) error

// makePrepareValidator constructs an instance of prepareValidator
// using n as the total number of nodes, and the supplied abstract
// interfaces.
func makePrepareValidator(n uint32, verifyUI uiVerifier, validateRequest requestValidator) prepareValidator {
	var previousHash [sha256.Size]byte
	return func(prepare messages.Prepare) ([]byte, error) {
		replicaID := prepare.ReplicaID()
		view := prepare.View()

		if !isPrimary(view, replicaID, n) {
			return nil, fmt.Errorf("Prepare from backup %d for view %d", replicaID, view)
		}

		if err := validateRequest(prepare.Request()); err != nil {
			return nil, fmt.Errorf("Request invalid: %s", err)
		}

		bb, er := verifyUI(prepare)
		if er != nil {
			return nil, fmt.Errorf("UI not valid: %s", er)
		}
		share, secretHash, e := BytesToShareSecret(bb)
		if e != nil {
			return nil, fmt.Errorf("Cannot parse Share and SecretHash")
		}
		previousHash = secretHash
		return share, nil
	}
}

// makePrepareApplier constructs an instance of prepareApplier using
// id as the current replica ID, and the supplied abstract interfaces.
func makePrepareApplier(id uint32, prepareSeq requestSeqPreparer, collectVote voteCollector, handleGeneratedMessage generatedMessageHandler, stopPrepTimer prepareTimerStopper, executeRequest requestExecutor) prepareApplier {

	var pendingRequest messages.Request
	return func(prepare messages.Prepare, bb []byte, active bool) error {
		request := prepare.Request()

		if new := prepareSeq(request); !new {
			return fmt.Errorf("Request already prepared")
		}
		if !active {
			return nil
		}
		if id != prepare.ReplicaID() {
			if prepare.UI().Counter != 1 {
				executeRequest(pendingRequest)
			}

			pendingRequest = prepare.Request()
		}

		stopPrepTimer(request)
		m := messageImpl.NewVote(id, prepare)
		m.SetShare(bb)
		if id != prepare.ReplicaID() {
			handleGeneratedMessage(m)
		}

		return nil
	}
}
func BytesToShareSecret(uibytes []byte) (share []byte, secretHash [sha256.Size]byte, err error) {
	type sharesecret struct {
		S  []byte
		SH []byte
	}
	ss := new(sharesecret)
	ret, err := asn1.Unmarshal(uibytes, ss)
	if err != nil || ret == nil {
		panic(err)
	}
	copy(secretHash[:], ss.SH)
	return ss.S, secretHash, nil
}
