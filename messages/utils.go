// Copyright (c) 2019 NEC Laboratories Europe GmbH.
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

package messages

import (
	"fmt"
	"encoding/hex"
)

const maxStringWidth = 256

// Stringify returns a human-readable string representing the message
// content that is sufficient for diagnostic output.
func Stringify(msg Message) string {
	var cv uint64
	if msg, ok := msg.(CertifiedMessage); ok {
		cv = msg.UI().Counter
	}

	switch msg := msg.(type) {
	case Hello:
		return fmt.Sprintf("<HELLO replica=%d>", msg.ReplicaID())
	case Request:
		return fmt.Sprintf("<REQUEST client=%d seq=%d operation=%q>",
			msg.ClientID(), msg.Sequence(),
			shortString(string(msg.Operation()), maxStringWidth))
	case Reply:
		return fmt.Sprintf("<REPLY replica=%d seq=%d result=%q>",
			msg.ReplicaID(), msg.Sequence(),
			shortString(string(msg.Result()), maxStringWidth))
	case Prepare:
		req := msg.Request()
		return fmt.Sprintf("<PREPARE cv=%d replica=%d view=%d client=%d seq=%d, secret: %s>",
			cv, msg.ReplicaID(), msg.View(),
			req.ClientID(), req.Sequence(),hex.EncodeToString(msg.UI().Cert))
	case Commit:
		return fmt.Sprintf("<COMMIT cv=%d replica=%d prepare=%s>",
			cv, msg.ReplicaID(), Stringify(msg.Prepare()))
	case Vote:
		return fmt.Sprintf("<VOTE cv=%d replica=%d share=%s>",             msg.Prepare().UI().Counter, msg.ReplicaID(), hex.EncodeToString(msg.Share()))
	case ReqViewChange:
		return fmt.Sprintf("<REQ-VIEW-CHANGE replica=%d newView=%d>",
			msg.ReplicaID(), msg.NewView())
	}

	return "(unknown message)"
}

func shortString(str string, max int) string {
	if max > 0 && len(str) > max {
		return str[0:max-1] + "..."
	}
	return str
}
