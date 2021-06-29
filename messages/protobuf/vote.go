package protobuf

import (
	"github.com/hyperledger-labs/minbft/messages"
	"github.com/hyperledger-labs/minbft/messages/protobuf/pb"
	"golang.org/x/xerrors"
)

type vote struct {
	pbMsg *pb.Vote
	prep  messages.Prepare
	share []byte
}

func newVote(r uint32, prep messages.Prepare) *vote {
	return &vote{
		pbMsg: &pb.Vote{
			ReplicaId: r,
			Prepare:   pbPrepareFromAPI(prep),
		},
		prep: prep,
	}
}

func newVoteFromPb(pbMsg *pb.Vote) (*vote, error) {
	prep, err := newPrepareFromPb(pbMsg.GetPrepare())
	if err != nil {
		return nil, xerrors.Errorf("cannot unmarshal embedded Prepare: %w", err)
	}
	share := pbMsg.GetShare()	
	return &vote{pbMsg: pbMsg, prep: prep,share:share}, nil
}

func (m *vote) MarshalBinary() ([]byte, error) {
	return marshalMessage(m.pbMsg)
}

func (m *vote) ReplicaID() uint32 {
	return m.pbMsg.GetReplicaId()
}

func (m *vote) Prepare() messages.Prepare {
	return m.prep
}

func (m *vote) Signature() []byte {
	return m.pbMsg.Signature
}

func (m *vote) Share() []byte {
	return m.pbMsg.Share
}

func (m *vote) SetSignature(signature []byte) {
	m.pbMsg.Signature = signature
}

func (m *vote) SetShare(share []byte) {
	m.pbMsg.Share=share
}

func (vote) ImplementsReplicaMessage() {}
func (vote) ImplementsPeerMessage() {}
func (vote) ImplementsVote()        {}

