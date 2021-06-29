package minbft

import (
	"fmt"
	"sync"

	"github.com/hyperledger-labs/minbft/messages"
	"github.com/hyperledger-labs/minbft/shamir"
)

type voteValidator func(vote messages.Vote) error

type voteApplier func(vote messages.Vote, active bool) error

type voteCollector func(msg messages.Vote, bb []byte) error

type voteAccepter func(replicaID uint32, newView bool, view, primaryCV, replicaCV uint64) error

type voteCounter func(replicaID uint32, view uint64, primaryCV uint64, share []byte) (done bool, secret []byte)

func makeVoteValidator(verifyMessageSignature messageSignatureVerifier) voteValidator {
	return func(vote messages.Vote) error {
		err := verifyMessageSignature(vote)

		if err != nil {
			return fmt.Errorf("Vote Signature is not valid: %s", err)
		}

		return nil

	}
}

func makeVoteApplier(id uint32, collectVote voteCollector) voteApplier {
	return func(vote messages.Vote, active bool) error {
		if id != vote.Prepare().ReplicaID() {
			return nil
		}
		if err := collectVote(vote, vote.Share()); err != nil {
			return fmt.Errorf("vote cannot be taken into account: %s", err)
		}
		return nil
	}
}

func makeVoteCollector(acceptVote voteAccepter, countVote voteCounter, executeRequest requestExecutor) voteCollector {
	var lock sync.Mutex

	return func(msg messages.Vote, bb []byte) error {
		replicaID := msg.ReplicaID()
		var prepare = msg.Prepare()

		view := prepare.View()
		primaryCV := prepare.UI().Counter
		replicaCV := prepare.UI().Counter

		lock.Lock()
		defer lock.Unlock()

		if err := acceptVote(replicaID, false, view, primaryCV, replicaCV); err != nil {
			return fmt.Errorf("cannot accept commitment: %s", err)
		}

		done, _ := countVote(replicaID, view, primaryCV, bb)
		if !done {
			return nil
		}

		executeRequest(prepare.Request())
		return nil
	}
}

func makeVoteAcceptor() voteAccepter {
	var (
		replicaViews   = make(map[uint32]uint64)
		lastPrimaryCVs = make(map[uint32]uint64)
		lastReplicaCVs = make(map[uint32]uint64)
	)

	return func(replicaID uint32, newView bool, view, primaryCV, replicaCV uint64) error {
		if newView {
			if view <= replicaViews[replicaID] {
				return fmt.Errorf("unexpected view number")
			}
			replicaViews[replicaID] = view
		} else {
			if view != replicaViews[replicaID] {
				return fmt.Errorf("unexpected view number")
			}
			if primaryCV != lastPrimaryCVs[replicaID]+1 {
				return fmt.Errorf("non-sequential primary UI")
			}
			if replicaCV != lastReplicaCVs[replicaID]+1 {
				return fmt.Errorf("non-sequential replica UI")
			}
		}

		lastPrimaryCVs[replicaID] = primaryCV
		lastReplicaCVs[replicaID] = replicaCV

		return nil
	}
}

func makeVoteCounter(f uint32) voteCounter {
	var (
		lastView      = uint64(0)
		highest       = make([]uint64, f)
		lastVotes     = make(map[byte][]byte)
		enough        = false
		currentSecret []byte
	)

	return func(replicaId uint32, view uint64, primaryCV uint64, share []byte) (done bool, secret []byte) {
		if view < lastView {
			return false, nil
		}
		if view > lastView {
			lastView = view
			highest = make([]uint64, f)
			lastVotes = make(map[byte][]byte, f)
			enough = false
		}

		for i, cv := range highest {
			if primaryCV > cv {
				highest[i] = primaryCV
				lastVotes[byte(replicaId)] = share
				return false, nil
			}
		}
		if enough == true {
			return true, currentSecret
		}
		enough = true
		lastVotes[byte(replicaId)] = share

		secretss, err := shamir.Combine(lastVotes)
		if err != nil {
			panic(err)
		}
		currentSecret = secretss

		return true, currentSecret
	}

}
