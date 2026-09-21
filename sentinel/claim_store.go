package sentinel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/arkeonetwork/arkeo/common"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type ClaimStore struct {
	mu     sync.Mutex
	logger zerolog.Logger
	db     *leveldb.DB
}

type Claim struct {
	Provider   common.PubKey `json:"provider"`
	ContractId uint64        `json:"contract_id"`
	Spender    common.PubKey `json:"spender"`
	Nonce      int64         `json:"nonce"`
	Signature  string        `json:"signature"`
	Claimed    bool          `json:"claimed"`
}

func NewClaim(contractId uint64, spender common.PubKey, nonce int64, signature string) Claim {
	return Claim{
		ContractId: contractId,
		Spender:    spender,
		Nonce:      nonce,
		Signature:  signature,
		Claimed:    false,
	}
}

func NewClaimStore(levelDbFolder string) (*ClaimStore, error) {
	var db *leveldb.DB
	var err error
	if len(levelDbFolder) == 0 {
		log.Warn().Msg("level db folder is empty, create in memory storage")
		// no directory given, use in memory store
		storage := storage.NewMemStorage()
		db, err = leveldb.Open(storage, nil)
		if err != nil {
			return nil, fmt.Errorf("fail to in memory open level db: %w", err)
		}
	} else {
		db, err = leveldb.OpenFile(levelDbFolder, nil)
		if err != nil {
			return nil, fmt.Errorf("fail to open level db %s: %w", levelDbFolder, err)
		}
	}
	return &ClaimStore{
		logger: log.With().Str("module", "claim-storage").Logger(),
		db:     db,
	}, nil
}

var ErrClaimNonce = errors.New("claim nonce must increase")

func (s *ClaimStore) write(item Claim) error {
	buf, err := json.Marshal(item)
	if err != nil {
		return err
	}
	return s.db.Put([]byte(item.Key()), buf, &opt.WriteOptions{Sync: true})
}

// Accept atomically reserves a nonce before an authorized request is served.
func (s *ClaimStore) Accept(item Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.Get(item.Key())
	if err != nil {
		return err
	}
	if item.Nonce <= 0 || old.Nonce >= item.Nonce {
		return ErrClaimNonce
	}
	return s.write(item)
}

func (s *ClaimStore) Set(item Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.Get(item.Key())
	if err != nil {
		return err
	}
	if item.Nonce < old.Nonce || (item.Nonce == old.Nonce && old.Claimed && !item.Claimed) {
		return ErrClaimNonce
	}
	return s.write(item)
}

// A delayed settlement must never overwrite a newer unclaimed authorization.
func (s *ClaimStore) MarkClaimed(contractID uint64, nonce int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strconv.FormatUint(contractID, 10)
	item, err := s.Get(key)
	if err != nil {
		return false, err
	}
	if item.ContractId != contractID || item.Nonce != nonce {
		return false, nil
	}
	item.Claimed = true
	return true, s.write(item)
}

func (s *ClaimStore) Batch(items []Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := new(leveldb.Batch)
	pending := make(map[string]Claim)
	for _, item := range items {
		old, err := s.Get(item.Key())
		if err != nil {
			return err
		}
		if staged, ok := pending[item.Key()]; ok {
			old = staged
		}
		if item.Nonce < old.Nonce || (item.Nonce == old.Nonce && old.Claimed && !item.Claimed) {
			return ErrClaimNonce
		}
		key := item.Key()
		buf, err := json.Marshal(item)
		if err != nil {
			s.logger.Error().Err(err).Msg("fail to marshal to claim store item")
			return err
		}
		batch.Put([]byte(key), buf)
		pending[key] = item
	}
	return s.db.Write(batch, &opt.WriteOptions{Sync: true})
}

func (s *ClaimStore) Get(key string) (item Claim, err error) {
	buf, err := s.db.Get([]byte(key), nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return item, nil
	}
	if err != nil {
		return item, err
	}
	if err := json.Unmarshal(buf, &item); err != nil {
		s.logger.Error().Err(err).Msg("fail to unmarshal to claim store item")
		return item, err
	}

	return
}

// Has check whether the given key exist in key value store
func (s *ClaimStore) Has(key string) (ok bool) {
	ok, _ = s.db.Has([]byte(key), nil)
	return
}

// Remove remove the given item from key values store
func (s *ClaimStore) Remove(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Delete([]byte(key), &opt.WriteOptions{Sync: true})
}

// List send back tx out to retry depending on arg failed only
func (s *ClaimStore) List() []Claim {
	iterator := s.db.NewIterator(util.BytesPrefix([]byte(nil)), nil)
	defer iterator.Release()
	var results []Claim
	for iterator.Next() {
		buf := iterator.Value()
		if len(buf) == 0 {
			continue
		}

		var item Claim
		if err := json.Unmarshal(buf, &item); err != nil {
			s.logger.Error().Err(err).Msg("fail to unmarshal to claim store item")
			continue
		}

		results = append(results, item)
	}

	return results
}

// Close underlying db
func (s *ClaimStore) Close() error {
	return s.db.Close()
}

func (s *ClaimStore) GetInternalDb() *leveldb.DB {
	return s.db
}

func (c Claim) Key() string {
	return strconv.FormatUint(c.ContractId, 10)
}
