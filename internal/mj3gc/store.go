package mj3gc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	roleOwner = "owner"
	roleUser  = "user"
)

var (
	ErrKeyNotFound          = errors.New("api key not found")
	ErrKeyDisabled          = errors.New("api key disabled")
	ErrQuotaExceeded        = errors.New("quota exceeded")
	ErrConcurrencyExceeded  = errors.New("concurrency exceeded")
	ErrUserNotFound         = errors.New("user not found")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrDuplicateUsername    = errors.New("duplicate username")
	ErrDuplicateAPIKey      = errors.New("duplicate api key")
	ErrInvalidConfiguration = errors.New("invalid configuration")
)

type Data struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Users     []User    `json:"users"`
	APIKeys   []APIKey  `json:"api_keys"`
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         string    `json:"role"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
}

type APIKey struct {
	ID                string    `json:"id"`
	Key               string    `json:"key"`
	Label             string    `json:"label"`
	UserID            string    `json:"user_id"`
	Enabled           bool      `json:"enabled"`
	TotalLimit        int64     `json:"total_limit"`
	UsedCount         int64     `json:"used_count"`
	ConcurrencyLimit  int       `json:"concurrency_limit"`
	CompatibilityMode bool      `json:"compatibility_mode"`
	CreatedAt         time.Time `json:"created_at"`
}

type Store struct {
	mu       sync.RWMutex
	path     string
	data     Data
	inflight map[string]int
}

var defaultStore = NewStore()

func DefaultStore() *Store { return defaultStore }

func NewStore() *Store {
	return &Store{inflight: make(map[string]int)}
}

func (s *Store) SetPath(path string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.path = strings.TrimSpace(path)
	s.mu.Unlock()
}

func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

func (s *Store) Load() error {
	if s == nil {
		return nil
	}
	path := s.Path()
	if path == "" {
		return ErrInvalidConfiguration
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.mu.Lock()
			s.data = Data{Version: 1, UpdatedAt: time.Now()}
			s.mu.Unlock()
			return nil
		}
		return err
	}
	var data Data
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	if data.Version == 0 {
		data.Version = 1
	}
	s.mu.Lock()
	s.data = data
	s.mu.Unlock()
	return nil
}

func (s *Store) Save() error {
	if s == nil {
		return nil
	}
	path := s.Path()
	if path == "" {
		return ErrInvalidConfiguration
	}
	s.mu.RLock()
	data := s.snapshotLocked()
	s.mu.RUnlock()
	data.UpdatedAt = time.Now()
	payload, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "mj3gc-*.json")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if _, err := tmp.Write(payload); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *Store) snapshotLocked() Data {
	data := Data{
		Version: s.data.Version,
		Users:   append([]User(nil), s.data.Users...),
		APIKeys: append([]APIKey(nil), s.data.APIKeys...),
	}
	return data
}

func (s *Store) Snapshot() Data {
	if s == nil {
		return Data{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked()
}

func (s *Store) UpsertUser(user User) (User, error) {
	if s == nil {
		return User{}, ErrInvalidConfiguration
	}
	if strings.TrimSpace(user.Username) == "" {
		return User{}, fmt.Errorf("username required")
	}
	if user.Role == "" {
		user.Role = roleUser
	}
	if user.Role != roleOwner && user.Role != roleUser {
		return User{}, fmt.Errorf("invalid role")
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.data.Users {
		if strings.EqualFold(existing.Username, user.Username) && existing.ID != user.ID {
			return User{}, ErrDuplicateUsername
		}
	}

	if user.ID == "" {
		user.ID = newID("usr")
		s.data.Users = append(s.data.Users, user)
	} else {
		updated := false
		for i := range s.data.Users {
			if s.data.Users[i].ID == user.ID {
				s.data.Users[i] = user
				updated = true
				break
			}
		}
		if !updated {
			s.data.Users = append(s.data.Users, user)
		}
	}

	return user, nil
}

func (s *Store) DeleteUser(id string) error {
	if s == nil {
		return ErrInvalidConfiguration
	}
	if strings.TrimSpace(id) == "" {
		return ErrUserNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]User, 0, len(s.data.Users))
	found := false
	for _, u := range s.data.Users {
		if u.ID == id {
			found = true
			continue
		}
		out = append(out, u)
	}
	if !found {
		return ErrUserNotFound
	}
	s.data.Users = out
	return nil
}

func (s *Store) FindUserByUsername(username string) (User, bool) {
	if s == nil {
		return User{}, false
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.data.Users {
		if strings.EqualFold(u.Username, username) {
			return u, true
		}
	}
	return User{}, false
}

func (s *Store) FindUserByID(id string) (User, bool) {
	if s == nil {
		return User{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.data.Users {
		if u.ID == id {
			return u, true
		}
	}
	return User{}, false
}

func (s *Store) AuthenticateUser(username, password string) (User, error) {
	user, ok := s.FindUserByUsername(username)
	if !ok || user.Disabled {
		return User{}, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return User{}, ErrInvalidCredentials
	}
	return user, nil
}

func (s *Store) UpsertAPIKey(key APIKey) (APIKey, error) {
	if s == nil {
		return APIKey{}, ErrInvalidConfiguration
	}
	if strings.TrimSpace(key.Key) == "" {
		return APIKey{}, fmt.Errorf("api key required")
	}
	if key.CreatedAt.IsZero() {
		key.CreatedAt = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.data.APIKeys {
		if existing.Key == key.Key && existing.ID != key.ID {
			return APIKey{}, ErrDuplicateAPIKey
		}
	}

	if key.ID == "" {
		key.ID = newID("key")
		s.data.APIKeys = append(s.data.APIKeys, key)
	} else {
		updated := false
		for i := range s.data.APIKeys {
			if s.data.APIKeys[i].ID == key.ID {
				s.data.APIKeys[i] = key
				updated = true
				break
			}
		}
		if !updated {
			s.data.APIKeys = append(s.data.APIKeys, key)
		}
	}

	return key, nil
}

func (s *Store) DeleteAPIKey(id string) error {
	if s == nil {
		return ErrInvalidConfiguration
	}
	if strings.TrimSpace(id) == "" {
		return ErrKeyNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]APIKey, 0, len(s.data.APIKeys))
	found := false
	for _, k := range s.data.APIKeys {
		if k.ID == id {
			found = true
			continue
		}
		out = append(out, k)
	}
	if !found {
		return ErrKeyNotFound
	}
	s.data.APIKeys = out
	return nil
}

func (s *Store) FindAPIKey(value string) (APIKey, bool) {
	if s == nil {
		return APIKey{}, false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return APIKey{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.data.APIKeys {
		if k.Key == value {
			return k, true
		}
	}
	return APIKey{}, false
}

func (s *Store) FindAPIKeyByID(id string) (APIKey, bool) {
	if s == nil {
		return APIKey{}, false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return APIKey{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.data.APIKeys {
		if k.ID == id {
			return k, true
		}
	}
	return APIKey{}, false
}

func (s *Store) ListAPIKeys() []APIKey {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]APIKey, len(s.data.APIKeys))
	copy(out, s.data.APIKeys)
	return out
}

func (s *Store) ListAPIKeysByUser(userID string) []APIKey {
	if s == nil {
		return nil
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]APIKey, 0, len(s.data.APIKeys))
	for _, k := range s.data.APIKeys {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	return out
}

func (s *Store) ListUsers() []User {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, len(s.data.Users))
	copy(out, s.data.Users)
	return out
}

func (s *Store) BeginRequest(value string) (APIKey, error) {
	if s == nil {
		return APIKey{}, ErrInvalidConfiguration
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return APIKey{}, ErrKeyNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.APIKeys {
		if s.data.APIKeys[i].Key != value {
			continue
		}
		key := s.data.APIKeys[i]
		if !key.Enabled {
			return APIKey{}, ErrKeyDisabled
		}
		if key.TotalLimit > 0 && key.UsedCount >= key.TotalLimit {
			return APIKey{}, ErrQuotaExceeded
		}
		if key.ConcurrencyLimit > 0 {
			current := s.inflight[key.ID]
			if current >= key.ConcurrencyLimit {
				return APIKey{}, ErrConcurrencyExceeded
			}
			s.inflight[key.ID] = current + 1
		}
		return key, nil
	}
	return APIKey{}, ErrKeyNotFound
}

func (s *Store) EndRequest(value string, count bool) {
	if s == nil {
		return
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.APIKeys {
		if s.data.APIKeys[i].Key != value {
			continue
		}
		key := &s.data.APIKeys[i]
		if key.ConcurrencyLimit > 0 {
			current := s.inflight[key.ID]
			if current > 0 {
				s.inflight[key.ID] = current - 1
			}
		}
		if count {
			key.UsedCount++
		}
		return
	}
}

func HashPassword(password string) (string, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return "", fmt.Errorf("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func NewAPIKey() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "mj3gc-" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func newID(prefix string) string {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("%s_%s", prefix, base64.RawURLEncoding.EncodeToString(buf))
}

func SanitizeUser(user User) User {
	user.PasswordHash = ""
	return user
}

func SanitizeKey(key APIKey) APIKey {
	return key
}
