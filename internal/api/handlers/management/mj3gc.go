package management

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/mj3gc"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
)

type mj3gcUserRequest struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Disabled *bool  `json:"disabled"`
}

type mj3gcKeyRequest struct {
	ID                string `json:"id"`
	Key               *string `json:"key"`
	Label             *string `json:"label"`
	UserID            *string `json:"user_id"`
	Enabled           *bool  `json:"enabled"`
	TotalLimit        *int64 `json:"total_limit"`
	ConcurrencyLimit  *int   `json:"concurrency_limit"`
	CompatibilityMode *bool  `json:"compatibility_mode"`
	ResetUsage        bool   `json:"reset_usage"`
}

type mj3gcKeyUsage struct {
	ID           string `json:"id"`
	Key          string `json:"key"`
	Label        string `json:"label"`
	UserID       string `json:"user_id"`
	TotalLimit   int64  `json:"total_limit"`
	UsedCount    int64  `json:"used_count"`
	Remaining    int64  `json:"remaining"`
	Concurrency  int    `json:"concurrency_limit"`
	CompatMode   bool   `json:"compatibility_mode"`
	TotalRequest int64  `json:"total_requests"`
	TotalTokens  int64  `json:"total_tokens"`
}

type mj3gcLogEntry struct {
	Timestamp int64            `json:"timestamp"`
	Model     string           `json:"model"`
	Failed    bool             `json:"failed"`
	Tokens    usage.TokenStats `json:"tokens"`
}

func (h *Handler) GetMJ3GCState(c *gin.Context) {
	store := mj3gc.DefaultStore()
	if store == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "store unavailable"})
		return
	}
	data := store.Snapshot()
	users := make([]mj3gc.User, 0, len(data.Users))
	for _, u := range data.Users {
		users = append(users, mj3gc.SanitizeUser(u))
	}
	c.JSON(http.StatusOK, gin.H{
		"version":    data.Version,
		"updated_at": data.UpdatedAt,
		"users":      users,
		"api_keys":   data.APIKeys,
	})
}

func (h *Handler) GetMJ3GCUsers(c *gin.Context) {
	store := mj3gc.DefaultStore()
	users := store.ListUsers()
	out := make([]mj3gc.User, 0, len(users))
	for _, u := range users {
		out = append(out, mj3gc.SanitizeUser(u))
	}
	c.JSON(http.StatusOK, gin.H{"users": out})
}

func (h *Handler) UpsertMJ3GCUser(c *gin.Context) {
	var body mj3gcUserRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	store := mj3gc.DefaultStore()
	var user mj3gc.User
	if strings.TrimSpace(body.ID) != "" {
		if existing, ok := store.FindUserByID(strings.TrimSpace(body.ID)); ok {
			user = existing
		}
		user.ID = strings.TrimSpace(body.ID)
	}
	if strings.TrimSpace(body.Username) != "" {
		user.Username = strings.TrimSpace(body.Username)
	}
	if strings.TrimSpace(body.Role) != "" {
		user.Role = strings.TrimSpace(body.Role)
	}
	if body.Disabled != nil {
		user.Disabled = *body.Disabled
	}
	if strings.TrimSpace(body.Password) != "" {
		hash, err := mj3gc.HashPassword(body.Password)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid password"})
			return
		}
		user.PasswordHash = hash
	}

	if user.ID == "" && user.PasswordHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password required for new user"})
		return
	}

	updated, err := store.UpsertUser(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := store.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist store"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": mj3gc.SanitizeUser(updated)})
}

func (h *Handler) DeleteMJ3GCUser(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	store := mj3gc.DefaultStore()
	if err := store.DeleteUser(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := store.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist store"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) GetMJ3GCKeys(c *gin.Context) {
	store := mj3gc.DefaultStore()
	keys := store.ListAPIKeys()
	c.JSON(http.StatusOK, gin.H{"api_keys": keys})
}

func (h *Handler) UpsertMJ3GCKey(c *gin.Context) {
	var body mj3gcKeyRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	store := mj3gc.DefaultStore()
	var key mj3gc.APIKey
	if strings.TrimSpace(body.ID) != "" {
		if existing, ok := store.FindAPIKeyByID(strings.TrimSpace(body.ID)); ok {
			key = existing
		}
		key.ID = strings.TrimSpace(body.ID)
	}
	if body.Key != nil {
		key.Key = strings.TrimSpace(*body.Key)
	}
	if body.Label != nil {
		key.Label = strings.TrimSpace(*body.Label)
	}
	if body.UserID != nil {
		key.UserID = strings.TrimSpace(*body.UserID)
	}
	if body.Enabled != nil {
		key.Enabled = *body.Enabled
	} else if key.ID == "" {
		key.Enabled = true
	}
	if body.TotalLimit != nil {
		key.TotalLimit = *body.TotalLimit
		if key.TotalLimit < 0 {
			key.TotalLimit = 0
		}
	}
	if body.ConcurrencyLimit != nil {
		key.ConcurrencyLimit = *body.ConcurrencyLimit
		if key.ConcurrencyLimit < 0 {
			key.ConcurrencyLimit = 0
		}
	}
	if body.CompatibilityMode != nil {
		key.CompatibilityMode = *body.CompatibilityMode
	}
	if body.ResetUsage {
		key.UsedCount = 0
	}
	if key.Key == "" {
		generated, err := mj3gc.NewAPIKey()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate api key"})
			return
		}
		key.Key = generated
	}

	updated, err := store.UpsertAPIKey(key)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := store.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist store"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_key": updated})
}

func (h *Handler) DeleteMJ3GCKey(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	store := mj3gc.DefaultStore()
	if err := store.DeleteAPIKey(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := store.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist store"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) ResetMJ3GCKeyUsage(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	store := mj3gc.DefaultStore()
	key, ok := store.FindAPIKeyByID(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
		return
	}
	key.UsedCount = 0
	updated, err := store.UpsertAPIKey(key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := store.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist store"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_key": updated})
}

func (h *Handler) GetMJ3GCUsage(c *gin.Context) {
	store := mj3gc.DefaultStore()
	keys := store.ListAPIKeys()
	usageSnapshot := usage.StatisticsSnapshot{}
	if h.usageStats != nil {
		usageSnapshot = h.usageStats.Snapshot()
	}
	out := make([]mj3gcKeyUsage, 0, len(keys))
	for _, key := range keys {
		out = append(out, buildKeyUsage(key, usageSnapshot))
	}
	c.JSON(http.StatusOK, gin.H{
		"keys":  out,
		"stats": usageSnapshot,
	})
}

func (h *Handler) GetMJ3GCPortalMe(c *gin.Context) {
	ctx, ok := getPortalContext(c)
	if !ok {
		return
	}
	store := mj3gc.DefaultStore()
	keys := portalKeys(ctx, store)
	c.JSON(http.StatusOK, gin.H{
		"user": mj3gc.SanitizeUser(ctx.User),
		"keys": keys,
	})
}

func (h *Handler) GetMJ3GCPortalUsage(c *gin.Context) {
	ctx, ok := getPortalContext(c)
	if !ok {
		return
	}
	store := mj3gc.DefaultStore()
	keys := portalKeys(ctx, store)
	usageSnapshot := usage.StatisticsSnapshot{}
	if h.usageStats != nil {
		usageSnapshot = h.usageStats.Snapshot()
	}
	out := make([]mj3gcKeyUsage, 0, len(keys))
	for _, key := range keys {
		out = append(out, buildKeyUsage(key, usageSnapshot))
	}
	c.JSON(http.StatusOK, gin.H{"keys": out})
}

func (h *Handler) GetMJ3GCPortalLogs(c *gin.Context) {
	ctx, ok := getPortalContext(c)
	if !ok {
		return
	}
	store := mj3gc.DefaultStore()
	keys := portalKeys(ctx, store)
	usageSnapshot := usage.StatisticsSnapshot{}
	if h.usageStats != nil {
		usageSnapshot = h.usageStats.Snapshot()
	}
	since := parseSince(c.Query("since"))
	limit := parsePortalLimit(c.Query("limit"))
	items := make([]mj3gcLogEntry, 0, 128)
	for _, key := range keys {
		items = append(items, collectLogsForKey(key, usageSnapshot, since)...)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Timestamp > items[j].Timestamp })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	c.JSON(http.StatusOK, gin.H{"logs": items})
}

func getPortalContext(c *gin.Context) (mj3gc.PortalContext, bool) {
	if c == nil {
		return mj3gc.PortalContext{}, false
	}
	value, ok := c.Get("portal")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return mj3gc.PortalContext{}, false
	}
	ctx, ok := value.(mj3gc.PortalContext)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return mj3gc.PortalContext{}, false
	}
	return ctx, true
}

func portalKeys(ctx mj3gc.PortalContext, store *mj3gc.Store) []mj3gc.APIKey {
	if store == nil {
		return nil
	}
	if ctx.Key != nil {
		return []mj3gc.APIKey{*ctx.Key}
	}
	if ctx.User.ID == "" {
		return nil
	}
	return store.ListAPIKeysByUser(ctx.User.ID)
}

func buildKeyUsage(key mj3gc.APIKey, snapshot usage.StatisticsSnapshot) mj3gcKeyUsage {
	remaining := int64(0)
	if key.TotalLimit > 0 {
		remaining = key.TotalLimit - key.UsedCount
		if remaining < 0 {
			remaining = 0
		}
	}
	stats := snapshot.APIs[key.Key]
	return mj3gcKeyUsage{
		ID:           key.ID,
		Key:          key.Key,
		Label:        key.Label,
		UserID:       key.UserID,
		TotalLimit:   key.TotalLimit,
		UsedCount:    key.UsedCount,
		Remaining:    remaining,
		Concurrency:  key.ConcurrencyLimit,
		CompatMode:   key.CompatibilityMode,
		TotalRequest: stats.TotalRequests,
		TotalTokens:  stats.TotalTokens,
	}
}

func collectLogsForKey(key mj3gc.APIKey, snapshot usage.StatisticsSnapshot, since time.Time) []mj3gcLogEntry {
	stats := snapshot.APIs[key.Key]
	if len(stats.Models) == 0 {
		return nil
	}
	out := make([]mj3gcLogEntry, 0, 64)
	for model, modelStats := range stats.Models {
		for _, detail := range modelStats.Details {
			if !since.IsZero() && detail.Timestamp.Before(since) {
				continue
			}
			out = append(out, mj3gcLogEntry{
				Timestamp: detail.Timestamp.Unix(),
				Model:     model,
				Failed:    detail.Failed,
				Tokens:    detail.Tokens,
			})
		}
	}
	return out
}

func parseSince(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0)
}

func parsePortalLimit(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 200
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 200
	}
	if value > 2000 {
		return 2000
	}
	return value
}
