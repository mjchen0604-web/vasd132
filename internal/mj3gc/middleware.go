package mj3gc

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// QuotaMiddleware enforces per-key quota and concurrency limits.
func QuotaMiddleware(store *Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			c.Next()
			return
		}
		apiKey, ok := c.Get("apiKey")
		if !ok {
			c.Next()
			return
		}
		keyValue, _ := apiKey.(string)
		if keyValue == "" {
			c.Next()
			return
		}
		_, err := store.BeginRequest(keyValue)
		if err != nil {
			status := http.StatusUnauthorized
			switch err {
			case ErrQuotaExceeded, ErrConcurrencyExceeded:
				status = http.StatusTooManyRequests
			case ErrKeyNotFound, ErrKeyDisabled:
				status = http.StatusUnauthorized
			default:
				status = http.StatusForbidden
			}
			c.AbortWithStatusJSON(status, gin.H{"error": err.Error()})
			return
		}

		c.Next()
		success := c.Writer.Status() < http.StatusBadRequest
		store.EndRequest(keyValue, success)
		if success {
			_ = store.Save()
		}
	}
}
