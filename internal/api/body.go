package api

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type limitedBody struct {
	io.ReadCloser
	c *gin.Context
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	var limit *http.MaxBytesError
	if errors.As(err, &limit) {
		b.c.Set("body_limit_exceeded", true)
	}
	return n, err
}

func (s *Server) limitBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := int64(1 << 20)
		if strings.HasSuffix(c.Request.URL.Path, "/import") {
			limit = 8 << 20
		}
		if c.Request.URL.Path == "/api/v1/geoip/upload" {
			limit = (200 << 20) + (1 << 20)
		}
		if c.Request.ContentLength > limit {
			c.Abort()
			fail(c, http.StatusRequestEntityTooLarge, "请求体超过大小限制")
			return
		}
		c.Request.Body = &limitedBody{ReadCloser: http.MaxBytesReader(c.Writer, c.Request.Body, limit), c: c}
		c.Next()
	}
}
