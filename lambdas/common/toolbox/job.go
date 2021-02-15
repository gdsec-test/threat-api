package toolbox

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/opentracing/opentracing-go"
)

const (
	salt = "Sf(*GO*&$@Feaf"
)

// GenerateJobID Creates a new job id
func (t *Toolbox) GenerateJobID(ctx context.Context) string {
	generateHashSpan, _ := opentracing.StartSpanFromContext(ctx, "GenerateRequestID")
	requestIDSha := sha256.New()
	requestIDSha.Write([]byte(fmt.Sprintf("%d%s", time.Now().UnixNano(), salt)))
	jobID := fmt.Sprintf("%x", requestIDSha.Sum(nil))
	generateHashSpan.Finish()

	return jobID
}
