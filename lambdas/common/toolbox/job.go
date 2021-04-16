package toolbox

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"time"
)

const (
	salt = "Sf(*GO*&$@Feaf"
)

// GenerateJobID Creates a new job id
func (t *Toolbox) GenerateJobID(ctx context.Context) string {
	generateHashSpan, _ := t.TracerLogger.StartSpan(ctx, "GenerateRequestID", "job", "jobid", "generate")
	requestIDSha := sha256.New()
	requestIDSha.Write([]byte(fmt.Sprintf("%d%s", time.Now().UnixNano(), salt)))
	jobID := fmt.Sprintf("%x", requestIDSha.Sum(nil))
	generateHashSpan.End(ctx)

	return jobID
}

// CreateExecuteSpan is a helper function to standardize logging the execution of a module.
// It creates a standardized "Execute" span with the module name and jobID.
// This makes it easier to trace execution of the modules
func (t *Toolbox) CreateExecuteSpan(ctx context.Context, moduleName string, jobID string, iocType string) (*appsectracing.Span, context.Context) {
	span, spanCtx := t.TracerLogger.StartSpan(ctx, "Execute", "module", "", "execute")
	defer span.End(spanCtx)
	span.LogKV("moduleName", moduleName)
	span.LogKV("jobID", jobID)
	span.LogKV("iocType", iocType)

	return span, spanCtx
}
