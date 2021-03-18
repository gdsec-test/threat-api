package appseclogging

import (
	"os"

	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type AppSecLogger struct {
	// underlying ZAP logger.
	// We use ZAP because the ECS (elastic common schema) uses ZAP as the JSON formatter
	logger *zap.Logger
	tags   []string
	labels map[string]string
}

// Fields are new fields to add to a logging event.  It is a collection of fields
// mapped to key value pairs.
type Fields map[string]map[string]string

// to ZAPFields converts our custom fields structure to the zap field structure
func (a Fields) toZAPFields() []zap.Field {
	ret := []zap.Field{}
	for key, value := range a {
		ret = append(ret, zap.Any(key, value))
	}
	return ret
}

func NewLogger(tags []string, labels map[string]string) *AppSecLogger {
	encoderConfig := ecszap.NewDefaultEncoderConfig()
	core := encoderConfig.ToZapCoreEncoderConfig()
	core.LevelKey = zapcore.OmitKey
	core.CallerKey = zapcore.OmitKey
	JSONCore := zapcore.NewJSONEncoder(core)
	newCore := zapcore.NewCore(JSONCore, os.Stdout, zap.DebugLevel)
	wrapCore := ecszap.WrapCore(newCore)
	logger := zap.New(wrapCore, zap.AddCaller())
	defer logger.Sync()

	tagsNew := tags
	l := &AppSecLogger{logger: logger, tags: append(tagsNew, "security"), labels: labels}
	return l
}

// requiredFields returns the required fields for every log entry
func (l AppSecLogger) requiredFields() []zap.Field {
	return []zap.Field{
		zap.Any("tags", l.tags),
		zap.Any("labels", l.labels),
	}
}

func (l AppSecLogger) Info(msg string, fields Fields) {
	l.logger.Info(msg, append(l.requiredFields(), fields.toZAPFields()...)...)
}

func (l AppSecLogger) Debug(msg string, fields Fields) {
	l.logger.Debug(msg, append(l.requiredFields(), fields.toZAPFields()...)...)
}

func (l AppSecLogger) Warn(msg string, fields Fields) {
	l.logger.Warn(msg, append(l.requiredFields(), fields.toZAPFields()...)...)
}

func (l AppSecLogger) Error(msg string, fields Fields) {
	l.logger.Error(msg, append(l.requiredFields(), fields.toZAPFields()...)...)
}

func (l AppSecLogger) Fatal(msg string, fields Fields) {
	l.logger.Fatal(msg, append(l.requiredFields(), fields.toZAPFields()...)...)
}
