package appseclogging

import (
	"os"

	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// AppLogger is a logger designed to support normal application logging, and Application Security Logging
type AppLogger struct {
	// underlying ZAP logger.
	// We use ZAP because the ECS (elastic common schema) uses ZAP as the JSON formatter
	logger *zap.Logger
	// tags to apply to every log event
	tags []string
	// labels to apply to ever log event
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

// NewLogger creates a new app logger with the provided tags and labels that will be
// applied to each log event.
func NewLogger(tags []string, labels map[string]string) *AppLogger {
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
	l := &AppLogger{logger: logger, tags: append(tagsNew), labels: labels}
	return l
}

// buildZapFields Takes the provided fields and combines them with the logger
// default, returning a slice of zap fields.
func (l AppLogger) buildZapFields(fields Fields, tags []string, labels map[string]string) []zap.Field {
	logEventLabels := l.labels // default lables
	// Add the provided labels
	for key, value := range labels {
		logEventLabels[key] = value
	}

	// Add tags and labels as fields
	zapFields := []zap.Field{
		zap.Any("tags", append(l.tags, tags...)),
		zap.Any("labels", logEventLabels),
	}

	return append(zapFields, fields.toZAPFields()...)
}

// InfoSecurity is a helper function around Info that logs it as a application security log.
// https://github.secureserver.net/CTO/guidelines/blob/master/Standards-Best-Practices/Security/Application-Security-Logging-Standard.md
func (l AppLogger) InfoSecurity(msg string, fields Fields) {
	l.Info(msg, fields, []string{"security"}, nil)
}

// Info logs the provided message with the custom tags and labels
func (l AppLogger) Info(msg string, fields Fields, tags []string, labels map[string]string) {
	l.logger.Info(msg, l.buildZapFields(fields, tags, labels)...)
}

// Debug logs the provided message with the custom tags and labels
func (l AppLogger) Debug(msg string, fields Fields, tags []string, labels map[string]string) {
	l.logger.Debug(msg, l.buildZapFields(fields, tags, labels)...)
}

// Warn logs the provided message with the custom tags and labels
func (l AppLogger) Warn(msg string, fields Fields, tags []string, labels map[string]string) {
	l.logger.Warn(msg, l.buildZapFields(fields, tags, labels)...)
}

// Error logs the provided message with the custom tags and labels
func (l AppLogger) Error(msg string, fields Fields, tags []string, labels map[string]string) {
	l.logger.Error(msg, l.buildZapFields(fields, tags, labels)...)
}

// Fatal logs the provided message with the custom tags and labels
func (l AppLogger) Fatal(msg string, fields Fields, tags []string, labels map[string]string) {
	l.logger.Fatal(msg, l.buildZapFields(fields, tags, labels)...)
}
