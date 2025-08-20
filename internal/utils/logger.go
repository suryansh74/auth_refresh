package utils

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger *zap.Logger
	once   sync.Once
)

// InitLogger initializes the zap logger based on environment
func InitLogger() *zap.Logger {
	once.Do(func() {
		var err error
		env := os.Getenv("APP_ENV")

		if env == "production" {
			logger, err = newProductionLogger()
		} else {
			logger, err = newDevelopmentLogger()
		}

		if err != nil {
			panic("Failed to initialize zap logger: " + err.Error())
		}
	})
	return logger
}

func newProductionLogger() (*zap.Logger, error) {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	config.OutputPaths = []string{
		"stdout",
		"logs/app.log",
	}
	config.ErrorOutputPaths = []string{
		"stderr",
		"logs/error.log",
	}

	// Ensure logs directory exists
	os.MkdirAll("logs", 0755)

	return config.Build()
}

func newDevelopmentLogger() (*zap.Logger, error) {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	return config.Build()
}

// GetLogger returns the singleton zap.Logger instance
func GetLogger() *zap.Logger {
	if logger == nil {
		return InitLogger()
	}
	return logger
}

// Sync flushes any buffered log entries
func Sync() {
	if logger != nil {
		_ = logger.Sync()
	}
}

// LogField creates structured log fields
func LogField(key string, value interface{}) zap.Field {
	switch v := value.(type) {
	case string:
		return zap.String(key, v)
	case int:
		return zap.Int(key, v)
	case int64:
		return zap.Int64(key, v)
	case uint:
		return zap.Uint(key, v)
	case bool:
		return zap.Bool(key, v)
	case error:
		return zap.Error(v)
	default:
		return zap.Any(key, v)
	}
}
