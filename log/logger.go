package log

import (
	"fmt"
	"io"
	"log"
)

// Logger is a logger interface
type Logger interface {
	Debug(v ...interface{})
	Debugf(format string, v ...interface{})
	Error(v ...interface{})
	Errorf(format string, v ...interface{})
	Info(v ...interface{})
	Infof(format string, v ...interface{})
	Warn(v ...interface{})
	Warnf(format string, v ...interface{})
}

type SimpleLogger struct {
	DEBUG *log.Logger
	ERR   *log.Logger
	INFO  *log.Logger
	WARN  *log.Logger
}

func NewSimpleLogger(out io.Writer) *SimpleLogger {
	prefix := ""
	flag := log.Ldate | log.Ltime | log.Lshortfile
	return &SimpleLogger{
		DEBUG: log.New(out, fmt.Sprintf("%s [debug] ", prefix), flag),
		ERR:   log.New(out, fmt.Sprintf("%s [error] ", prefix), flag),
		INFO:  log.New(out, fmt.Sprintf("%s [info]  ", prefix), flag),
		WARN:  log.New(out, fmt.Sprintf("%s [warn]  ", prefix), flag),
	}
}

func (s SimpleLogger) Debug(v ...interface{}) {
	_ = s.DEBUG.Output(2, fmt.Sprintln(v...))
}

func (s SimpleLogger) Debugf(format string, v ...interface{}) {
	_ = s.DEBUG.Output(2, fmt.Sprintf(format, v...))
}

func (s SimpleLogger) Error(v ...interface{}) {
	_ = s.ERR.Output(2, fmt.Sprintln(v...))
}

func (s SimpleLogger) Errorf(format string, v ...interface{}) {
	_ = s.ERR.Output(2, fmt.Sprintf(format, v...))
}

func (s SimpleLogger) Info(v ...interface{}) {
	_ = s.INFO.Output(2, fmt.Sprintln(v...))
}

func (s SimpleLogger) Infof(format string, v ...interface{}) {
	_ = s.INFO.Output(2, fmt.Sprintf(format, v...))
}

func (s SimpleLogger) Warn(v ...interface{}) {
	_ = s.WARN.Output(2, fmt.Sprintln(v...))
}

func (s SimpleLogger) Warnf(format string, v ...interface{}) {
	_ = s.WARN.Output(2, fmt.Sprintf(format, v...))
}
