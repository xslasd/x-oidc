package ecode

import (
	"fmt"
	"strconv"
)

var (
	_codes = make(map[int]ECodes, 0)
)

type ECodes interface {
	// Code Status get error code.
	Code() int

	ErrorType() errorType

	Description() string

	// Values get formatted message parameter,it may be nil.
	Values() []string

	ErrorUri() string

	Error() string

	SetDescription(msg string) ECodes
	SetDescriptionf(a ...string) ECodes
	SetErrorUri(url string) ECodes
}

func New(e int, eType errorType, description string, errorUri string) *ecode {
	if _, ok := _codes[e]; ok {
		panic(fmt.Sprintf("ecode: %d already exist", e))
	}
	return &ecode{
		errorType:   eType,
		code:        e,
		description: description,
		errorUri:    errorUri,
		f:           nil,
	}
}

func Cause(e error) ECodes {
	ec, ok := e.(ECodes)
	if ok {
		return ec
	}
	return ServerError.SetDescription(e.Error())
}

type ecode struct {
	errorType   errorType
	code        int
	description string
	errorUri    string
	f           []string
}

func (c *ecode) ErrorType() errorType {
	return c.errorType
}

func (c *ecode) Error() string {
	return strconv.Itoa(c.code)
}
func (c *ecode) Code() int { return c.code }

func (c *ecode) Values() []string {
	return c.f
}
func (c *ecode) Description() string {
	if c.description != "" {
		if c.f != nil {
			return fmt.Sprintf(c.description, c.f)
		}
		return c.description
	}
	return c.description
}
func (c *ecode) ErrorUri() string {
	return c.errorUri
}

func (c *ecode) SetDescription(msg string) ECodes {
	return &ecode{
		errorType:   c.errorType,
		code:        c.code,
		description: msg,
		errorUri:    c.errorUri,
		f:           c.f,
	}
}
func (c *ecode) SetDescriptionf(a ...string) ECodes {
	return &ecode{
		errorType:   c.errorType,
		code:        c.code,
		description: c.description,
		errorUri:    c.errorUri,
		f:           a,
	}
}
func (c *ecode) SetErrorUri(url string) ECodes {
	return &ecode{
		errorType:   c.errorType,
		code:        c.code,
		description: c.description,
		errorUri:    url,
		f:           c.f,
	}
}
