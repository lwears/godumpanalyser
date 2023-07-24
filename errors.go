package main

import (
	"errors"
)

var (
	ErrReadingFile  = errors.New("error reading file")
	ErrCreatingFile = errors.New("error creating file")
	ErrParsingLine  = errors.New("error parsing line")
	ErrLineLength   = errors.New("line length error")
)
