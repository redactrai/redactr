package contextgate

import (
	"github.com/rakeshguha/redactr/internal/scanner"
)

type Stub struct{}

func New() *Stub             { return &Stub{} }
func (s *Stub) Name() string { return "contextgate" }
func (s *Stub) Ready() bool  { return true }
func (s *Stub) Scan(text string) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{}, nil
}
