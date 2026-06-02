package proxy

import (
	"github.com/rakeshguha/redactr/internal/scanner"
)

type ScanPipeline interface {
	ScanAndRedact(text string) (string, *scanner.PipelineReport, error)
}
