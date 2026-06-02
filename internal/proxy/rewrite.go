package proxy

import (
	"github.com/redactrai/redactr/internal/scanner"
)

type ScanPipeline interface {
	ScanAndRedact(text string) (string, *scanner.PipelineReport, error)
}
