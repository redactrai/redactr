package scanner

type Finding struct {
	Label      string  `json:"label"`
	Value      string  `json:"value"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
	Layer      string  `json:"layer"`
}

type ScanResult struct {
	Findings []Finding `json:"findings"`
	LayerMs  int64     `json:"layer_ms"`
}

type Layer interface {
	Name() string
	Scan(text string) (*ScanResult, error)
	Ready() bool
}
