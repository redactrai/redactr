package admin

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "redactr_requests_total",
		Help: "Total proxy requests processed.",
	}, []string{"upstream", "status"})

	EntitiesRedactedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "redactr_entities_redacted_total",
		Help: "Total PII entities redacted.",
	}, []string{"entity_type", "layer"})

	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "redactr_request_duration_seconds",
		Help:    "Total request processing time.",
		Buckets: prometheus.DefBuckets,
	}, []string{"upstream"})

	DetectionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "redactr_detection_duration_seconds",
		Help:    "Per-layer detection time.",
		Buckets: prometheus.DefBuckets,
	}, []string{"layer"})

	ErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "redactr_errors_total",
		Help: "Total detection errors.",
	}, []string{"layer", "error_type"})
)
