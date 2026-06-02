package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var reportsBucket = []byte("reports")

type ScanReport struct {
	ID         string        `json:"id"`
	Timestamp  time.Time     `json:"timestamp"`
	Provider   string        `json:"provider"`
	Source     string        `json:"source"`
	LatencyMs  int64         `json:"latency_ms"`
	Redactions []Redaction   `json:"redactions"`
	Layers     []LayerResult `json:"layers"`
	Blocked    bool          `json:"blocked"`
	Reason     string        `json:"reason"`
}

type Redaction struct {
	Label    string `json:"label"`
	Original string `json:"original"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Layer    string `json:"layer"`
}

type LayerResult struct {
	Name          string `json:"name"`
	FindingsCount int    `json:"findings_count"`
	LatencyMs     int64  `json:"latency_ms"`
}

type QueryFilter struct {
	Provider string
	Source   string
	Blocked  *bool
	Since    time.Time
	Until    time.Time
	Limit    int
}

type Stats struct {
	TotalScanned   int     `json:"total_scanned"`
	TotalRedactions int    `json:"total_redactions"`
	TotalBlocked   int     `json:"total_blocked"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
}

type Store struct {
	db *bolt.DB
}

func New(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(reportsBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SaveReport(report *ScanReport) (string, error) {
	id := fmt.Sprintf("%d", report.Timestamp.UnixNano())
	report.ID = id

	data, err := json.Marshal(report)
	if err != nil {
		return "", err
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(reportsBucket).Put([]byte(id), data)
	})
	return id, err
}

func (s *Store) GetReport(id string) (*ScanReport, error) {
	var report ScanReport
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(reportsBucket).Get([]byte(id))
		if data == nil {
			return fmt.Errorf("report %s not found", id)
		}
		return json.Unmarshal(data, &report)
	})
	return &report, err
}

func (s *Store) QueryReports(filter QueryFilter) ([]ScanReport, error) {
	var results []ScanReport

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(reportsBucket)
		return b.ForEach(func(k, v []byte) error {
			var r ScanReport
			if err := json.Unmarshal(v, &r); err != nil {
				return nil
			}
			if filter.Provider != "" && r.Provider != filter.Provider {
				return nil
			}
			if filter.Source != "" && r.Source != filter.Source {
				return nil
			}
			if filter.Blocked != nil && r.Blocked != *filter.Blocked {
				return nil
			}
			if !filter.Since.IsZero() && r.Timestamp.Before(filter.Since) {
				return nil
			}
			if !filter.Until.IsZero() && r.Timestamp.After(filter.Until) {
				return nil
			}
			results = append(results, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}
	return results, nil
}

func (s *Store) GetStats(since, until time.Time) (*Stats, error) {
	var stats Stats
	var totalLatency int64

	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(reportsBucket).ForEach(func(k, v []byte) error {
			var r ScanReport
			if err := json.Unmarshal(v, &r); err != nil {
				return nil
			}
			if r.Timestamp.Before(since) || r.Timestamp.After(until) {
				return nil
			}
			stats.TotalScanned++
			stats.TotalRedactions += len(r.Redactions)
			if r.Blocked {
				stats.TotalBlocked++
			}
			totalLatency += r.LatencyMs
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if stats.TotalScanned > 0 {
		stats.AvgLatencyMs = float64(totalLatency) / float64(stats.TotalScanned)
	}
	return &stats, nil
}
