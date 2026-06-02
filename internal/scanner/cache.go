package scanner

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
)

type CacheStats struct {
	Hits    int64 `json:"hits"`
	Misses  int64 `json:"misses"`
	Size    int   `json:"size"`
	MaxSize int   `json:"max_size"`
}

type cacheEntry struct {
	key          string
	redactedText string
	report       *PipelineReport
}

type Cache struct {
	mu      sync.Mutex
	maxSize int
	items   map[string]*list.Element
	order   *list.List
	hits    atomic.Int64
	misses  atomic.Int64
}

func NewCache(maxSize int) *Cache {
	return &Cache{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}
}

func (c *Cache) Get(text string) (string, *PipelineReport, bool) {
	key := hash(text)
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		c.hits.Add(1)
		return entry.redactedText, entry.report, true
	}

	c.misses.Add(1)
	return "", nil, false
}

func (c *Cache) Put(text, redactedText string, report *PipelineReport) {
	key := hash(text)
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		entry.redactedText = redactedText
		entry.report = report
		return
	}

	if c.order.Len() >= c.maxSize {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*cacheEntry).key)
		}
	}

	entry := &cacheEntry{key: key, redactedText: redactedText, report: report}
	elem := c.order.PushFront(entry)
	c.items[key] = elem
}

func (c *Cache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.order = list.New()
}

func (c *Cache) Stats() CacheStats {
	c.mu.Lock()
	size := c.order.Len()
	c.mu.Unlock()

	return CacheStats{
		Hits:    c.hits.Load(),
		Misses:  c.misses.Load(),
		Size:    size,
		MaxSize: c.maxSize,
	}
}

func hash(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:])
}
