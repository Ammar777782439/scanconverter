// Package cache provides a two-level LRU + Redis cache for ScanResults.
package cache

import (
 "context"
 "encoding/json"
 "fmt"
 "time"

 lru "github.com/hashicorp/golang-lru/v2"

 "github.com/Ammar777782439/scanconverter/pkg/models"
)

// Cache is the generic caching interface.
type Cache interface {
 Set(key string, value *models.ScanResult, ttl time.Duration) error
 Get(key string) (*models.ScanResult, bool)
 Delete(key string)
 Flush()
}

// --- L1: in-memory LRU ---

// LRUCache wraps hashicorp/golang-lru/v2 with TTL support.
type LRUCache struct {
 cache *lru.Cache[string, *lruEntry]
}

type lruEntry struct {
 value *models.ScanResult
 expiresAt time.Time
}

// NewLRUCache creates an LRU cache with the given capacity.
func NewLRUCache(capacity int) (*LRUCache, error) {
 c, err:= lru.New[string, *lruEntry](capacity)
 if err != nil {
 return nil, fmt.Errorf("NewLRUCache: %w", err)
 }
 return &LRUCache{cache: c}, nil
}

func (c *LRUCache) Set(key string, value *models.ScanResult, ttl time.Duration) error {
 c.cache.Add(key, &lruEntry{
 value: value,
 expiresAt: time.Now().Add(ttl),
 })
 return nil
}

func (c *LRUCache) Get(key string) (*models.ScanResult, bool) {
 entry, ok:= c.cache.Get(key)
 if !ok {
 return nil, false
 }
 if time.Now().After(entry.expiresAt) {
 c.cache.Remove(key)
 return nil, false
 }
 return entry.value, true
}

func (c *LRUCache) Delete(key string) { c.cache.Remove(key) }
func (c *LRUCache) Flush() { c.cache.Purge() }

// --- L2: Redis-backed cache (interface-compatible, Redis client injected) ---

// RedisClient is the minimal interface required from a Redis client.
// Compatible with go-redis v9 (*redis.Client).
type RedisClient interface {
 Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
 Get(ctx context.Context, key string) (string, error)
 Del(ctx context.Context, keys...string) error
}

// RedisCache stores ScanResults in Redis using JSON serialization.
type RedisCache struct {
 client RedisClient
 prefix string
}

// NewRedisCache creates a RedisCache with a key prefix.
func NewRedisCache(client RedisClient, prefix string) *RedisCache {
 return &RedisCache{client: client, prefix: prefix}
}

func (c *RedisCache) key(k string) string { return c.prefix + ":" + k }

func (c *RedisCache) Set(key string, value *models.ScanResult, ttl time.Duration) error {
 b, err:= json.Marshal(value)
 if err != nil {
 return fmt.Errorf("RedisCache Set marshal: %w", err)
 }
 return c.client.Set(context.Background(), c.key(key), string(b), ttl)
}

func (c *RedisCache) Get(key string) (*models.ScanResult, bool) {
 s, err:= c.client.Get(context.Background(), c.key(key))
 if err != nil {
 return nil, false
 }
 var result models.ScanResult
 if err:= json.Unmarshal([]byte(s), &result); err != nil {
 return nil, false
 }
 return &result, true
}

func (c *RedisCache) Delete(key string) {
 _ = c.client.Del(context.Background(), c.key(key))
}

func (c *RedisCache) Flush() {} // Redis flush is a global operation; omit for safety

// --- MultiLevelCache ---

// Option configures a MultiLevelCache.
type Option func(*MultiLevelCache)

// WithLRU sets the L1 LRU cache.
func WithLRU(capacity int) Option {
 return func(m *MultiLevelCache) {
 c, err:= NewLRUCache(capacity)
 if err == nil {
 m.l1 = c
 }
 }
}

// WithRedis sets the L2 Redis cache.
func WithRedis(client RedisClient) Option {
 return func(m *MultiLevelCache) {
 m.l2 = NewRedisCache(client, "sc")
 }
}

// WithTTL sets the default TTL for cache entries.
func WithTTL(ttl time.Duration) Option {
 return func(m *MultiLevelCache) { m.ttl = ttl }
}

// MultiLevelCache checks L1 (LRU) first, then L2 (Redis), with write-through on miss.
type MultiLevelCache struct {
 l1 Cache
 l2 Cache
 ttl time.Duration
}

// NewMultiLevel creates a MultiLevelCache with the given options.
func NewMultiLevel(opts...Option) *MultiLevelCache {
 m:= &MultiLevelCache{ttl: 5 * time.Minute}
 for _, o:= range opts {
 o(m)
 }
 return m
}

// Set writes to both L1 and L2.
func (m *MultiLevelCache) Set(key string, value *models.ScanResult) {
 if m.l1 != nil {
 _ = m.l1.Set(key, value, m.ttl)
 }
 if m.l2 != nil {
 _ = m.l2.Set(key, value, m.ttl)
 }
}

// Get checks L1 first; on miss checks L2 and back-fills L1.
func (m *MultiLevelCache) Get(key string) (*models.ScanResult, bool) {
 if m.l1 != nil {
 if v, ok:= m.l1.Get(key); ok {
 return v, true
 }
 }
 if m.l2 != nil {
 if v, ok:= m.l2.Get(key); ok {
 if m.l1 != nil {
 _ = m.l1.Set(key, v, m.ttl)
 }
 return v, true
 }
 }
 return nil, false
}