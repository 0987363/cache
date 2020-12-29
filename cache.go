package cache

import (
	"bytes"
	"crypto/sha1"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/0987363/cache/persistence"
	"github.com/gin-gonic/gin"
)

var (
	CACHE_MIDDLEWARE_KEY = "gincontrib.cache"
)

var (
	PageCachePrefix = "gincontrib.page.cache"
)

const (
	// ResultLimitHeader is request limit
	ResultLimitHeader = "X-Result-Limit"

	// ResultOffsetHeader is request offset
	ResultOffsetHeader = "X-Result-Offset"

	// ResultSortHeader is request sort
	ResultSortHeader = "X-Result-Sort"

	// ResultCountHeader is request result count
	ResultCountHeader = "X-Result-Count"

	AuthenticationHeader = "X-Druid-Authentication"

	// ResultLastParam url last
	ResultLastHeader = "X-Result-Last"
)

type responseCache struct {
	Status int
	Header http.Header
	Data   []byte
}

// RegisterResponseCacheGob registers the responseCache type with the encoding/gob package
func RegisterResponseCacheGob() {
	gob.Register(responseCache{})
}

type cachedWriter struct {
	gin.ResponseWriter
	status  int
	written bool
	store   persistence.CacheStore
	expire  time.Duration
	key     string
}

var _ gin.ResponseWriter = &cachedWriter{}

func SetPageKey(key string) {
	PageCachePrefix = key
}

// CreateKey creates a package specific key for a given string
func CreateKey(u string) string {
	return urlEscape(PageCachePrefix, u)
}

func urlEscape(prefix string, u string) string {
	key := url.QueryEscape(u)
	if len(key) > 200 {
		h := sha1.New()
		io.WriteString(h, u)
		key = fmt.Sprintf("%x", h.Sum(nil))
	}
	var buffer bytes.Buffer
	buffer.WriteString(prefix)
	buffer.WriteString(":")
	buffer.WriteString(key)
	return buffer.String()
}

func newCachedWriter(store persistence.CacheStore, expire time.Duration, writer gin.ResponseWriter, key string) *cachedWriter {
	return &cachedWriter{writer, 0, false, store, expire, key}
}

func (w *cachedWriter) WriteHeader(code int) {
	w.status = code
	w.written = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *cachedWriter) Status() int {
	return w.ResponseWriter.Status()
}

func (w *cachedWriter) Written() bool {
	return w.ResponseWriter.Written()
}

func (w *cachedWriter) Write(data []byte) (int, error) {
	ret, err := w.ResponseWriter.Write(data)
	if err == nil {
		store := w.store
		var cache responseCache
		if err := store.Get(w.key, &cache); err == nil {
			data = append(cache.Data, data...)
		}

		//cache responses with a status code < 300
		if w.Status() < 300 {
			val := responseCache{
				w.Status(),
				w.Header(),
				data,
			}
			err = store.Set(w.key, val, w.expire)
			if err != nil {
				// need logger
			}
		}
	}
	return ret, err
}

func (w *cachedWriter) WriteString(data string) (n int, err error) {
	ret, err := w.ResponseWriter.WriteString(data)
	//cache responses with a status code < 300
	if err == nil && w.Status() < 300 {
		store := w.store
		val := responseCache{
			w.Status(),
			w.Header(),
			[]byte(data),
		}
		store.Set(w.key, val, w.expire)
	}
	return ret, err
}

// Cache Middleware
func Cache(store persistence.CacheStore) gin.HandlerFunc {
	if store == nil {
		store = persistence.Store
	}
	return func(c *gin.Context) {
		c.Set(CACHE_MIDDLEWARE_KEY, store)
		c.Next()
	}
}

func SiteCache(store persistence.CacheStore, expire time.Duration) gin.HandlerFunc {
	if store == nil {
		store = persistence.Store
	}
	return func(c *gin.Context) {
		var cache responseCache
		key := getKey(c)

		err := store.Get(key, &cache)
		if err == nil {
			c.Writer.WriteHeader(cache.Status)
			for k, vals := range cache.Header {
				for _, v := range vals {
					c.Writer.Header().Set(k, v)
				}
			}
			c.Writer.Write(cache.Data)
			return
		}

		switch err {
		case io.EOF:
			c.Next()
			return
		case persistence.ErrCacheMiss:
			writer := newCachedWriter(store, expire, c.Writer, key)
			c.Writer = writer
			c.Next()

			// Drop caches of aborted contexts
			if c.IsAborted() {
				store.Delete(key)
			}
			return
		default:
			log.Println("Get data failed:", err, key)
			return
		}
	}
}

// CachePage Decorator
func CachePage(store persistence.CacheStore, expire time.Duration, handle gin.HandlerFunc) gin.HandlerFunc {
	if store == nil {
		store = persistence.Store
	}
	return func(c *gin.Context) {
		var cache responseCache
		key := getKey(c)

		err := store.Get(key, &cache)
		if err == nil {
			c.Writer.WriteHeader(cache.Status)
			for k, vals := range cache.Header {
				for _, v := range vals {
					c.Writer.Header().Set(k, v)
				}
			}
			c.Writer.Write(cache.Data)
			return
		}

		switch err {
		case io.EOF:
			handle(c)
			return
		case persistence.ErrCacheMiss:
			writer := newCachedWriter(store, expire, c.Writer, key)
			c.Writer = writer
			handle(c)

			// Drop caches of aborted contexts
			if c.IsAborted() {
				store.Delete(key)
			}
			return
		default:
			log.Println("Get data failed:", err, key)
			return
		}
	}
}

// CachePageWithoutQuery add ability to ignore GET query parameters.
func CachePageWithoutQuery(store persistence.CacheStore, expire time.Duration, handle gin.HandlerFunc) gin.HandlerFunc {
	if store == nil {
		store = persistence.Store
	}
	return func(c *gin.Context) {
		var cache responseCache
		key := getKey(c)
		if err := store.Get(key, &cache); err != nil {
			if err != persistence.ErrCacheMiss {
				log.Println(err.Error())
			}
			// replace writer
			writer := newCachedWriter(store, expire, c.Writer, key)
			c.Writer = writer
			handle(c)
		} else {
			c.Writer.WriteHeader(cache.Status)
			for k, vals := range cache.Header {
				for _, v := range vals {
					c.Writer.Header().Set(k, v)
				}
			}
			c.Writer.Write(cache.Data)
		}
	}
}

// CachePageAtomic Decorator
func CachePageAtomic(store persistence.CacheStore, expire time.Duration, handle gin.HandlerFunc) gin.HandlerFunc {
	if store == nil {
		store = persistence.Store
	}
	var m sync.Mutex
	p := CachePage(store, expire, handle)
	return func(c *gin.Context) {
		m.Lock()
		defer m.Unlock()
		p(c)
	}
}

func CachePageWithoutHeader(store persistence.CacheStore, expire time.Duration, handle gin.HandlerFunc) gin.HandlerFunc {
	if store == nil {
		store = persistence.Store
	}
	return func(c *gin.Context) {
		var cache responseCache
		key := getKey(c)

		err := store.Get(key, &cache)
		if err == nil {
			c.Writer.WriteHeader(cache.Status)
			c.Writer.Write(cache.Data)
			return
		}

		switch err {
		case io.EOF:
			handle(c)
			return
		case persistence.ErrCacheMiss:
			writer := newCachedWriter(store, expire, c.Writer, key)
			c.Writer = writer
			handle(c)

			// Drop caches of aborted contexts
			if c.IsAborted() {
				store.Delete(key)
			}
			return
		default:
			log.Println("Get data failed:", err, key)
			return
		}
	}
}

func getKey(c *gin.Context) string {
	key := c.Request.Method

	referer := c.Request.Header.Get("Referer")
	if referer != "" {
		key = key + "\t" + referer
	}

	token := c.Request.Header.Get(AuthenticationHeader)
	if token == "" {
		token = c.Query(AuthenticationHeader)
	}
	key = key + "\t" + token

	offset := c.Request.Header.Get(ResultOffsetHeader)
	if offset == "" {
		offset = "0"
	}
	key = key + "\t" + offset

	limit := c.Request.Header.Get(ResultLimitHeader)
	if limit == "" {
		limit = "0"
	}
	key = key + "\t" + limit

	sorts := c.Request.Header.Get(ResultSortHeader)
	if sorts == "" {
		sorts = ""
	}
	key = key + "\t" + sorts

	if c.Request.Method == http.MethodPost {
		b, _ := ioutil.ReadAll(c.Request.Body)
		c.Request.Body.Close() //  must close
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		key = key + "\t" + string(b)
	}

	return urlEscape(PageCachePrefix, c.Request.URL.RequestURI()+key)
}
