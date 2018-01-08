package cache

import (
	"bytes"
	"crypto/sha1"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
	"fmt"
	"errors"
	"io/ioutil"

	"github.com/gin-contrib/cache/persistence"
	"github.com/gin-gonic/gin"
)

var (
	CACHE_MIDDLEWARE_KEY = "gincontrib.cache"
)

var (
	PageCachePrefix = "gincontrib.page.cache"
)

const (
    // ResultLimitHeader is request result limit
    ResultLimitHeader = "X-Result-Limit"

    // ResultOffsetHeader is request result offset
    ResultOffsetHeader = "X-Result-Offset"

    // ResultSortHeader is request result sort
    ResultSortHeader = "X-Result-Sort"

    // ResultCountHeader is request result count
    ResultCountHeader = "X-Result-Count"

	AuthenticationHeader = "X-Druid-Authentication"
	AuthenticationParam = "authentication"

    // ResultLimitParam url limit
    ResultLimitParam = "limit"

    // ResultOffsetParam url offset
    ResultOffsetParam = "offset"

    // ResultSortParam url sort
    ResultSortParam = "sort"

    // ResultLastParam url sort
    ResultLastParam = "last"
)

type responseCache struct {
	Status int
	Header http.Header
	Data   []byte
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

func SetKey(key string) {
	CACHE_MIDDLEWARE_KEY = key
}

func SetPageKey(key string) {
	PageCachePrefix = key
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
		//cache response
		store := w.store
		val := responseCache{
			w.status,
			w.Header(),
			data,
		}
		err = store.Set(w.key, val, w.expire)
		if err != nil {
			log.Println("Set key failed,", err)
			// need logger
		}
	}
	return ret, err
}

func (w *cachedWriter) WriteString(data string) (n int, err error) {
	ret, err := w.ResponseWriter.WriteString(data)
	if err == nil {
		//cache response
		store := w.store
		val := responseCache{
			w.status,
			w.Header(),
			[]byte(data),
		}
		store.Set(w.key, val, w.expire)
	}
	return ret, err
}

// Cache Middleware
func Cache(store *persistence.CacheStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(CACHE_MIDDLEWARE_KEY, store)
		c.Next()
	}
}

func SiteCache(store persistence.CacheStore, expire time.Duration) gin.HandlerFunc {

	return func(c *gin.Context) {
		var cache responseCache
		url := c.Request.URL
		key := urlEscape(PageCachePrefix, url.RequestURI())
		if err := store.Get(key, &cache); err != nil {
			c.Next()
		} else {
			c.Writer.WriteHeader(cache.Status)
			for k, vals := range cache.Header {
				for _, v := range vals {
					if (k == "Content-Encoding" && v == "gzip") {
						continue
					}
					switch k {
					case "Access-Control-Allow-Credentials", "Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Vary":
						continue
					}
					c.Writer.Header().Add(k, v)
				}
			}
			c.Writer.Write(cache.Data)
		}
	}
}

// Cache Decorator
func CachePage(store persistence.CacheStore, expire time.Duration, handle gin.HandlerFunc) gin.HandlerFunc {

	return func(c *gin.Context) {
		var cache responseCache

		key, err := getKey(c)
		if err != nil {
			log.Println("get key failed:", err)
			return
		}
		log.Println("Key is:", key)

		if err := store.Get(key, &cache); err != nil {
			log.Println(err.Error())
			// replace writer
			writer := newCachedWriter(store, expire, c.Writer, key)
			c.Writer = writer
			handle(c)
		} else {
			log.Println(cache.Status)
			c.Writer.WriteHeader(cache.Status)
			for k, vals := range cache.Header {
				for _, v := range vals {
					if (k == "Content-Encoding" && v == "gzip") {
						continue
					}
					switch k {
					case "Access-Control-Allow-Credentials", "Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Vary":
						continue
					}
					c.Writer.Header().Add(k, v)
				}
			}
			c.Writer.Write(cache.Data)
		}
	}
}

func getKey(c *gin.Context) (string, error) {
	key := c.Request.Method

    token := c.Query(AuthenticationParam)
    if token == "" {
        token = c.Request.Header.Get(AuthenticationHeader)
        if token == "" {
            return "", errors.New("Token is invalid.")
        }
    }
	key = key + "\t" + token

	offset := c.Query(ResultOffsetParam)
	if offset == "" {
		offset = c.Request.Header.Get(ResultOffsetHeader)
		if offset == "" {
			offset = "0"
		}
	}
	key = key + "\t" + offset

	limit := c.Query(ResultLimitParam)
    if limit == "" {
        limit = c.Request.Header.Get(ResultLimitHeader)
        if limit == "" {
			limit = "0"
        }
    }
	key = key + "\t" + limit

	sorts := c.Query(ResultSortParam)
    if sorts == "" {
        sorts = c.Request.Header.Get(ResultSortHeader)
        if sorts == "" {
			sorts = ""
        }
    }
	key = key + "\t" + sorts

	if c.Request.Method == http.MethodPost {
		b, _ := ioutil.ReadAll(c.Request.Body)
		c.Request.Body.Close()  //  must close
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		key = key + "\t" + string(b)
	}

	return key, nil
}

