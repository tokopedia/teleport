package cache

import (
	"github.com/coocood/freecache"
	log "github.com/sirupsen/logrus"
)

var cacheObj *freecache.Cache

func init() {
	cacheSize := 100 * 1024 * 1024
	cacheObj = freecache.NewCache(cacheSize)
}

func Set(key string, val []byte, expire int) error {
	log.Debugf("[Cache] cache set: (%s)", key)
	return cacheObj.Set([]byte(key), val, expire)
}

func Get(key string) ([]byte, error) {
	log.Debugf("[Cache] cache get: (%s)", key)
	got, err := cacheObj.Get([]byte(key))
	log.Debugf("[Cache] cache get: (%s), got (%s), ", key, got)
	return got, err
}
