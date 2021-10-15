package shadowsocks

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lru"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lrulist"
	"math/rand"
	"time"
)

// UserContext is the context of a user which indicates the preferred servers
type UserContext lrulist.LruList

func (ctx *UserContext) Auth(probe func(Key) ([]byte, bool)) (hit *Key, content []byte) {
	lruList := ctx.Infra()
	listCopy := lruList.GetListCopy()
	defer lruList.GiveBackListCopy(listCopy)
	// probe every server
	for i := range listCopy {
		server := listCopy[i].Val.(Key)
		if content, ok := probe(server); ok {
			lruList.Promote(listCopy[i])
			return &server, content
		}
	}
	return nil, nil
}

func (ctx *UserContext) Infra() *lrulist.LruList {
	return (*lrulist.LruList)(ctx)
}

func (ctx *UserContext) Close() error {
	return ctx.Infra().Close()
}

// UserContextPool is a pool which saves the UserContext and eliminates unused UserContext over time
type UserContextPool lru.LRU

func (pool *UserContextPool) Infra() *lru.LRU {
	return (*lru.LRU)(pool)
}

func NewUserContext(keys []Key) *UserContext {
	basicInterval := 10 * time.Second
	offsetRange := 6.0
	offset := time.Duration((rand.Float64()-0.5)*offsetRange*1000) * time.Millisecond
	var list = make([]interface{}, len(keys))
	for i, k := range keys {
		list[i] = k
	}
	ctx := lrulist.NewWithList(basicInterval+offset, lrulist.InsertFront, list)
	return (*UserContext)(ctx)
}

func (s *Server) GetUserContextOrInsert(userIP string) *UserContext {
	userCtx, removed := s.userContextPool.Infra().GetOrInsert(userIP, func() (val interface{}) {
		return NewUserContext(s.keys)
	})
	for _, ev := range removed {
		ev.Value.(*lrulist.LruList).Close()
	}
	return userCtx.(*UserContext)
}
