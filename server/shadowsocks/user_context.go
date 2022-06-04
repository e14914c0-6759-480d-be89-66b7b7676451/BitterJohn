package shadowsocks

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lru"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lrulist"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"time"
)

// UserContext is the context of a user which indicates the preferred servers
type UserContext lrulist.LruList

func (ctx *UserContext) Auth(probe func(*Passage) ([]byte, bool)) (hit *Passage, content []byte) {
	lruList := ctx.Infra()
	listCopy := lruList.GetListCopy()
	defer lruList.DestroyListCopy(listCopy)
	// probe every server
	for i := range listCopy {
		server := listCopy[i].Val.(*Passage)
		if content, ok := probe(server); ok {
			lruList.Promote(listCopy[i])
			return server, content
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

func NewUserContext(passages []Passage) *UserContext {
	basicInterval := 10 * time.Second
	offsetRange := 6.0
	offset := time.Duration((fastrand.Float64()-0.5)*offsetRange*1000) * time.Millisecond
	var list = make([]interface{}, len(passages))
	for i := range passages {
		list[i] = &passages[i]
	}
	ctx := lrulist.NewWithList(basicInterval+offset, lrulist.InsertFront, list)
	return (*UserContext)(ctx)
}

func (s *Server) GetUserContextOrInsert(userIP string) *UserContext {
	userCtx, removed := s.userContextPool.Infra().GetOrInsert(userIP, func() (val interface{}) {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		return NewUserContext(s.passages)
	})
	for _, ev := range removed {
		ev.Value.(*UserContext).Close()
	}
	return userCtx.(*UserContext)
}
