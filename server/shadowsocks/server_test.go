package shadowsocks

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lru"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"sort"
	"strconv"
	"testing"
	"time"
)

func getState(s *Server, key string) (list []string) {
	val, _ := s.userContextPool.Infra().GetOrInsert(key, func() (val interface{}) {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		return NewUserContext(s.passages)
	})
	nodes := val.(*UserContext).Infra().GetListCopy()
	for _, node := range nodes {
		list = append(list, node.Val.(Passage).In.From)
	}
	val.(*UserContext).Infra().DestroyListCopy(nodes)
	return list
}

func TestServer_AddPassages(t *testing.T) {
	s := Server{
		userContextPool: (*UserContextPool)(lru.New(lru.FixedTimeout, int64(1*time.Hour))),
	}
	if err := s.AddPassages([]server.Passage{{Manager: true}}); err != nil {
		t.Fatal(err)
	}
	if len(s.passages) != 1 {
		t.Fatal()
	} else if !s.passages[0].Manager {
		t.Fatal()
	}
	passages := [][]server.Passage{
		{
			{
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "1",
						Argument: model.Argument{Method: "1"},
					},
				}}, {
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "2",
						Argument: model.Argument{Method: "2"},
					},
				},
			},
		},
		{
			{
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "1",
						Argument: model.Argument{Method: "1"},
					},
				},
			},
		},
		{
			{
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "1",
						Argument: model.Argument{Method: "1"},
					},
				},
			},
			{
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "2",
						Argument: model.Argument{Method: "2"},
					},
				},
			},
		},
	}
	states := [][]string{
		{"", "1", "2"},
		{"", "1"},
		{"", "1", "2"},
	}
	for i := range passages {
		if err := s.SyncPassages(passages[i]); err != nil {
			t.Fatal(err)
		}
		st := getState(&s, "test")
		if len(states[i]) != len(st) {
			t.Fatal("test", strconv.Itoa(i)+":", st, "should be", states[i])
		}
		sort.Strings(st)
		sort.Strings(states[i])
		for j := range st {
			if states[i][j] != st[j] {
				t.Fatal("test", strconv.Itoa(i)+":", st, "should be", states[i])
			}
		}
	}
}
