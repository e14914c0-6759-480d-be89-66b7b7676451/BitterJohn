package vmess

import (
	"context"
	"net"
	"testing"

	proto "github.com/daeuniverse/softwind/pkg/gun_proto"
	"github.com/daeuniverse/softwind/protocol/direct"
	"github.com/daeuniverse/softwind/protocol/vmess"
	grpc2 "github.com/daeuniverse/softwind/transport/grpc"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"google.golang.org/grpc"
)

func TestServer(t *testing.T) {
	doubleCuckoo := vmess.NewReplayFilter(120)
	svr, err := New(context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	if err = svr.AddPassages([]server.Passage{{
		Manager: false,
		Passage: model.Passage{
			In: model.In{
				From: "",
				Argument: model.Argument{
					Protocol: "vmess",
					Password: "28446de9-2a7e-4fab-827b-6df93e46f945",
				},
			},
			Out: nil,
		},
	}}); err != nil {
		t.Fatal(err)
	}
	t.Log("Listen at localhost:18080")
	if err := svr.Listen("tcp://localhost:18080"); err != nil {
		t.Fatal(err)
	}
}

func TestGrpcServer(t *testing.T) {
	log.SetLogLevel("trace")
	doubleCuckoo := vmess.NewReplayFilter(120)
	svr, err := New(context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	if err = svr.AddPassages([]server.Passage{{
		Manager: false,
		Passage: model.Passage{
			In: model.In{
				From: "",
				Argument: model.Argument{
					Protocol: "vmess",
					Password: "28446de9-2a7e-4fab-827b-6df93e46f945",
				},
			},
			Out: nil,
		},
	}}); err != nil {
		t.Fatal(err)
	}

	lt, err := net.Listen("tcp", "localhost:18443")
	if err != nil {
		t.Fatal(err)
	}
	s := svr.(*Server)
	s.grpc = grpc2.Server{
		Server:     grpc.NewServer(),
		LocalAddr:  lt.Addr(),
		HandleConn: s.handleConn,
	}
	proto.RegisterGunServiceServerX(s.grpc.Server, s.grpc, "GunService")

	t.Log("Serve at https://localhost:18443")
	if err = s.grpc.Serve(lt); err != nil {
		t.Fatal(err)
	}
}
