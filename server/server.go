package server

type Server interface {
	Listen(addr string) (err error)
	AddUsers(users []User) (err error)
	RemoveUsers(users []User) (err error)
	Users() (users []User)
}

func Register() {

}
