package server

type User struct {
	// Optional
	Username string
	// Required
	Password string
	// Optional
	Method string
	// SweetLisa
	Manager bool
	// Required for relay
	ForwardTo string
}
