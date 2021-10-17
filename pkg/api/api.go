package api

import (
	"context"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"net/http"
	"time"
)

func Register() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	http.NewRequestWithContext(ctx, "POST", config.GetConfig().SweetLisa, nil)
}
