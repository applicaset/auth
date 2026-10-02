package main

import (
	authapp "github.com/applicaset/auth/app"
	"github.com/applicaset/pkg/serve"
)

func main() { serve.Main(authapp.Run) }
