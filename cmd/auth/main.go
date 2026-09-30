package main

import (
	authapp "github.com/applicaset/buildset/auth/app"
	"github.com/applicaset/buildset/pkg/serve"
)

func main() { serve.Main(authapp.Run) }
