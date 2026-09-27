package main

import (
	authapp "github.com/buildset/buildset/auth/app"
	"github.com/buildset/buildset/pkg/serve"
)

func main() { serve.Main(authapp.Run) }
