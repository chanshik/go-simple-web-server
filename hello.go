package main

import (
	. "github.com/chanshik/go-simple-web-server/server"
	"fmt"
)

func Hello(param *MethodParam) {
	fmt.Fprintf(param.Out, "Hello, World!")
}

func HelloArgs(param *MethodParam) {
	fmt.Fprintf(param.Out, "Hello, %s", param.Vars["name"])
}

func main() {
	errorChan := make(chan error)
	webServer := NewWebServer(errorChan, &WebServerConfig{
		Port: 8080,
		VerboseLog: true,
	})

	webServer.AddHandler("/",
		UrlHandler{
			GET: Method{
				Handler: Hello,
			},
		})

	webServer.AddHandler("/hello/{name:str}",
		UrlHandler{
			GET: Method{
				Handler: HelloArgs,
			},
		})

	webServer.Run()
}
