package main

import (
	"log"

	"github.com/yushi/sniproxy"
)

func main() {
	proxy := sniproxy.NewSNIProxy()
	if err := proxy.AddCert("server.crt", "server.key", "127.0.0.1:8080"); err != nil {
		log.Fatal(err)
	}
	if err := proxy.AddCert("127.0.0.1.crt", "server.key", "127.0.0.1:8081"); err != nil {
		log.Fatal(err)
	}
	if err := proxy.Listen("tcp", ":443"); err != nil {
		log.Fatal(err)
	}
	proxy.Serve()
}
