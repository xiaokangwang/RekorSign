package main

import (
	"flag"
	"fmt"
	"github.com/go-openapi/runtime/client"
	"github.com/xiaokangwang/RekorSign/rekorst"
	"github.com/xiaokangwang/RekorSign/serial"
	"os"
)

func main() {
	action := flag.String("action", "genTopicKeyPair", "Action to perform")
	fin := flag.String("fin", "", "input file")
	idin := flag.String("idin", "", "input uuid")
	host := flag.String("host", "rekor.sigstore.dev", "host")
	flag.Parse()
	runtime := client.New(*host, "/", []string{"https"})
	rekostld := rekorst.NewRekoStLd(runtime)
	switch *action {
	case "genTopicKeyPair":
		pub, priv, err := serial.CreateTopicKeyPair()
		if err != nil {
			panic(err)
		}
		fmt.Println(pub)
		fmt.Println(priv)
	case "postSHA512":
		priv, err := os.ReadFile(*fin)
		if err != nil {
			panic(err)
		}
		uuid, err := rekostld.PutSHA512(*idin, string(priv))
		if err != nil {
			panic(err)
		}
		fmt.Println(uuid)
	}

}
