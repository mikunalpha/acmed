package main

import (
	"fmt"
	"os"
	"time"
)

var interval = 24 // 1 Day

func main() {
	if len(os.Args) == 1 {
		// fmt.Println("usage: acmed <role> [<args>]\n")
		fmt.Println("usage: acmed <command>\n")
		fmt.Println("Notice that you can delete a web folder under webs and restart acmed to re-generate certificates.\n")
		fmt.Println("The options of <command> are: ")
		fmt.Println(" run     Generate certificates of account and webs.")
		fmt.Println(" server  Periodically generate certificates of account and webs.")
		// fmt.Println("The options of args are: ")
		// fmt.Println(" -p [address]  The listening address for challenge ,such as 0.0.0.0:4402 .")
		return
	}

	switch os.Args[1] {
	case "run":
		runRun(os.Args[2:])
	case "server":
		for {
			select {
			case <-time.After(time.Hour * time.Duration(interval)):
				fmt.Println(time.Now())
				runRun(os.Args[2:])
			}
		}
	default:
		fmt.Printf("%q is not valid command.\n", os.Args[1])
		os.Exit(2)
	}
}
