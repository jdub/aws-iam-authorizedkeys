package main

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
)

func init() {
	logwriter, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_AUTH,
		"aws-iam-authorizedkeys")

	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not connect to syslog")
		os.Exit(exitCodeError)
	}
	log.SetOutput(logwriter)
}
