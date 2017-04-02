package main

import (
	"io/ioutil"
	"log"
	"os"
	"sort"

	"gopkg.in/yaml.v2"
)

type config struct {
	Allowed struct {
		Users  []string
		Groups []string
	}
}

const (
	configFile string = "/etc/aws-iam-authorizedkeys.yaml"
)

var (
	cfg config
)

func init() {
	if y, err := ioutil.ReadFile(configFile); err == nil {
		err := yaml.Unmarshal(y, &cfg)

		if err != nil {
			log.Println(err)
			os.Exit(exitCodeError)
		}

		sort.Strings(cfg.Allowed.Users)
		sort.Strings(cfg.Allowed.Groups)
	}
}
