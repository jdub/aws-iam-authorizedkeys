package main

import (
	"io/ioutil"
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
		if err := yaml.Unmarshal(y, &cfg); err != nil {
			cfg = config{}
			return
		}

		sort.Strings(cfg.Allowed.Users)
		sort.Strings(cfg.Allowed.Groups)
	}
}
