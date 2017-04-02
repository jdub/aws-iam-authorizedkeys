package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

const (
	exitCodeOk    int = 0
	exitCodeError int = 1
)

var (
	wg sync.WaitGroup
)

func init() {
	// Exit normally if OpenSSH sees a matching key and no longer requires our
	// services
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGPIPE)
	go func() {
		_ = <-signals
		os.Exit(exitCodeOk)
	}()
}

func main() {
	_, DEBUG := os.LookupEnv("DEBUG")

	// Expect user name as first argument, per default OpenSSH configuration:
	// AuthorizedKeysCommand <command> %u
	if len(os.Args) < 2 {
		os.Exit(exitCodeOk)
	}

	userName := os.Args[1]
	allowed := true

	// If we have a user whitelist, check it
	if len(cfg.Allowed.Users) > 0 {
		allowed = false
		i := sort.SearchStrings(cfg.Allowed.Users, userName)
		if i < len(cfg.Allowed.Users) && cfg.Allowed.Users[i] == userName {
			allowed = true
		}
	}

	sess, _ := session.NewSession()
	svc := iam.New(sess)

	// FIXME: check for keys.IsTruncated
	keys, err := svc.ListSSHPublicKeys(
		&iam.ListSSHPublicKeysInput{
			UserName: aws.String(userName),
		})

	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			switch awsErr.Code() {
			// The IAM user doesn't exist, which is fine, but we don't need to
			// do any more work
			case iam.ErrCodeNoSuchEntityException:
				log.Printf("iam::NoSuchEntity user=%s", userName)
				os.Exit(exitCodeOk)
			}
		}
		log.Println(err)
		os.Exit(exitCodeError)
	}

	if DEBUG {
		fmt.Fprintln(os.Stderr, keys)
	}

	// No SSH keys exist for this user, which is fine, but we don't need to
	// do any more work
	if len(keys.SSHPublicKeys) == 0 {
		os.Exit(exitCodeOk)
	}

	// If we have a group whitelist, check it
	if allowed == false && len(cfg.Allowed.Groups) > 0 {
		// FIXME: check for groups.IsTruncated
		groups, err := svc.ListGroupsForUser(
			&iam.ListGroupsForUserInput{
				UserName: aws.String(userName),
			})

		if err != nil {
			log.Println(err)
			os.Exit(exitCodeError)
		}

		for _, group := range groups.Groups {
			i := sort.SearchStrings(cfg.Allowed.Groups, *group.GroupName)
			if i < len(cfg.Allowed.Groups) && cfg.Allowed.Groups[i] == *group.GroupName {
				allowed = true
				break
			}
		}

		if DEBUG {
			fmt.Fprintln(os.Stderr, groups)
		}
	}

	// User is whitelisted (or perhaps in the future, blacklisted)
	if allowed == false {
		os.Exit(exitCodeOk)
	}

	// Finally, fetch all the keys and output them as fast as we can
	for _, key := range keys.SSHPublicKeys {
		if *key.Status != "Active" {
			continue
		}

		wg.Add(1)
		go func() {
			params := &iam.GetSSHPublicKeyInput{
				Encoding:       aws.String("SSH"),
				SSHPublicKeyId: key.SSHPublicKeyId,
				UserName:       aws.String(userName),
			}
			key, err := svc.GetSSHPublicKey(params)

			if DEBUG {
				fmt.Fprintln(os.Stderr, key)
			}

			if err == nil {
				fmt.Printf("%s # %s\n",
					*key.SSHPublicKey.SSHPublicKeyBody, userName)
			}

			wg.Done()
		}()
	}

	wg.Wait()
}
