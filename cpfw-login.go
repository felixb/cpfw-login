package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	agent     = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/41.0.2272.76 Chrome/41.0.2272.76 Safari/537.36"
	success   = "SUCCESS"
	auth_fail = "AUTH_FAILURE"
)

type LoginResponse struct {
	Context         string
	Type            string
	Opaque          string
	NextStateId     string
	OrgUrl          string
	keepAliveActive bool
	delayInterval   string
}

type LoginParamsRaw struct {
	M          string
	E          string
	LoginToken string
}

type LoginParams struct {
	PublicKey  rsa.PublicKey
	LoginToken string
}

type Attributes struct {
	CheckStatus        bool
	Authenticated      bool
	AgreementVerified  bool
	AgentConnected     bool
	OrgUrl             string
	AgentOsSupported   bool
	AgentRequired      bool
	TimeToEndOfSession int
	TextToEndOfSession string
	KeepaliveRequired  bool
	KeepaliveInterval  int
}

func (r *LoginResponse) String() string {
	return r.Type
}

func (a *Attributes) String() string {
	return fmt.Sprintf("authenticated: %v, end of session: %s", a.Authenticated, a.TextToEndOfSession)
}

func NewLoginParamsRaw(params []byte) (LoginParamsRaw, error) {
	var lpr LoginParamsRaw
	err := json.Unmarshal(params, &lpr)
	return lpr, err
}

func NewLoginParams(params LoginParamsRaw) (*LoginParams, error) {
	m := new(big.Int)
	m.SetString(params.M, 16)
	e, err := strconv.ParseInt(params.E, 16, 0)
	if err != nil {
		return nil, err
	}
	return &LoginParams{rsa.PublicKey{m, int(e)}, params.LoginToken}, nil
}

func prelogin(client *http.Client, uri string) (*LoginParams, error) {
	_, err := fetch(client, uri, "/PortalMain")
	if err != nil {
		log.Printf("Error loading login page: %v", err)
		return nil, err
	}
	_, err = fetch(client, uri, "/LoginSettings")
	if err != nil {
		log.Printf("Error loading login page: %v", err)
		return nil, err
	}

	lp, err := fetchLoginParams(client, uri)
	if err != nil {
		log.Printf("Error loading login params: %v", err)
		return nil, err
	}

	return lp, nil
}

func login(client *http.Client, uri, user, password string, params *LoginParams) (*LoginResponse, error) {
	crypted_password, err := encrypt(rand.Reader, *params, password)
	if err != nil {
		log.Printf("Error encrypting password: %v", err)
		return nil, err
	}

	response, err := sendPassword(client, uri, user, crypted_password)
	if err != nil {
		log.Printf("Error sending login data: %v", err)
		return nil, err
	}

	if response.Type == auth_fail {
		log.Print("Invalid username/password")
		return nil, err
	}
	if response.Type != success {
		log.Printf("Error logging in: %s", response)
		return nil, err
	}
	log.Printf("Logged in as %s", user)
	return &response, nil
}

func postlogin(client *http.Client, uri string) (*Attributes, error) {
	_, err := fetch(client, uri, "/connect/GetStateAndView")
	if err != nil {
		log.Printf("Error loading post login page: %v", err)
		return nil, err
	}
	_, err = fetch(client, uri, "/connect/css/Final")
	if err != nil {
		log.Printf("Error loading final page: %v", err)
		return nil, err
	}

	attr, err := fetchAttributes(client, uri)
	if err != nil {
		log.Printf("Error loading attributes: %v", err)
		return nil, err
	}
	return attr, nil
}

func check_connection(client *http.Client, uri string) error {
	_, err := fetch(client, uri, "")
	if err != nil {
		log.Printf("Unable to reach %s: %v", uri, err)
		return err
	}
	log.Printf("Reached %s sucessfully", uri)
	return nil
}

func run(client *http.Client, uri, user, password, check string) error {
	if len(check) == 0 || check_connection(client, check) != nil {
		lp, err := prelogin(client, uri)
		if err != nil {
			return err
		}
		_, err = login(client, uri, user, password, lp)
		if err != nil {
			log.Printf("Login failed: %v", err)
			return err
		}
		attr, err := postlogin(client, uri)
		if err != nil {
			log.Printf("Post login failed: %v", err)
			return err
		}
		if attr.TimeToEndOfSession > 0 {
			log.Printf("End of session: %s", attr.TextToEndOfSession)
		} else {
			return errors.New(fmt.Sprintf("Session setup failed: %v", attr))
		}

		if len(check) > 0 {
			return check_connection(client, check)
		}
	}
	return nil
}

func main() {
	var uri string
	var user string
	var password string
	var check_url string
	var interval uint
	flag.StringVar(&uri, "url", os.Getenv("CPFW_AUTH_URL"), "login form base url, also: CPFW_AUTH_URL")
	flag.StringVar(&user, "user", os.Getenv("CPFW_AUTH_USER"), "login username, also: CPFW_AUTH_USER")
	flag.StringVar(&password, "password", os.Getenv("CPFW_AUTH_PASSWORD"), "login password, also: CPFW_AUTH_PASSWORD")
	flag.StringVar(&check_url, "check", os.Getenv("CPFW_AUTH_CHECK_URL"), "check url for successful login, also: CPFW_AUTH_CHECK_URL")
	flag.UintVar(&interval, "interval", 0, "recheck connection every Xs")
	flag.Parse()

	if len(uri) == 0 {
		log.Println("Missing mandatory parameter: uri")
		os.Exit(1)
	}
	log.Printf("Connecting to: %s", uri)

	client := httpClient(uri, user)
	for {
		err := run(client, uri, user, password, check_url)
		if interval <= 0 {
			// exit loop when not looping
			if err != nil {
				log.Printf("unexpected error: %v", err)
				os.Exit(1)
			}
			break
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
}
