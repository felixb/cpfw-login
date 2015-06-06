package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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

func prelogin(client *http.Client, uri string) *LoginParams {
	_, err := fetch(client, uri, "/PortalMain")
	if err != nil {
		log.Printf("Error loading login page: %v", err)
		os.Exit(1)
	}
	_, err = fetch(client, uri, "/LoginSettings")
	if err != nil {
		log.Printf("Error loading login page: %v", err)
		os.Exit(1)
	}

	lp, err := fetchLoginParams(client, uri)
	if err != nil {
		log.Printf("Error loading login params: %v", err)
		os.Exit(1)
	}
	return lp
}

func login(client *http.Client, uri, user, password string, params *LoginParams) *LoginResponse {
	crypted_password, err := encrypt(rand.Reader, *params, password)
	if err != nil {
		log.Printf("Error encrypting password: %v", err)
		os.Exit(1)
	}

	response, err := sendPassword(client, uri, user, crypted_password)
	if err != nil {
		log.Printf("Error sending login data: %v", err)
		os.Exit(1)
	}

	if response.Type == auth_fail {
		log.Print("Invalid username/password")
		os.Exit(1)
	}
	if response.Type != success {
		log.Printf("Error logging in: %s", response)
		os.Exit(1)
	}
	log.Printf("Logged in as %s", user)
	return &response
}

func postlogin(client *http.Client, uri string) *Attributes {
	_, err := fetch(client, uri, "/connect/GetStateAndView")
	if err != nil {
		log.Printf("Error loading post login page: %v", err)
		os.Exit(1)
	}
	_, err = fetch(client, uri, "/connect/css/Final")
	if err != nil {
		log.Printf("Error loading final page: %v", err)
		os.Exit(1)
	}

	attr, err := fetchAttributes(client, uri)
	if err != nil {
		log.Printf("Error loading attributes: %v", err)
		os.Exit(1)
	}
	return attr
}

func check_connection(client *http.Client, uri string) bool {
	_, err := fetch(client, uri, "")
	if err != nil {
		log.Printf("Unable to reach %s: %v", uri, err)
		return false
	}
	log.Printf("Reached %s sucessfully", uri)
	return true
}

func run(client *http.Client, uri, user, password, check string) {
	if len(check) == 0 || !check_connection(client, check) {
		lp := prelogin(client, uri)
		login(client, uri, user, password, lp)
		postlogin(client, uri)
		attr := postlogin(client, uri)
		if attr.TimeToEndOfSession > 0 {
			log.Printf("End of session: %s", attr.TextToEndOfSession)
		} else {
			log.Printf("Session setup failed: %v", attr)
			os.Exit(1)
		}

		if len(check) > 0 {
			check_connection(client, check)
		}
	}
}

func main() {
	var uri string
	var user string
	var password string
	var check string
	var interval uint
	flag.StringVar(&uri, "url", os.Getenv("CPFW_AUTH_URL"), "login form base url, also: CPFW_AUTH_URL")
	flag.StringVar(&user, "user", os.Getenv("CPFW_AUTH_USER"), "login username, also: CPFW_AUTH_USER")
	flag.StringVar(&password, "password", os.Getenv("CPFW_AUTH_PASSWORD"), "login password, also: CPFW_AUTH_PASSWORD")
	flag.StringVar(&check, "check", os.Getenv("CPFW_AUTH_CHECK_URL"), "check url for successful login, also: CPFW_AUTH_CHECK_URL")
	flag.UintVar(&interval, "interval", 0, "recheck connection every Xs")
	flag.Parse()

	if len(uri) == 0 {
		log.Println("Missing mandatory parameter: uri")
		os.Exit(1)
	}
	log.Printf("Connecting to: %s", uri)

	client := httpClient(uri, user)
	run(client, uri, user, password, check)
	if interval > 0 {
		for {
			time.Sleep(time.Duration(interval) * time.Second)
			run(client, uri, user, password, check)
		}
	}
}
