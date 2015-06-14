package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

func initCookies(uri, user string) *cookiejar.Jar {
	u, _ := url.Parse(uri)
	jar, _ := cookiejar.New(nil)
	cookies := make([]*http.Cookie, 2)
	t := time.Now()
	t = t.Add(5 * time.Hour)
	cookies[0] = &http.Cookie{"cpnacportal_login_type", "password", "/", u.Host, t, "", 0, true, false, "password", []string{"password"}}
	cookies[1] = &http.Cookie{"cpnacportal_username", user, "/", u.Host, t, "", 0, true, false, "password", []string{user}}
	// log.Printf("cookies: %v", cookies)
	jar.SetCookies(u, cookies)
	return jar
}

// get a common http client
func httpClient(uri, user string, insecure bool) *http.Client {
	jar := initCookies(uri, user)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
	return &http.Client{Transport: tr, Jar: jar, Timeout: 5 * time.Second}
}

func initHeader(req *http.Request, uri string) {
	r := fmt.Sprintf("%s/PortalMain", uri)
	req.Header.Set("Referer", r)
	req.Header.Set("Origin", r)
	req.Header.Set("User-Agent", agent)
}

func fetch(client *http.Client, uri, path string) ([]byte, error) {
	u := fmt.Sprintf("%s%s", uri, path)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	initHeader(req, uri)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}
	//log.Printf("body for url %s: %s", u, body)
	return body, err
}

// load public key and logintoken from uri + '/RSASettings'
func fetchLoginParams(client *http.Client, uri string) (*LoginParams, error) {
	body, err := fetch(client, uri, "/RSASettings")
	if err != nil {
		return nil, err
	}
	lpr, err := NewLoginParamsRaw(body)
	if err != nil {
		return nil, err
	}
	return NewLoginParams(lpr)
}

// load attributes from uri + '/GetAttributes'
func fetchAttributes(client *http.Client, uri string) (*Attributes, error) {
	body, err := fetch(client, uri, "/GetAttributes")
	if err != nil {
		return nil, err
	}
	var a Attributes
	err = json.Unmarshal(body, &a)
	return &a, err
}

// send encrypted password to server
func sendPassword(client *http.Client, uri, user, password string) (*LoginResponse, error) {
	data := url.Values{}
	data.Set("realm", "passwordRealm")
	data.Set("username", user)
	data.Set("password", password)
	// uri = "http://localhost:8080" // for testing
	u := fmt.Sprintf("%s/Login", uri)
	b := bytes.NewReader([]byte(data.Encode()))
	req, err := http.NewRequest("POST", u, b)
	if err != nil {
		return nil, err
	}
	initHeader(req, uri)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var r LoginResponse
	err = json.Unmarshal(body, &r)
	return &r, err
}
