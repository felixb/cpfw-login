// +build go1.12

package main

import (
	"net/http"
	"time"
)

func loginTypeCookie(host string, time time.Time) *http.Cookie {
	return &http.Cookie{"cpnacportal_login_type", "password", "/", host, time, "", 0, true, false, http.SameSiteLaxMode, "password", []string{"password"}}
}

func userCookie(host string, time time.Time, user string) *http.Cookie {
	return &http.Cookie{"cpnacportal_username", user, "/", host, time, "", 0, true, false, http.SameSiteLaxMode, "password", []string{user}}
}
