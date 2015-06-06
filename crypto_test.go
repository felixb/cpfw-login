package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestNewLoginRaw(t *testing.T) {
	lpr, err := NewLoginParamsRaw([]byte("{\"m\": \"37\", \"e\": \"3\", \"logintoken\": \"token\"}"))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if lpr.LoginToken != "token" {
		t.Errorf("Logintoken does not match 'token': %s", lpr.LoginToken)
	}
	if lpr.M != "37" {
		t.Errorf("M does not match '37': %s", lpr.M)
	}
	if lpr.E != "3" {
		t.Errorf("E does not match '3': %s", lpr.E)
	}
}

func TestNewLoginParams(t *testing.T) {
	lpr := LoginParamsRaw{"25", "00011", "token"}
	lp, err := NewLoginParams(lpr)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if lp.LoginToken != "token" {
		t.Errorf("Logintoken does not match 'token': %s", lp.LoginToken)
	}
	if fmt.Sprintf("%d", lp.PublicKey.N) != "37" {
		t.Errorf("M does not match '37': %v", lp.PublicKey.N)
	}
	if lp.PublicKey.E != 17 {
		t.Errorf("E does not match '17': %v", lp.PublicKey.E)
	}
}

func TestReverse(t *testing.T) {
	v := reverse("1234567890")
	if v != "9078563412" {
		t.Errorf("reverse(123456789) is not 9078563412: %s", v)
	}
}

func TestEncrypt(t *testing.T) {
	lpr := LoginParamsRaw{
		"8a272cb8fd28392d75fd5c3958a9fd1ece3ffa0e492fa216a95f57ec0f9546a7d3bc966f3188d5e53a67a8f36d49c1a72297e86f524e44295f21919ac1eff8e784f433ed326063a9a4042e7d33c84dc445574064378fa3d4ab96e85f169c2394d6714a251ecff11ef830795b97032fd2e00e818393af136e21b17c6a50073b3f",
		"00000011",
		"2616d134a4b8bdbe"}
	rd := make([]byte, 1024)
	for i := range rd {
		rd[i] = 0xff
	}
	r := bytes.NewReader(rd)
	expected := "06655cda9f172949fc7dcb1df87e8b85b6d3b3b426f75917235ebc868528988a940744e64e049529d7869fbf76fbac53211c69c4d5852e149b077913943a9fbb71d99c6ce6741052f4841353e32e0f897c713d6496056c3f16e67779a02ddd445dda8f49943a9617c4d6894c98b6892c34782b85aa3223d547d76e9e569cdf07"
	lp, _ := NewLoginParams(lpr)
	v, err := encrypt(r, *lp, "xxx")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if v != expected {
		t.Errorf("encrypt(0xff, 8a272..., 11, xxx) is not '06655cda9f172949fc...': %s", v)
	}
}
