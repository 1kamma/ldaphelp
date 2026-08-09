package main

import (
	"strings"
	"testing"
)

func TestParseList(t *testing.T) {
	got := parseList("( cn $ sn $ 'mail' )")
	want := []string{"cn", "sn", "mail"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("parseList() = %#v, want %#v", got, want)
	}
}

func TestParseObjectClass(t *testing.T) {
	raw := "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )"
	got := parseObjectClass(raw)
	if got.Name != "person" {
		t.Fatalf("Name = %q", got.Name)
	}
	if strings.Join(got.Sup, "|") != "top" {
		t.Fatalf("Sup = %#v", got.Sup)
	}
	if strings.Join(got.Must, "|") != "sn|cn" {
		t.Fatalf("Must = %#v", got.Must)
	}
	if strings.Join(got.May, "|") != "userPassword|telephoneNumber" {
		t.Fatalf("May = %#v", got.May)
	}
}

func TestParseAttributeType(t *testing.T) {
	raw := "( 2.5.4.3 NAME 'cn' DESC 'Common name' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
	got := parseAttributeType(raw)
	if got.Name != "cn" {
		t.Fatalf("Name = %q", got.Name)
	}
	if got.Desc != "Common name" {
		t.Fatalf("Desc = %q", got.Desc)
	}
	if !strings.Contains(got.Syntax, "Directory String") {
		t.Fatalf("Syntax = %q", got.Syntax)
	}
}
