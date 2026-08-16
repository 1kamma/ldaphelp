package main

import "testing"

func TestParseObjectClassExtractsReadableMetadata(t *testing.T) {
	def := "( 1.2.840.113556.1.5.9 NAME ( 'groupOfNames' 'group' ) DESC 'Group of names' SUP top STRUCTURAL MUST ( cn $ member ) MAY ( description $ owner ) )"
	parsed := parseObjectClass(def)

	if parsed.OID != "1.2.840.113556.1.5.9" {
		t.Fatalf("expected OID, got %q", parsed.OID)
	}
	if parsed.Name != "groupofnames" {
		t.Fatalf("expected primary name groupofnames, got %q", parsed.Name)
	}
	if parsed.Kind != "STRUCTURAL" {
		t.Fatalf("expected structural kind, got %q", parsed.Kind)
	}
	if len(parsed.Aliases) != 2 || parsed.Aliases[1] != "group" {
		t.Fatalf("expected aliases to include group, got %#v", parsed.Aliases)
	}
	if len(parsed.Must) != 2 || parsed.Must[0] != "cn" || parsed.Must[1] != "member" {
		t.Fatalf("unexpected MUST attrs: %#v", parsed.Must)
	}
	if len(parsed.May) != 2 || parsed.May[0] != "description" || parsed.May[1] != "owner" {
		t.Fatalf("unexpected MAY attrs: %#v", parsed.May)
	}
}

func TestParseAttributeTypeExtractsAliasesSyntaxAndFlags(t *testing.T) {
	def := "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'Common name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
	parsed := parseAttributeType(def)

	if parsed.OID != "2.5.4.3" {
		t.Fatalf("expected OID, got %q", parsed.OID)
	}
	if parsed.Name != "cn" {
		t.Fatalf("expected primary name cn, got %q", parsed.Name)
	}
	if len(parsed.Aliases) != 2 || parsed.Aliases[1] != "commonname" {
		t.Fatalf("unexpected aliases: %#v", parsed.Aliases)
	}
	if parsed.Syntax != "Directory String (1.3.6.1.4.1.1466.115.121.1.15)" {
		t.Fatalf("unexpected syntax: %q", parsed.Syntax)
	}
	if !parsed.SingleValue {
		t.Fatal("expected SINGLE-VALUE to be detected")
	}
}

func TestEncodeBinaryAttributeValueUsesImageDataURLForPhotos(t *testing.T) {
	jpgHeader := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46}
	encoded := encodeBinaryAttributeValue("jpegPhoto", jpgHeader)
	if got := encoded[:22]; got != "data:image/jpeg;base64" {
		t.Fatalf("expected jpeg data url prefix, got %q", got)
	}
}

func TestEncodeBinaryAttributeValueUsesBase64PrefixForNonImages(t *testing.T) {
	encoded := encodeBinaryAttributeValue("objectGUID", []byte{0x00, 0x01, 0x02, 0x03})
	if len(encoded) < 7 || encoded[:7] != "base64:" {
		t.Fatalf("expected base64 prefix, got %q", encoded)
	}
}
