package main

import "time"

type PacketInfo struct {
	Timestamp     time.Time
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	Protocol      string
	Application   string
	PayloadSize   int
	PayloadHex    string
	SNI           string
	HTTPHost      string
	ContentType   string
	TLSVersion    string
	JA3           string
	Reasons       []string
	PayloadString string
}
