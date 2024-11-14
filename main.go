package main

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Open the network interface for capturing
	handle, err := pcap.OpenLive("en8", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set BPF filter for TCP traffic on port 443 (HTTPS)
	err = handle.SetBPFFilter("tcp port 443")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Started capturing TLS handshakes on en8...")
	fmt.Println("Listening for SNI information...")

	for packet := range packetSource.Packets() {
		// Get TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, _ := tcpLayer.(*layers.TCP)

		// Check for TLS Client Hello packets
		payload := tcp.Payload
		if len(payload) < 5 {
			continue
		}

		// Check if it's a TLS handshake (Content Type = 22) and Client Hello
		if payload[0] == 0x16 && payload[5] == 0x01 {
			sni := extractSNI(payload)
			if sni != "" {
				fmt.Printf("Detected SNI: %s\n", sni)
			}
		}
	}
}

func extractSNI(payload []byte) string {
	if len(payload) < 43 {
		return ""
	}

	// Skip record header (5 bytes) and handshake header (4 bytes)
	pos := 43

	// Skip session ID
	if pos+1 >= len(payload) {
		return ""
	}
	sessionIDLength := int(payload[pos])
	pos += 1 + sessionIDLength

	// Skip cipher suites
	if pos+2 >= len(payload) {
		return ""
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + cipherSuitesLength

	// Skip compression methods
	if pos+1 >= len(payload) {
		return ""
	}
	compressionMethodsLength := int(payload[pos])
	pos += 1 + compressionMethodsLength

	// Read extensions length
	if pos+2 >= len(payload) {
		return ""
	}
	extensionsLength := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	// Parse extensions
	endOfExtensions := pos + extensionsLength
	for pos+4 <= endOfExtensions {
		extensionType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extensionLength := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4

		// SNI extension type is 0
		if extensionType == 0 {
			// Skip server name list length
			if pos+2 > len(payload) {
				return ""
			}
			pos += 2

			// Skip server name type
			if pos+1 > len(payload) {
				return ""
			}
			pos++

			// Read server name length
			if pos+2 > len(payload) {
				return ""
			}
			serverNameLength := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
			pos += 2

			// Read server name
			if pos+serverNameLength > len(payload) {
				return ""
			}
			return string(payload[pos : pos+serverNameLength])
		}

		pos += extensionLength
	}

	return ""
}
