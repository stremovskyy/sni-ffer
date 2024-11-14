package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// GlobalConfig holds the parsed configuration
var GlobalConfig Config

// CLI flags
var (
	iface        string
	snaplen      int64
	promisc      bool
	timeout      time.Duration
	filter       string
	verbose      bool
	tryToDecrypt = false
	lsIfaces     = false
)

func init() {
	flag.StringVar(&iface, "i", "en0", "Interface to capture packets from")
	flag.Int64Var(&snaplen, "s", 1600, "Snapshot length")
	flag.BoolVar(&promisc, "p", true, "Promiscuous mode")
	flag.DurationVar(&timeout, "t", pcap.BlockForever, "Capture timeout")
	flag.StringVar(&filter, "f", "tcp", "BPF filter")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&tryToDecrypt, "d", false, "Try to decrypt payloads")
	flag.BoolVar(&lsIfaces, "ls", false, "List available interfaces")
	flag.Parse()

	configLocations := []string{
		"config.yml",
		"/etc/sni-ffer/config.yml",
		"$HOME/.config/sni-ffer/config.yml",
	}

	configLoaded := false
	for _, loc := range configLocations {
		expandedLoc := os.ExpandEnv(loc)
		if err := LoadConfig(expandedLoc); err == nil {
			configLoaded = true
			break
		}
	}

	if !configLoaded {
		log.Printf("No configuration files found, using default configuration")
		GlobalConfig = defaultConfig
	}

	// Parse timeout duration
	var err error
	timeout, err = time.ParseDuration(GlobalConfig.Timeout)
	if err != nil {
		log.Printf("Invalid timeout value in config, using default: %v", err)
		timeout = pcap.BlockForever
	}

	if iface != "en0" {
		GlobalConfig.Interface = iface
	}

	if snaplen != 1600 {
		GlobalConfig.SnapshotLength = snaplen
	}

	if promisc != true {
		GlobalConfig.PromiscMode = promisc
	}

	if filter != "tcp" {
		GlobalConfig.Filter = filter
	}

	if verbose != false {
		GlobalConfig.Verbose = verbose
	}

	if tryToDecrypt != false {
		tryToDecrypt = true
	}
}

func main() {
	// List interfaces and exit
	if lsIfaces {
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Available interfaces:")
		for _, iface := range ifaces {
			if len(iface.Addresses) > 0 {
				fmt.Printf("\t%s (%s) - %s\n", iface.Name, iface.Description, iface.Addresses[0].IP)
			}
		}
		return
	}

	handle, err := pcap.OpenLive(
		GlobalConfig.Interface,
		int32(GlobalConfig.SnapshotLength),
		GlobalConfig.PromiscMode,
		timeout,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(GlobalConfig.Filter); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Printf("Started capturing on %s...\n\n", GlobalConfig.Interface)

	for packet := range packetSource.Packets() {
		info := analyzePacket(packet)
		if info != nil {
			printPacketInfo(info)
		}
	}
}

func detectProtocol(payload []byte, defaultProtocol string) string {
	if len(payload) == 0 {
		return defaultProtocol
	}

	// Check against protocol patterns
	for proto, pattern := range GlobalConfig.ProtocolPatternsMap {
		if pattern.Match(payload) {
			return proto
		}
	}

	// DNS check (standard query or response)
	if len(payload) > 2 && (payload[2] == 0x01 || payload[2] == 0x02) && len(payload) > 12 {
		return "DNS"
	}

	// QUIC check
	if payload[0] == 0x00 && len(payload) > 5 {
		return "QUIC"
	}

	// HTTP check (HTTP request usually starts with "GET", "POST", etc.)
	if len(payload) > 3 && (payload[0] == 0x47 || payload[0] == 0x50) { // 0x47 = 'G', 0x50 = 'P'
		if string(payload[:3]) == "GET" || string(payload[:3]) == "POST" || string(payload[:3]) == "PUT" || string(payload[:3]) == "DELETE" {
			return "HTTP"
		}
	}

	// FTP check (FTP command starts with "USER", "PASS", etc.)
	if len(payload) > 3 && (payload[0] == 0x55 || payload[0] == 0x50) { // 0x55 = 'U', 0x50 = 'P'
		if string(payload[:4]) == "USER" || string(payload[:4]) == "PASS" {
			return "FTP"
		}
	}

	// TLS/SSL check (TLS handshake starts with 0x16 and version bytes)
	if len(payload) > 0 && payload[0] == 0x16 {
		if len(payload) > 1 && payload[1] == 0x03 { // TLS version starts with 0x03
			return "TLS"
		}
	}

	// Custom Protocol detection via predefined patterns
	for protocol, pattern := range GlobalConfig.ProtocolPatternsMap {
		if pattern.Match(payload) {
			return protocol
		}
	}

	return defaultProtocol
}

func isTLSHandshake(payload []byte) bool {
	return len(payload) > 5 &&
		payload[0] == 0x16 && // Handshake
		payload[1] == 0x03 && // SSL/TLS version
		payload[5] == 0x01 // Client Hello
}

func getTLSVersion(payload []byte) string {
	if len(payload) < 3 {
		return "Unknown"
	}

	switch {
	case payload[1] == 0x03 && payload[2] == 0x00:
		return "SSL 3.0"
	case payload[1] == 0x03 && payload[2] == 0x01:
		return "TLS 1.0"
	case payload[1] == 0x03 && payload[2] == 0x02:
		return "TLS 1.1"
	case payload[1] == 0x03 && payload[2] == 0x03:
		return "TLS 1.2"
	case payload[1] == 0x03 && payload[2] == 0x04:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%02x%02x", payload[1], payload[2])
	}
}

func calculateJA3(payload []byte) string {
	// Simplified JA3 fingerprint calculation
	// In a real implementation, you would extract:
	// - TLS version
	// - Cipher suites
	// - Extensions
	// - Elliptic curves
	// - Elliptic curve formats
	if len(payload) < 40 {
		return ""
	}

	// This is a placeholder - implement full JA3 calculation here
	return fmt.Sprintf("JA3:%x", payload[0:16])
}

func extractHTTPHost(payload []byte) string {
	lines := strings.Split(string(payload), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

func extractContentType(payload []byte) string {
	lines := strings.Split(string(payload), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "content-type:") {
			return strings.TrimSpace(line[13:])
		}
	}
	return ""
}

func identifyApplication(host string) string {
	if host == "" {
		return "Unknown"
	}

	host = strings.ToLower(host)

	for app, domains := range GlobalConfig.Applications {
		for _, domain := range domains {
			if strings.Contains(host, domain) {
				return app
			}
		}
	}

	return "Unknown"
}

func isInterestingPacket(info *PacketInfo, payload []byte) (bool, []string) {
	reasons := []string{}

	// Check for sensitive ports
	sensitivePorts := map[uint16]string{
		22:    "SSH",
		23:    "Telnet",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}

	if proto, ok := sensitivePorts[info.DstPort]; ok {
		reasons = append(reasons, fmt.Sprintf("Sensitive Protocol: %s", proto))
	}

	// Check payload for sensitive data patterns
	if len(payload) > 0 {
		payloadStr := string(payload)
		for patternName, pattern := range GlobalConfig.PatternsMap {
			if pattern.MatchString(payloadStr) {
				reasons = append(reasons, fmt.Sprintf("Contains %s", patternName))
			}
		}

		// Check for interesting HTTP paths
		if info.Protocol == "HTTP" {
			for pathType, pattern := range GlobalConfig.PathsMap {
				if pattern.MatchString(payloadStr) {
					reasons = append(reasons, fmt.Sprintf("Interesting Path: %s", pathType))
				}
			}
		}
	}

	// Check for specific applications
	if info.Application != "Unknown" {
		reasons = append(reasons, fmt.Sprintf("Known Application: %s", info.Application))
	}

	// Check for TLS information
	if info.SNI != "" {
		reasons = append(reasons, fmt.Sprintf("TLS SNI: %s", info.SNI))
	}

	if info.PayloadString != "" && tryToDecrypt {
		reasons = append(reasons, fmt.Sprintf("Payload: %s", info.PayloadString))
	}

	return len(reasons) > 0, reasons
}

func analyzePacket(packet gopacket.Packet) *PacketInfo {
	// Extract IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Extract TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	info := &PacketInfo{
		Timestamp:   packet.Metadata().Timestamp,
		SrcIP:       ip.SrcIP.String(),
		DstIP:       ip.DstIP.String(),
		SrcPort:     uint16(tcp.SrcPort),
		DstPort:     uint16(tcp.DstPort),
		PayloadSize: len(tcp.Payload),
		Application: "Unknown",
	}

	// Existing protocol detection logic...
	if proto, ok := GlobalConfig.WellKnownPorts[info.DstPort]; ok {
		info.Protocol = proto
	} else if proto, ok := GlobalConfig.WellKnownPorts[info.SrcPort]; ok {
		info.Protocol = proto
	}

	if len(tcp.Payload) > 0 {
		info.PayloadHex = hex.EncodeToString(tcp.Payload[:min(16, len(tcp.Payload))])
		info.Protocol = detectProtocol(tcp.Payload, info.Protocol)

		if isTLSHandshake(tcp.Payload) {
			info.Protocol = "TLS"
			info.TLSVersion = getTLSVersion(tcp.Payload)
			info.SNI = extractSNI(tcp.Payload)
			info.JA3 = calculateJA3(tcp.Payload)
			info.Application = identifyApplication(info.SNI)
		}

		if info.Protocol == "HTTP" {
			info.HTTPHost = extractHTTPHost(tcp.Payload)
			info.ContentType = extractContentType(tcp.Payload)
			if info.HTTPHost != "" {
				info.Application = identifyApplication(info.HTTPHost)
			}
		}

		decryptedPayload := TryDecryptPayload(tcp.Payload)
		info.PayloadHex = hex.EncodeToString([]byte(decryptedPayload)[:min(16, len(decryptedPayload))])

		if isReadable([]byte(decryptedPayload)) {
			info.PayloadString = decryptedPayload
		}
	}

	// Check if packet is interesting
	interesting, reasons := isInterestingPacket(info, tcp.Payload)
	if !interesting {
		return nil
	}

	info.Application = strings.Join(reasons, ", ")
	info.Reasons = reasons
	return info
}

func printPacketInfo(info *PacketInfo) {
	// Print timestamp header
	fmt.Printf("\n")
	whiteBold.Printf(
		"[!] Interesting Packet Detected [%s]\n",
		info.Timestamp.Format("15:04:05"),
	)

	// Print connection details
	fmt.Printf(
		"    %s:%d → %s:%d\n",
		info.SrcIP,
		info.SrcPort,
		info.DstIP,
		info.DstPort,
	)

	// Print protocol and size
	fmt.Printf(
		"    Protocol: %s | Size: %d bytes\n",
		info.Protocol,
		info.PayloadSize,
	)

	// Print reasons with appropriate colors
	if len(info.Reasons) > 0 {
		fmt.Print("    Reasons: ")
		for i, reason := range info.Reasons {
			// Determine the color based on the reason type
			var colorPrinter *color.Color = GlobalConfig.ColorMap["Default"]

			if colorPrinter == nil {
				colorPrinter = greenBold
			}

			// Check each category prefix
			for category, printer := range GlobalConfig.ColorMap {
				if strings.Contains(reason, category) {
					colorPrinter = printer
					break
				}
			}

			// Print the reason with the determined color
			colorPrinter.Print(reason)

			// Add comma if not the last reason
			if i < len(info.Reasons)-1 {
				fmt.Print(", ")
			}
		}
		fmt.Println()
	}

	// Print additional details if available
	if info.SNI != "" {
		cyanBold.Printf("    SNI: %s\n", info.SNI)
	}

	if info.TLSVersion != "" {
		cyanBold.Printf("    TLS Version: %s\n", info.TLSVersion)
	}

	if info.HTTPHost != "" {
		blueBold.Printf("    Host: %s\n", info.HTTPHost)
	}

	if info.ContentType != "" {
		whiteBold.Printf("    Content-Type: %s\n", info.ContentType)
	}

	if info.PayloadHex != "" {
		yellowBold.Printf("    Payload Preview: %s\n", info.PayloadHex)
	}

	if info.PayloadString != "" {
		yellowBold.Printf("    Payload Decrypt: %s\n", info.PayloadString)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func extractSNI(payload []byte) string {
	if len(payload) < 43 {
		return ""
	}

	pos := 43
	if pos+1 >= len(payload) {
		return ""
	}
	pos += 1 + int(payload[pos])

	if pos+2 >= len(payload) {
		return ""
	}
	pos += 2 + int(binary.BigEndian.Uint16(payload[pos:pos+2]))

	if pos+1 >= len(payload) {
		return ""
	}
	pos += 1 + int(payload[pos])

	if pos+2 >= len(payload) {
		return ""
	}
	extensionsLength := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	endOfExtensions := pos + extensionsLength
	for pos+4 <= endOfExtensions && pos+4 <= len(payload) {
		if pos+4 > len(payload) {
			return ""
		}
		extensionType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extensionLength := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4

		if extensionType == 0 {
			if pos+2 > len(payload) {
				return ""
			}
			pos += 2

			if pos+1 > len(payload) {
				return ""
			}
			pos++

			if pos+2 > len(payload) {
				return ""
			}
			serverNameLength := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
			pos += 2

			if pos+serverNameLength > len(payload) {
				return ""
			}
			return string(payload[pos : pos+serverNameLength])
		}

		pos += extensionLength
		if pos > len(payload) {
			return ""
		}
	}

	return ""
}

// DecryptXOR decrypts data that has been XOR encrypted with a single byte key.
func DecryptXOR(data []byte, key byte) []byte {
	decrypted := make([]byte, len(data))
	for i := range data {
		decrypted[i] = data[i] ^ key
	}
	return decrypted
}

// DecodeBase64 attempts to decode Base64 encoded data.
func DecodeBase64(data []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// TryDecryptPayload attempts to detect and decrypt payloads.
func TryDecryptPayload(payload []byte) string {
	if strings.Contains(string(payload), "==") || strings.Contains(string(payload), "=") {
		// Attempt Base64 decryption
		decoded, err := DecodeBase64(payload)
		if err == nil {
			return string(decoded)
		}
	}

	// Attempt XOR decryption with a common XOR key (example: 0x5A)
	decryptedXOR := DecryptXOR(payload, 0x5A)
	if isReadable(decryptedXOR) {
		return string(decryptedXOR)
	}

	return string(payload)
}

// Helper to check if decrypted text is readable
func isReadable(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != 9 && b != 10 && b != 13 { // exclude control chars
			return false
		}
	}
	return true
}
