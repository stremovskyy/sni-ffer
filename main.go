package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Packet metadata structure
type PacketInfo struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	Application string
	PayloadSize int
	PayloadHex  string
	SNI         string
	HTTPHost    string
	ContentType string
	TLSVersion  string
	JA3         string
	Reasons     []string
}

// Protocol definitions
var (
	// Color formatters
	redBold     = color.New(color.FgRed, color.Bold)
	greenBold   = color.New(color.FgGreen, color.Bold)
	yellowBold  = color.New(color.FgYellow, color.Bold)
	blueBold    = color.New(color.FgBlue, color.Bold)
	magentaBold = color.New(color.FgMagenta, color.Bold)
	cyanBold    = color.New(color.FgCyan, color.Bold)
	grayBold    = color.New(color.FgBlack, color.Bold)
	whiteBold   = color.New(color.FgWhite, color.Bold)

	// Color categories for different types of detections
	colorMap = map[string]*color.Color{
		"Authentication":     redBold,     // Security sensitive
		"API Key":            redBold,     // Security sensitive
		"Credit Card":        redBold,     // Security sensitive
		"Private Key":        redBold,     // Security sensitive
		"JWT":                redBold,     // Security sensitive
		"Email":              yellowBold,  // Personal data
		"Sensitive Protocol": magentaBold, // Protocol detection
		"Known Application":  blueBold,    // Application detection
		"TLS SNI":            cyanBold,    // TLS related
		"Interesting Path":   greenBold,   // HTTP paths
		"Default":            grayBold,    // Default color
	}

	sensitiveDataPatterns = map[string]*regexp.Regexp{
		"Email":          regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		"Credit Card":    regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`),
		"Authentication": regexp.MustCompile(`(?i)login|credential|password|token|key|secret|bearer`),
		"API Key":        regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?key|secret[_-]?key).[a-zA-Z0-9]{16,}`),
		"JWT":            regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
		"Private Key":    regexp.MustCompile(`(?i)-----BEGIN.*PRIVATE KEY-----`),
	}

	// Interesting domains and paths
	interestingPaths = map[string]*regexp.Regexp{
		"Login":         regexp.MustCompile(`(?i)/login|/auth|/signin|/oauth`),
		"Admin":         regexp.MustCompile(`(?i)/admin|/console|/dashboard`),
		"API":           regexp.MustCompile(`(?i)/api/|/v1/|/v2/|/graphql`),
		"Payment":       regexp.MustCompile(`(?i)/payment|/checkout|/cart`),
		"User Data":     regexp.MustCompile(`(?i)/user|/account|/profile`),
		"File Transfer": regexp.MustCompile(`(?i)/upload|/download|/file|/document`),
	}

	// Sensitive ports and protocols remain the same as in original
	wellKnownPorts = map[uint16]string{
		80:    "HTTP",
		443:   "HTTPS",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		110:   "POP3",
		143:   "IMAP",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}

	// Application layer patterns
	patterns = map[string]*regexp.Regexp{
		"HTTP":       regexp.MustCompile(`^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|TRACE)\s`),
		"TLS":        regexp.MustCompile(`^\x16\x03[\x00-\x03]`),
		"SSH":        regexp.MustCompile(`^SSH-\d\.\d`),
		"SMTP":       regexp.MustCompile(`^(?:220|250|354|450|500)`),
		"FTP":        regexp.MustCompile(`^(?:220|230|331|530)`),
		"DNS":        regexp.MustCompile(`^.{2}[\x01\x02].{2}`),
		"BitTorrent": regexp.MustCompile(`^(\x13|d1:)BitTorrent protocol`),
	}

	// Common application signatures
	appSignatures = map[string][]string{
		"Netflix":   {"netflix.com", "nflx.net"},
		"YouTube":   {"youtube.com", "googlevideo.com", "ytimg.com"},
		"Facebook":  {"facebook.com", "fbcdn.net", "facebook.net"},
		"Instagram": {"instagram.com", "cdninstagram.com"},
		"Twitter":   {"twitter.com", "twimg.com"},
		"TikTok":    {"tiktok.com", "musical.ly", "bytedance.com"},
		"Zoom":      {"zoom.us", "zoom.com"},
		"Spotify":   {"spotify.com", "spotify.net", "spotifycdn.com"},
		"Bolt":      {"bolt.eu", "bolt.com", "bolt.eu.com"},
	}
)

var (
	iface   string
	snaplen int64
	promisc bool
	timeout time.Duration
	filter  string
	verbose bool
)

func init() {
	flag.StringVar(&iface, "i", "en0", "Interface to capture packets from")
	flag.Int64Var(&snaplen, "s", 1600, "Snapshot length")
	flag.BoolVar(&promisc, "p", true, "Promiscuous mode")
	flag.DurationVar(&timeout, "t", pcap.BlockForever, "Capture timeout")
	flag.StringVar(&filter, "f", "tcp", "BPF filter")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()

}

func main() {
	handle, err := pcap.OpenLive(iface, int32(snaplen), promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Printf("Started capturing on %s...\n\n", iface)

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
	for proto, pattern := range patterns {
		if pattern.Match(payload) {
			return proto
		}
	}

	// Additional protocol detection logic
	if len(payload) >= 2 {
		// DNS check (standard query or response)
		if (payload[2] == 0x01 || payload[2] == 0x02) && len(payload) > 12 {
			return "DNS"
		}

		// QUIC check
		if payload[0] == 0x00 && len(payload) > 5 {
			return "QUIC"
		}

		// BitTorrent check
		if patterns["BitTorrent"].Match(payload) {
			return "BitTorrent"
		}

		// SSH check
		if patterns["SSH"].Match(payload) {
			return "SSH"
		}

		// SMTP check
		if patterns["SMTP"].Match(payload) {
			return "SMTP"
		}

		// FTP check
		if patterns["FTP"].Match(payload) {
			return "FTP"
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

	for app, domains := range appSignatures {
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
		for patternName, pattern := range sensitiveDataPatterns {
			if pattern.MatchString(payloadStr) {
				reasons = append(reasons, fmt.Sprintf("Contains %s", patternName))
			}
		}

		// Check for interesting HTTP paths
		if info.Protocol == "HTTP" {
			for pathType, pattern := range interestingPaths {
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
	if proto, ok := wellKnownPorts[info.DstPort]; ok {
		info.Protocol = proto
	} else if proto, ok := wellKnownPorts[info.SrcPort]; ok {
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
			var colorPrinter *color.Color
			found := false

			// Check each category prefix
			for category, printer := range colorMap {
				if strings.Contains(reason, category) {
					colorPrinter = printer
					found = true
					break
				}
			}

			// Use default color if no specific category matched
			if !found {
				colorPrinter = colorMap["Default"]
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
