package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Interface         string              `yaml:"interface"`
	SnapshotLength    int64               `yaml:"snapshot_length"`
	PromiscMode       bool                `yaml:"promisc_mode"`
	Timeout           string              `yaml:"timeout"`
	Filter            string              `yaml:"filter"`
	Verbose           bool                `yaml:"verbose"`
	ColorScheme       map[string]string   `yaml:"color_scheme"`
	SensitivePatterns map[string]string   `yaml:"sensitive_patterns"`
	WellKnownPorts    map[uint16]string   `yaml:"well_known_ports"`
	Applications      map[string][]string `yaml:"applications"`
	Paths             map[string]string   `yaml:"interesting_paths"`
	ProtocolPatterns  map[string]string   `yaml:"protocol_patterns"`

	ColorMap            map[string]*color.Color
	PatternsMap         map[string]*regexp.Regexp
	PathsMap            map[string]*regexp.Regexp
	ProtocolPatternsMap map[string]*regexp.Regexp
}

// parseColorString converts a color string to color.Attribute
func parseColorString(colorStr string) *color.Color {
	attrs := make([]color.Attribute, 0)

	for _, attr := range strings.Split(colorStr, ",") {
		switch strings.TrimSpace(attr) {
		case "red":
			attrs = append(attrs, color.FgRed)
		case "green":
			attrs = append(attrs, color.FgGreen)
		case "yellow":
			attrs = append(attrs, color.FgYellow)
		case "blue":
			attrs = append(attrs, color.FgBlue)
		case "magenta":
			attrs = append(attrs, color.FgMagenta)
		case "cyan":
			attrs = append(attrs, color.FgCyan)
		case "gray":
			attrs = append(attrs, color.FgBlack)
		case "white":
			attrs = append(attrs, color.FgWhite)
		case "bold":
			attrs = append(attrs, color.Bold)
		}
	}

	return color.New(attrs...)
}

// LoadConfig loads configuration from YAML file
func LoadConfig(filename string) error {
	// Start with default configuration
	GlobalConfig = defaultConfig

	// check if the file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil
	}

	// Try to read configuration file
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Warning: Could not read config file %s, using defaults: %v", filename, err)
		return nil
	}

	// Parse YAML
	var fileConfig Config
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}

	// Merge configurations, preferring file values over defaults
	if fileConfig.Interface != "" {
		GlobalConfig.Interface = fileConfig.Interface
	}
	if fileConfig.SnapshotLength != 0 {
		GlobalConfig.SnapshotLength = fileConfig.SnapshotLength
	}
	if fileConfig.PromiscMode {
		GlobalConfig.PromiscMode = fileConfig.PromiscMode
	}
	if fileConfig.Timeout != "" {
		GlobalConfig.Timeout = fileConfig.Timeout
	}
	if fileConfig.Filter != "" {
		GlobalConfig.Filter = fileConfig.Filter
	}
	if fileConfig.Verbose {
		GlobalConfig.Verbose = fileConfig.Verbose
	}

	// Merge color scheme
	for k, v := range fileConfig.ColorScheme {
		if GlobalConfig.ColorScheme == nil {
			GlobalConfig.ColorScheme = make(map[string]string)
		}

		GlobalConfig.ColorScheme[k] = v
	}

	for k, v := range fileConfig.ProtocolPatterns {
		if fileConfig.ProtocolPatterns == nil {
			GlobalConfig.ProtocolPatterns = make(map[string]string)
		}

		// unescape the pattern
		v = strings.ReplaceAll(v, `\\`, `\`)
		GlobalConfig.ProtocolPatterns[k] = v
	}

	// Initialize color formatters
	colorMap := make(map[string]*color.Color)
	for category, colorStr := range GlobalConfig.ColorScheme {
		colorMap[category] = parseColorString(colorStr)
	}

	// Merge patterns
	for k, v := range fileConfig.SensitivePatterns {
		if GlobalConfig.SensitivePatterns == nil {
			GlobalConfig.SensitivePatterns = make(map[string]string)
		}

		GlobalConfig.SensitivePatterns[k] = v
	}

	// Compile patterns
	patterns := make(map[string]*regexp.Regexp)
	for name, pattern := range GlobalConfig.SensitivePatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("error compiling pattern %s: %v", name, err)
		}
		patterns[name] = compiled
	}

	// Merge well-known ports
	for k, v := range fileConfig.WellKnownPorts {
		if GlobalConfig.WellKnownPorts == nil {
			GlobalConfig.WellKnownPorts = make(map[uint16]string)
		}

		GlobalConfig.WellKnownPorts[k] = v
	}

	// Merge applications
	for k, v := range fileConfig.Applications {
		if GlobalConfig.Applications == nil {
			GlobalConfig.Applications = make(map[string][]string)
		}

		GlobalConfig.Applications[k] = v
	}

	// Merge interesting paths
	for k, v := range fileConfig.Paths {
		if GlobalConfig.Paths == nil {
			GlobalConfig.Paths = make(map[string]string)
		}

		GlobalConfig.Paths[k] = v
	}

	// Compile interesting paths
	interestingPaths := make(map[string]*regexp.Regexp)
	for name, pattern := range GlobalConfig.Paths {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("error compiling interesting path %s: %v", name, err)
		}
		interestingPaths[name] = compiled
	}

	protocolPatterns := make(map[string]*regexp.Regexp)
	for name, pattern := range GlobalConfig.ProtocolPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("error compiling protocol pattern %s: %v", name, err)
		}
		protocolPatterns[name] = compiled
	}

	// setting the global config
	GlobalConfig.ColorMap = colorMap
	GlobalConfig.PatternsMap = patterns
	GlobalConfig.PathsMap = interestingPaths
	GlobalConfig.ProtocolPatternsMap = protocolPatterns

	return nil
}
