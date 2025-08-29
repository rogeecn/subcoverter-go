package parser

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/subconverter/subconverter-go/internal/domain/proxy"
	"github.com/subconverter/subconverter-go/internal/pkg/logger"
)

// Parser defines the interface for parsing different proxy protocols
type Parser interface {
	// Parse parses the subscription content into proxy configurations
	Parse(ctx context.Context, content string) ([]*proxy.Proxy, error)

	// Support checks if the parser supports the given content format
	Support(content string) bool

	// Type returns the type of proxy this parser handles
	Type() proxy.Type
}

// Manager manages multiple parsers and dispatches parsing tasks
type Manager struct {
	parsers []Parser
	logger  *logger.Logger
}

// NewManager creates a new parser manager with all available parsers
func NewManager(log *logger.Logger) *Manager {
	return &Manager{
		logger: log,
		parsers: []Parser{
			NewClashParser(),
			NewSSParser(),
			NewSSRParser(),
			NewVMessParser(),
			NewVLESSParser(),
			NewTrojanParser(),
			NewHysteriaParser(),
			NewHysteria2Parser(),
			NewSnellParser(),
			NewHTTPParser(),
			NewSocks5Parser(),
		},
	}
}

// Parse parses subscription content using appropriate parser
func (m *Manager) Parse(ctx context.Context, content string) ([]*proxy.Proxy, error) {
	// Attempt to decode Base64 content, as many subscriptions are encoded this way.
	processedContent := content
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		processedContent = string(decoded)
	} else if decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		processedContent = string(decoded)
	}

	// Stage 1: Try to find a parser that can handle the entire content block.
	// This is for file-based formats like Clash, which are not line-based.
	for _, parser := range m.parsers {
		// Heuristic to identify whole-file parsers. For now, only 'clash'.
		if parser.Type() == "clash" && parser.Support(processedContent) {
			return parser.Parse(ctx, processedContent)
		}
	}

	// Stage 2: If no whole-file parser matched, assume it's a list of proxy links (one per line).
	var allProxies []*proxy.Proxy
	lines := splitContent(processedContent)
	for _, line := range lines {
		line = cleanLine(line)
		if line == "" {
			continue
		}

		// Find a suitable line-based parser.
		for _, parser := range m.parsers {
			if parser.Type() == "clash" { // Skip whole-file parsers here.
				continue
			}
			if parser.Support(line) {
				proxies, err := parser.Parse(ctx, line)
				if err != nil {
					m.logger.WithError(err).WithField("line", line).Warn("Failed to parse proxy line")
					break // A parser supported the line but failed to parse it. Move to the next line.
				}
				allProxies = append(allProxies, proxies...)
				break // Successfully parsed the line. Move to the next line.
			}
		}
	}

	return allProxies, nil
}

// AddParser adds a custom parser to the manager
func (m *Manager) AddParser(parser Parser) {
	m.parsers = append(m.parsers, parser)
}

// GetParsers returns all registered parsers
func (m *Manager) GetParsers() []Parser {
	return m.parsers
}

// splitContent splits content into lines
func splitContent(content string) []string {
	return strings.Split(content, "\n")
}

// cleanLine removes whitespace and comments from a line
func cleanLine(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return ""
	}
	return line
}
