package parser

import (
	"context"
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
	var allProxies []*proxy.Proxy

	// Split content by lines and parse each line
	lines := splitContent(content)

	for _, line := range lines {
		line = cleanLine(line)
		if line == "" {
			continue
		}

		for _, parser := range m.parsers {
			if parser.Support(line) {
				proxies, err := parser.Parse(ctx, line)
				if err != nil {
					// Log error but continue processing other lines
					m.logger.WithError(err).WithField("line", line).Warn("Failed to parse proxy line")
					continue
				}
				allProxies = append(allProxies, proxies...)
				break
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
