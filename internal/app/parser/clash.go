package parser

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/subconverter/subconverter-go/internal/domain/proxy"
	"gopkg.in/yaml.v3"
)

// ClashParser parses Clash configuration files.
type ClashParser struct{}

// NewClashParser creates a new ClashParser.
func NewClashParser() *ClashParser { return &ClashParser{} }

// Type returns the type of proxy this parser handles.
func (p *ClashParser) Type() proxy.Type { return "clash" }

// Support checks if the content is a Clash configuration file.
func (p *ClashParser) Support(content string) bool {
	// A simple heuristic to detect a Clash config.
	// It must not be a single proxy link.
	if strings.HasPrefix(content, "ss://") || strings.HasPrefix(content, "vmess://") ||
		strings.HasPrefix(content, "trojan://") {
		return false
	}
	return strings.Contains(content, "proxies:")
}

// Parse parses the Clash configuration and extracts proxies.
func (p *ClashParser) Parse(ctx context.Context, content string) ([]*proxy.Proxy, error) {
	var config struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}

	if err := yaml.Unmarshal([]byte(content), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal clash config: %w", err)
	}

	var proxies []*proxy.Proxy
	for _, proxyMap := range config.Proxies {
		proxyNode, err := p.parseProxyMap(proxyMap)
		if err != nil {
			// Silently ignore proxies that fail to parse
			continue
		}
		proxies = append(proxies, proxyNode)
	}

	return proxies, nil
}

func (p *ClashParser) parseProxyMap(proxyMap map[string]interface{}) (*proxy.Proxy, error) {
	proxyType, _ := proxyMap["type"].(string)
	if proxyType == "" {
		return nil, fmt.Errorf("proxy type is missing")
	}

	node := &proxy.Proxy{
		ID:     uuid.New().String(),
		Type:   proxy.Type(proxyType),
		Name:   lo.ValueOr(proxyMap, "name", "").(string),
		Server: lo.ValueOr(proxyMap, "server", "").(string),
		Port:   lo.ValueOr(proxyMap, "port", 0).(int),
		UDP:    lo.ValueOr(proxyMap, "udp", false).(bool),
	}

	switch node.Type {
	case "ss":
		node.Method = lo.ValueOr(proxyMap, "cipher", "").(string)
		node.Password = lo.ValueOr(proxyMap, "password", "").(string)
		if opts, ok := proxyMap["plugin-opts"].(map[string]interface{}); ok {
			node.Plugin = lo.ValueOr(proxyMap, "plugin", "").(string)
			if node.Plugin == "obfs" {
				node.PluginOpts = fmt.Sprintf(
					"obfs=%s;obfs-host=%s",
					lo.ValueOr(opts, "mode", ""),
					lo.ValueOr(opts, "host", ""),
				)
			}
		}
	case "ssr":
		node.Method = lo.ValueOr(proxyMap, "cipher", "").(string)
		node.Password = lo.ValueOr(proxyMap, "password", "").(string)
		node.Protocol = lo.ValueOr(proxyMap, "protocol", "").(string)
		node.ProtocolParam = lo.ValueOr(proxyMap, "protocol-param", "").(string)
		node.Obfs = lo.ValueOr(proxyMap, "obfs", "").(string)
		node.ObfsParam = lo.ValueOr(proxyMap, "obfs-param", "").(string)
	case "vmess":
		node.UUID = lo.ValueOr(proxyMap, "uuid", "").(string)
		node.AID = lo.ValueOr(proxyMap, "alterId", 0).(int)
		node.Method = lo.ValueOr(proxyMap, "cipher", "").(string)
		node.Network = proxy.Network(lo.ValueOr(proxyMap, "network", "tcp").(string))
		if tls, ok := proxyMap["tls"].(bool); ok && tls {
			node.TLS = proxy.TLSRequire
		}
		node.SNI = lo.ValueOr(proxyMap, "servername", "").(string)
		if wsOpts, ok := proxyMap["ws-opts"].(map[string]interface{}); ok {
			node.Path = lo.ValueOr(wsOpts, "path", "").(string)
			if headers, ok := wsOpts["headers"].(map[string]interface{}); ok {
				node.Host = lo.ValueOr(headers, "Host", "").(string)
			}
		}
	case "vless":
		node.UUID = lo.ValueOr(proxyMap, "uuid", "").(string)
		node.Network = proxy.Network(lo.ValueOr(proxyMap, "network", "tcp").(string))
		if tls, ok := proxyMap["tls"].(bool); ok && tls {
			node.TLS = proxy.TLSRequire
		}
		node.SNI = lo.ValueOr(proxyMap, "servername", "").(string)
		if grpcOpts, ok := proxyMap["grpc-opts"].(map[string]interface{}); ok {
			node.Path = lo.ValueOr(grpcOpts, "grpc-service-name", "").(string)
		}
	case "trojan":
		node.Password = lo.ValueOr(proxyMap, "password", "").(string)
		node.SNI = lo.ValueOr(proxyMap, "sni", "").(string)
		node.SkipCertVerify = lo.ValueOr(proxyMap, "skip-cert-verify", false).(bool)
	case "http", "https":
		node.Username = lo.ValueOr(proxyMap, "username", "").(string)
		node.Password, _ = proxyMap["password"].(string)
		if tls, ok := proxyMap["tls"].(bool); ok && tls {
			node.TLS = proxy.TLSRequire
		}
	case "snell":
		node.Password = lo.ValueOr(proxyMap, "psk", "").(string)
	case "hysteria", "hysteria2":
		node.Password = lo.ValueOr(proxyMap, "password", "").(string)
		node.SNI = lo.ValueOr(proxyMap, "sni", "").(string)
		node.SkipCertVerify = lo.ValueOr(proxyMap, "skip-cert-verify", false).(bool)
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", node.Type)
	}

	return node, nil
}
