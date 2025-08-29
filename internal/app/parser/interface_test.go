package parser

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/subconverter/subconverter-go/internal/pkg/logger"
)

func TestManager_Parse(t *testing.T) {
	log := logger.New(logger.Config{Level: "panic"}) // Use panic level to suppress logs during tests
	manager := NewManager(log)
	ctx := context.Background()

	clashContent := `
proxies:
  - name: "SS-Test"
    type: ss
    server: 127.0.0.1
    port: 8888
    cipher: aes-256-gcm
    password: "password"
  - name: "VMess-Test"
    type: vmess
    server: example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174000
    alterId: 0
    cipher: auto
    tls: true
`

	lineContent := `
ss://YWVzLTI1Ni1jZmI6cGFzc3dvcmQ@example.com:8388#SS-Line-Test
vmess://eyJwcyI6IlZtZXNzLUxpbmUtVGVzdCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiYWJjMTIzNDUtNjc4OS1kZWZhLTEyMzQtNDU2Nzg5MDEyMzQ1IiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidGxzIjoidGxzIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii9wYXRoIiwidiI6IjIifQ==
trojan://password@example.com:443#Trojan-Line-Test
`

	mixedContent := `
ss://YWVzLTI1Ni1jZmI6cGFzc3dvcmQ@example.com:8388#SS-Valid
this-is-an-invalid-line
trojan://password@example.com:443#Trojan-Valid
`

	tests := []struct {
		name          string
		content       string
		expectedCount int
		expectedNames []string
		wantErr       bool
	}{
		{
			name:          "Parse Clash Config",
			content:       clashContent,
			expectedCount: 2,
			expectedNames: []string{"SS-Test", "VMess-Test"},
			wantErr:       false,
		},
		{
			name:          "Parse Line-based Content",
			content:       lineContent,
			expectedCount: 3,
			expectedNames: []string{"SS-Line-Test", "Vmess-Line-Test", "Trojan-Line-Test"},
			wantErr:       false,
		},
		{
			name:          "Parse Base64 Encoded Line-based Content",
			content:       base64.StdEncoding.EncodeToString([]byte(lineContent)),
			expectedCount: 3,
			expectedNames: []string{"SS-Line-Test", "Vmess-Line-Test", "Trojan-Line-Test"},
			wantErr:       false,
		},
		{
			name:          "Parse Base64 Encoded Clash Config",
			content:       base64.StdEncoding.EncodeToString([]byte(clashContent)),
			expectedCount: 2,
			expectedNames: []string{"SS-Test", "VMess-Test"},
			wantErr:       false,
		},
		{
			name:          "Parse Mixed Valid and Invalid Lines",
			content:       mixedContent,
			expectedCount: 2,
			expectedNames: []string{"SS-Valid", "Trojan-Valid"},
			wantErr:       false,
		},
		{
			name:          "Parse Invalid Content",
			content:       "this is just some random text that is not a proxy",
			expectedCount: 0,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxies, err := manager.Parse(ctx, tt.content)

			require.NoError(t, err)
			assert.Len(t, proxies, tt.expectedCount)

			var names []string
			for _, p := range proxies {
				names = append(names, p.Name)
			}
			assert.ElementsMatch(t, tt.expectedNames, names)
		})
	}
}
