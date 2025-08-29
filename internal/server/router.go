package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/subconverter/subconverter-go/internal/app/converter"
	"github.com/subconverter/subconverter-go/internal/infra/config"
	"github.com/subconverter/subconverter-go/internal/infra/http"
	"github.com/subconverter/subconverter-go/internal/pkg/errors"
	"github.com/subconverter/subconverter-go/internal/pkg/validator"
)

// Router manages HTTP routes
type Router struct {
	app     *fiber.App
	service *converter.Service
	config  *config.Config
}

// NewRouter creates a new router
func NewRouter(service *converter.Service, cfg *config.Config) *Router {
	app := fiber.New(fiber.Config{
		CaseSensitive: true,
		StrictRouting: true,
		ServerHeader:  "SubConverter-Go",
		AppName:       "SubConverter Go",
		ReadTimeout:   30 * time.Second,
		WriteTimeout:  30 * time.Second,
		IdleTimeout:   60 * time.Second,
	})

	return &Router{
		app:     app,
		service: service,
		config:  cfg,
	}
}

// SetupRoutes configures all routes
func (r *Router) SetupRoutes() {
	// Middleware
	r.app.Use(recover.New())
	r.app.Use(logger.New(logger.Config{
		Format: "${time} ${method} ${path} - ${status} ${latency}\n",
	}))

	if r.config.Security.CORS.Enabled {
		r.app.Use(cors.New(cors.Config{
			AllowOrigins: strings.Join(r.config.Security.CORS.Origins, ","),
			AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
			AllowHeaders: "Origin,Content-Type,Accept,Authorization",
		}))
	}

	if r.config.Security.RateLimit.Enabled {
		r.app.Use(limiter.New(limiter.Config{
			Max:        r.config.Security.RateLimit.Requests,
			Expiration: parseDuration(r.config.Security.RateLimit.Window),
			KeyGenerator: func(c *fiber.Ctx) string {
				return c.IP()
			},
		}))
	}

	// API routes
	api := r.app.Group("/api/v1")

	// Conversion routes
	api.Post("/convert", r.handleConvert)
	api.Post("/convert/batch", r.handleBatchConvert)
	api.Post("/validate", r.handleValidate)

	// Info routes
	api.Get("/info", r.handleInfo)
	api.Get("/health", r.handleHealth)
	api.Get("/formats", r.handleFormats)

	// Static routes
	r.app.Get("/", r.handleRoot)
	r.app.Get("/docs", r.handleDocs)
}

// handleConvert handles single conversion requests
func (r *Router) handleConvert(c *fiber.Ctx) error {
	var req converter.ConvertRequest
	if err := c.BodyParser(&req); err != nil {
		return r.errorResponse(c, errors.BadRequest("INVALID_REQUEST", err.Error()))
	}

	if err := validator.Validate(&req); err != nil {
		return r.errorResponse(c, err)
	}

	// Add user-agent to context
	userAgent := c.Get("User-Agent")
	ctx := context.WithValue(c.Context(), http.UserAgentKey, userAgent)

	resp, err := r.service.Convert(ctx, &req)
	if err != nil {
		return r.errorResponse(c, err)
	}

	// Set appropriate content type
	generator, exists := r.service.GeneratorManager().Get(req.Target)
	if !exists {
		return r.errorResponse(c, fmt.Errorf("unsupported format: %s", req.Target))
	}
	c.Set("Content-Type", generator.ContentType())
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=config.%s", req.Target))

	return c.SendString(resp.Config)
}

// handleBatchConvert handles batch conversion requests
func (r *Router) handleBatchConvert(c *fiber.Ctx) error {
	var req converter.BatchConvertRequest
	if err := c.BodyParser(&req); err != nil {
		return r.errorResponse(c, errors.BadRequest("INVALID_REQUEST", err.Error()))
	}

	if err := validator.Validate(&req); err != nil {
		return r.errorResponse(c, err)
	}

	results := make([]converter.ConvertResponse, 0, len(req.Requests))
	errorsList := make([]string, 0)

	// Add user-agent to context
	userAgent := c.Get("User-Agent")
	ctx := context.WithValue(c.Context(), http.UserAgentKey, userAgent)

	for _, convReq := range req.Requests {
		resp, err := r.service.Convert(ctx, &convReq)
		if err != nil {
			errorsList = append(errorsList, err.Error())
			continue
		}
		results = append(results, *resp)
	}

	return c.JSON(converter.BatchConvertResponse{
		Results: results,
		Errors:  errorsList,
	})
}

// handleValidate handles URL validation requests
func (r *Router) handleValidate(c *fiber.Ctx) error {
	var req converter.ValidateRequest
	if err := c.BodyParser(&req); err != nil {
		return r.errorResponse(c, errors.BadRequest("INVALID_REQUEST", err.Error()))
	}

	if err := validator.Validate(&req); err != nil {
		return r.errorResponse(c, err)
	}

	// Add user-agent to context
	userAgent := c.Get("User-Agent")
	ctx := context.WithValue(c.Context(), http.UserAgentKey, userAgent)

	resp, err := r.service.Validate(ctx, &req)
	if err != nil {
		return r.errorResponse(c, err)
	}

	return c.JSON(resp)
}

// handleInfo returns service information
func (r *Router) handleInfo(c *fiber.Ctx) error {
	formats := r.service.SupportedFormats()
	return c.JSON(converter.InfoResponse{
		Version:        "1.0.0",
		SupportedTypes: formats,
		Features: []string{
			"High-performance conversion",
			"Multiple protocol support",
			"Cloud-native architecture",
			"Caching support",
			"Rate limiting",
			"Health checks",
		},
	})
}

// handleHealth returns health status
func (r *Router) handleHealth(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
	defer cancel()

	services := make(map[string]string)

	// Check service health
	if err := r.service.Health(ctx); err != nil {
		services["service"] = "unhealthy"
		services["error"] = err.Error()
	} else {
		services["service"] = "healthy"
	}

	return c.JSON(converter.HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().Format(time.RFC3339),
		Services:  services,
	})
}

// handleFormats returns supported formats
func (r *Router) handleFormats(c *fiber.Ctx) error {
	formats := r.service.SupportedFormats()
	return c.JSON(map[string][]string{
		"formats": formats,
	})
}

// handleRoot handles root endpoint
func (r *Router) handleRoot(c *fiber.Ctx) error {
	return c.JSON(map[string]string{
		"message": "SubConverter Go API",
		"version": "1.0.0",
		"docs":    "/docs",
	})
}

// handleDocs serves documentation
func (r *Router) handleDocs(c *fiber.Ctx) error {
	docs := `# SubConverter Go API Documentation

## Endpoints

### POST /api/v1/convert
Convert subscription URLs to target format.

**Request Body:**
` + "`" + `json
{
  "target": "clash",
  "urls": ["https://example.com/subscription"],
  "config": "https://example.com/config.yaml",
  "options": {
    "include_remarks": ["香港", "日本"],
    "exclude_remarks": ["测试"],
    "sort": true,
    "udp": true
  }
}
` + "`" + `

### POST /api/v1/convert/batch
Batch convert multiple subscriptions.

### POST /api/v1/validate
Validate subscription URL.

### GET /api/v1/info
Get service information.

### GET /api/v1/health
Health check endpoint.

### GET /api/v1/formats
Get supported formats.

## Supported Formats
- clash
- surge
- quantumult
- loon
- v2ray
- surfboard

## Examples

` + "`" + `bash
# Convert to Clash
curl -X POST http://localhost:8080/api/v1/convert \\
  -H "Content-Type: application/json" \\
  -d '{"target":"clash","urls":["https://example.com/sub"]}'

# Health check
curl http://localhost:8080/api/v1/health
` + "`" + `
`

	c.Set("Content-Type", "text/plain; charset=utf-8")
	return c.SendString(docs)
}

// errorResponse returns a standardized error response
func (r *Router) errorResponse(c *fiber.Ctx, err error) error {
	if appErr, ok := err.(*errors.Error); ok {
		return c.Status(appErr.Status).JSON(map[string]interface{}{
			"error":   appErr.Message,
			"code":    appErr.Code,
			"details": appErr.Details,
		})
	}

	return c.Status(500).JSON(map[string]interface{}{
		"error": err.Error(),
		"code":  "INTERNAL_ERROR",
	})
}

// App returns the fiber app
func (r *Router) App() *fiber.App {
	return r.app
}

// parseDuration parses duration string
func parseDuration(durationStr string) time.Duration {
	duration, _ := time.ParseDuration(durationStr)
	if duration == 0 {
		duration = time.Minute
	}
	return duration
}
