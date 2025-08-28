# SubConverter Go

SubConverter的Go语言版本实现，提供高性能的代理订阅转换服务。

## 特性

- **高性能**: 基于Go语言的高并发处理能力
- **多协议支持**: 支持SS、SSR、VMess、Trojan、Hysteria等主流协议
- **多格式输出**: 支持Clash、Surge、Quantumult、Loon等格式
- **云原生**: 支持容器化部署，Kubernetes友好
- **缓存支持**: 内置Redis缓存，提升响应速度
- **API友好**: RESTful API设计，支持批量处理

## 快速开始

### 安装

```bash
# 克隆项目
git clone https://github.com/subconverter/subconverter-go.git
cd subconverter-go

# 安装依赖
go mod tidy

# 构建
go build -o subconverter cmd/subconverter/main.go
```

### 运行

```bash
# 直接运行
./subconverter

# 使用配置文件
./subconverter --config configs/config.yaml

# 指定端口
./subconverter --port 8080
```

### Docker运行

```bash
# 构建镜像
docker build -t subconverter-go .

# 运行容器
docker run -p 8080:8080 subconverter-go
```

## API使用

### 转换订阅

```bash
curl -X POST http://localhost:8080/api/v1/convert \
  -H "Content-Type: application/json" \
  -d '{
    "target": "clash",
    "urls": ["https://example.com/subscription"],
    "config": "https://example.com/config.yaml",
    "options": {
      "include_remarks": ["香港", "日本"],
      "exclude_remarks": ["测试"],
      "rename_rules": ["香港->HK", "日本->JP"],
      "sort": true,
      "udp": true
    }
  }'
```

### 健康检查

```bash
curl http://localhost:8080/api/v1/health
```

## CLI工具

### 安装CLI

```bash
go install ./cmd/subctl
```

### 使用示例

```bash
# 转换订阅
subctl convert -u https://example.com/subscription -t clash -o config.yaml

# 使用自定义配置
subctl convert -u https://example.com/subscription -c configs/config.yaml
```

## 项目结构

```
subconverter-go/
├── cmd/
│   ├── subconverter/    # 主服务程序
│   ├── subctl/         # CLI工具
│   └── subworker/      # 后台任务
├── internal/
│   ├── app/
│   │   ├── converter/  # 转换服务
│   │   ├── parser/     # 协议解析
│   │   └── generator/  # 配置生成
│   ├── domain/
│   │   ├── proxy/      # 代理实体
│   │   ├── ruleset/    # 规则集实体
│   │   └── subscription/ # 订阅实体
│   ├── infra/
│   │   ├── cache/      # 缓存实现
│   │   ├── config/     # 配置管理
│   │   ├── http/       # HTTP客户端
│   │   └── storage/    # 存储抽象
│   └── pkg/
│       ├── logger/     # 日志封装
│       ├── errors/     # 错误处理
│       └── validator/  # 参数验证
├── configs/            # 配置文件
├── test/               # 测试文件
└── docs/               # 文档
```

## 开发指南

### 环境要求

- Go 1.21+
- Redis (可选)
- Docker (可选)

### 开发运行

```bash
# 安装开发依赖
go mod tidy

# 运行测试
go test ./...

# 运行基准测试
go test -bench=. ./...

# 生成代码覆盖率
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### 贡献指南

1. Fork项目
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 致谢

感谢原始SubConverter项目的贡献者和社区支持。