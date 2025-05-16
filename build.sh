#!/bin/bash

# 设置版本信息
VERSION="1.0.0"
APP_NAME="venom-jwt"

# 创建输出目录
mkdir -p ./bin

# 编译Linux amd64版本
echo "编译 Linux amd64 版本..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ./bin/${APP_NAME}_linux_amd64 ./cmd

# 编译macOS amd64版本
echo "编译 macOS amd64 版本..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o ./bin/${APP_NAME}_darwin_amd64 ./cmd

# 编译macOS arm64版本 (M1/M2芯片)
echo "编译 macOS arm64 版本..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o ./bin/${APP_NAME}_darwin_arm64 ./cmd

# 编译Windows amd64版本
echo "编译 Windows amd64 版本..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ./bin/${APP_NAME}_windows_amd64.exe ./cmd

# 设置执行权限
chmod +x ./bin/*

echo "编译完成! 可执行文件已保存在 ./bin 目录"
ls -la ./bin 