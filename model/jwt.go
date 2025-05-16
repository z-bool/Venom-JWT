package model

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// JWT 表示一个 JSON Web Token 的结构
type Jwt struct {
	// 解码后的头部信息
	RealHeader map[string]interface{}
	// 负载内容
	Payload string
	// 原始消息和签名
	Message, Signature []byte
}

// SetAlgorithm 设置 JWT 的算法类型
func (j *Jwt) SetAlgorithm(alg string) {
	j.RealHeader["alg"] = alg
}

// GetAlgorithm 获取 JWT 的算法类型
func (j *Jwt) GetAlgorithm() string {
	if alg, ok := j.RealHeader["alg"].(string); ok {
		return alg
	}
	return "" // 返回空字符串，避免类型断言失败的情况
}

// ToString 将 JWT 对象格式化为可读字符串
func (j *Jwt) ToString() string {
	headerStr, err := j.HeaderToString()
	if err != nil {
		return fmt.Sprintf("JWT Header错误: %s\nJWT Payload: %s\nJWT Signature: %s",
			err.Error(), j.Payload, hex.EncodeToString(j.Signature))
	}

	return fmt.Sprintf("JWT Header: <primary>%s</>\nJWT Payload: <primary>%s</>\nJWT Signature: <primary>%s</>",
		headerStr, j.Payload, hex.EncodeToString(j.Signature))
}

// HeaderToString 将 JWT 头部转换为 JSON 字符串
func (j *Jwt) HeaderToString() (string, error) {
	jsonBytes, err := json.Marshal(j.RealHeader)
	if err != nil {
		return "", fmt.Errorf("序列化JWT头部失败: %w", err)
	}
	return string(jsonBytes), nil
}
