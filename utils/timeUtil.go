package utils

import (
	"time"
)

// GetTimeNowStr 获取当前格式化时间字符串
func GetTimeNowStr() string {
	return time.Now().Format("2006-01-02 15:04:05")
}
