package service

import (
	"Venom-JWT/model"
	"Venom-JWT/utils"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gookit/color"
)

// EncodeMD5 将字符串进行MD5加密
func EncodeMD5(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Encode16MD5 将字符串进行16位MD5加密
func Encode16MD5(data string) string {
	return EncodeMD5(data)[8:24]
}

// JWTWithAllTypeVerify 使用所有支持的加密方式验证JWT
// 返回是否验证成功及加密类型
func JWTWithAllTypeVerify(tokenString string, secret string) (bool, string) {
	// None类型验证
	if result := jWTWithNoneType(tokenString, secret); result {
		return true, "NONE"
	}
	// MD5类型验证
	if result := jWTWithMD5Type(tokenString, secret); result {
		return true, "MD5"
	}
	// 16位MD5类型验证
	if result := jWTWith16MD5Type(tokenString, secret); result {
		return true, "16位MD5"
	}
	// Base64类型验证
	if result := jwtWithBase64Type(tokenString, secret); result {
		return true, "BASE64"
	}
	return false, ""
}

// jWTWithNoneType 使用原始密钥验证JWT
func jWTWithNoneType(tokenString string, secret string) bool {
	return jWTWithVerify(tokenString, secret, false)
}

// jWTWithMD5Type 使用MD5加密后的密钥验证JWT
func jWTWithMD5Type(tokenString string, secret string) bool {
	return jWTWithVerify(tokenString, EncodeMD5(secret), false)
}

// jWTWith16MD5Type 使用16位MD5加密后的密钥验证JWT
func jWTWith16MD5Type(tokenString string, secret string) bool {
	return jWTWithVerify(tokenString, Encode16MD5(secret), false)
}

// jwtWithBase64Type 使用Base64编码的密钥验证JWT
func jwtWithBase64Type(tokenString string, secret string) bool {
	return jWTWithVerify(tokenString, secret, true)
}

// jWTWithVerify 验证JWT的签名
func jWTWithVerify(tokenString string, secret string, decodeBool bool) bool {
	if token, err := utils.ParseJWTKeyBase64(tokenString, secret, decodeBool); err == nil {
		if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			return true
		}
	}
	return false
}

// DoJWTWithVerify 根据加密模式验证JWT
// 返回成功信息和错误（如果成功，错误信息为"爆破成功"）
func DoJWTWithVerify(tokenString string, secret string, encryptModel int) (string, error) {
	var verify = false
	var encryptType = ""

	switch encryptModel {
	case model.EncryptModelAll:
		// 所有加密方式
		verify, encryptType = JWTWithAllTypeVerify(tokenString, secret)
	case model.EncryptModelNone:
		// None加密
		verify = jWTWithNoneType(tokenString, secret)
		encryptType = "NONE"
	case model.EncryptModelMD5:
		// MD5加密
		verify = jWTWithMD5Type(tokenString, secret)
		encryptType = "MD5"
	case model.EncryptModel16MD5:
		// 16位MD5加密
		verify = jWTWith16MD5Type(tokenString, secret)
		encryptType = "16MD5"
	case model.EncryptModelBase64:
		// Base64加密
		verify = jwtWithBase64Type(tokenString, secret)
		encryptType = "BASE64"
	}

	if verify && encryptType != "" {
		return fmt.Sprintf("密钥为: %s, 加密方式为: %s", secret, encryptType), errors.New(model.ErrBruteForceSuccess)
	}
	return "", nil
}

// CoJwtCrack 并发爆破JWT密钥
func CoJwtCrack(tokenString string, encryptModel int, filePath string) {
	numWorkers := utils.GetWorkerCount()
	color.Printf("<cyan>开始爆破JWT... 使用 %d 个并发线程</>\n", numWorkers)

	// 定义处理函数
	worker := func(line string) bool {
		str, err := DoJWTWithVerify(tokenString, line, encryptModel)
		if err != nil && err.Error() == model.ErrBruteForceSuccess {
			color.Println("\n<red>[+]爆破成功: " + str + "</>")
			return true // 返回 true 表示需要停止
		}
		return false // 返回 false 表示继续处理
	}

	err := utils.ProcessFileByLine(filePath, worker, numWorkers)
	if err != nil {
		color.Printf("<red>[-]处理文件错误: %v</>\n", err)
		return
	}

	color.Println("<yellow>文件处理完成，未找到有效密钥。</>")
}
