package service

import (
	"Venom-JWT/utils"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gookit/color"
)

func EncodeMD5(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func Encode16MD5(data string) string {
	return EncodeMD5(data)[8:24]
}

func JWTWithAllTypeVerify(tokenString string, secret string) (bool, string) {
	result := jWTWithNoneType(tokenString, secret)
	if result {
		return true, "NONE"
	}
	result = jWTWithMD5Type(tokenString, secret)
	if result {
		return true, "MD5"
	}
	result = jWTWith16MD5Type(tokenString, secret)
	if result {
		return true, "16位MD5"
	}
	result = jwtWithBase64Type(tokenString, secret)
	if result {
		return true, "BASE64"
	}
	return false, ""
}

func jWTWithNoneType(tokenString string, secret string) bool {
	return jWTWithVerify(tokenString, secret, false)
}

func jWTWithMD5Type(tokenString string, secret string) bool {
	return jWTWithVerify(tokenString, EncodeMD5(secret), false)
}
func jWTWith16MD5Type(tokenString string, secret string) bool {
	return jWTWithVerify(tokenString, Encode16MD5(secret), false)
}

func jwtWithBase64Type(tokenString string, secret string) bool {
	return jWTWithVerify(tokenString, secret, true)
}

// 爆破
func jWTWithVerify(tokenString string, secret string, decodeBool bool) bool {
	if token, err := utils.ParseJWTKeyBase64(tokenString, secret, decodeBool); err == nil {
		if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			return true
		}
	}
	return false
}

// 并发爆破
func DoJWTWithVerify(tokenString string, secret string, encryptModel int) (string, error) {
	var verify = false
	var s = ""
	if encryptModel == 0 {
		// 说明执行全部的
		verify, s = JWTWithAllTypeVerify(tokenString, secret)
	} else if encryptModel == 1 {
		// 执行None
		verify = jWTWithNoneType(tokenString, secret)
		s = "NONE"
	} else if encryptModel == 2 {
		// 执行MD5
		verify = jWTWithMD5Type(tokenString, secret)
		s = "MD5"
	} else if encryptModel == 3 {
		// 执行16位MD5
		verify = jWTWith16MD5Type(tokenString, secret)
		s = "16MD5"
	} else if encryptModel == 4 {
		// 执行base64
		verify = jwtWithBase64Type(tokenString, secret)
		s = "BASE64"
	}
	if verify && s != "" {
		return "密钥为: " + secret + ",加密方式为: " + s, errors.New("爆破成功")
	}
	return "", nil
}

func CoJwtCrack(tokenString string, encryptModel int, filePath string) {
	numWorkers := utils.GetWorkerCount()
	// 定义处理函数
	worker := func(line string) bool {
		str, err := DoJWTWithVerify(tokenString, line, encryptModel)
		if err != nil && err.Error() == "爆破成功" {
			color.Println("\n<red>[+]爆破成功: " + str + "</>")
			return true // 返回 true 表示需要停止
		}
		return false // 返回 false 表示继续处理
	}
	err := utils.ProcessFileByLine(filePath, worker, numWorkers)
	if err != nil {
		fmt.Printf("Error processing file: %v\n", err)
		return
	}
	fmt.Println("File processing completed.")

}
