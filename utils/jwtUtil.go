package utils

import (
	"Venom-JWT/model"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gookit/color"
	"github.com/schollz/progressbar/v3"
	"os"
	"regexp"
	"strings"
	"sync"
)

// 返回解析的JWT对象
func ParseJWT(input string) (*model.Jwt, error) {
	parts := strings.Split(input, ".")
	decodedParts := make([][]byte, len(parts))
	if len(parts) != 3 {
		return nil, errors.New("【ERROR】JWT解析错误：JWT中必须包含(header, payload, signature)三个字段")
	}
	for i := range parts {
		decodedParts[i] = make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[i])))
		if _, err := base64.RawURLEncoding.Decode(decodedParts[i], []byte(parts[i])); err != nil {
			return nil, err
		}
	}
	var parsedHeader model.JwtHeader
	// 这里加入一步map处理为了验证是否存在其他字段
	// 解析 Header
	header, err := parseHeader(decodedParts[0])

	if err != nil {
		return nil, fmt.Errorf("【ERROR】Header 解析失败：%v", err)
	}
	if err := json.Unmarshal(decodedParts[0], &parsedHeader); err != nil {
		return nil, err
	}

	return &model.Jwt{
		RealHeader: header,
		Header:     &parsedHeader,
		Payload:    string(decodedParts[1]),
		Message:    []byte(parts[0] + "." + parts[1]),
		Signature:  decodedParts[2],
	}, nil
}

// parseHeader 解析 JWT Header 并返回 map[string]interface{}
func parseHeader(headerBytes []byte) (map[string]interface{}, error) {
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}

	// 检查是否存在额外字段
	for key := range header {
		if key != "alg" && key != "typ" {
			color.Printf("<lightRed>注意~Header 中可能存在标头注入攻击点：【%s】，请于 jwt.io 中分析</>\n", key)
		}
	}

	return header, nil
}

// 返回JWT的第一、三部分
func GetJwtBodyStr(input string, i int) string {
	parts := strings.Split(input, ".")
	if len(parts) == 3 && i > 0 {
		return parts[i-1]
	}
	return ""
}

// base64编码JWT第一部分和第二部分
func EncodeJWT(body string) string {
	jwtBodyBytes := []byte(body)
	var raw = base64.RawURLEncoding.WithPadding(-1)
	return raw.EncodeToString(jwtBodyBytes)
}

// base64解码JWT
func DecodeJWT(headerString string) string {
	decodedBytes, err := base64.RawURLEncoding.DecodeString(headerString)
	if err != nil {
		fmt.Println("解码错误:", err)
	}
	return string(decodedBytes)
}

// 解决指针问题只做拷贝
func JwtCopy(jwt *model.Jwt) model.Jwt {
	return model.Jwt{RealHeader: jwt.RealHeader, Header: jwt.Header, Payload: jwt.Payload, Message: jwt.Message, Signature: jwt.Signature}
}

// 伪造密钥
// 写入公钥进文件
func WritePubKeyToFile(publickey *rsa.PublicKey) error {
	publicKeyASNDER1, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyASNDER1,
	}

	file, err := os.Create("public.pem")
	if err != nil {
		return nil
	}

	err = pem.Encode(file, publicKeyBlock)
	if err != nil {
		return nil
	}

	return nil
}

// 写入私钥进文件
func WritePrivKeyToFile(privatekey *rsa.PrivateKey) error {
	var privKeyASNDER []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyASNDER,
	}

	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}

	if err := pem.Encode(file, privateKeyBlock); err != nil {
		return nil
	}
	return nil
}

// 获取RSA密钥
func GenRsaPrivKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	return privatekey, &privatekey.PublicKey, nil
}

// 将pem.pub直接进行转换
func PEMToRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	// 解码PEM块
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing the key")
	}

	// 检查是否是RSA公钥
	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("key type is not RSA PUBLIC KEY")
	}

	// 解析DER编码的公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %v", err)
	}

	// 断言为*rsa.PublicKey类型
	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}

	return pubKey, nil
}

// 伪造密钥头部
func GetHeadersB64(n, e string) string {
	myJwk := model.Jwk{
		Kty: "RSA",
		Kid: "example@example.com",
		Use: "sig",
		N:   n,
		E:   e,
	}

	header := model.JwtHeader{
		Algorithm: "RS256",
		Jwk:       myJwk,
		Type:      "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return base64.RawURLEncoding.EncodeToString(headerBytes)
}

// 造一个HS256的标头
func CreateHS256Header(jwtHeader *model.JwtHeader) string {
	copyJwtHeader := model.JwtHeader{Algorithm: "HS256", Jwk: jwtHeader.Jwk, Type: "JWT"}
	if headerBytes, err := json.Marshal(copyJwtHeader); err == nil {
		return EncodeJWT(string(headerBytes))
	}
	return ""
}

// 生成所有可能的字符组合，并写入文件
func GenerateCombinations(minLength, maxLength int, chars string, outputFile string, bar *progressbar.ProgressBar) {
	// 尝试删除文件
	deleted, err := DeleteFileIfExists(outputFile)
	if err != nil {
		fmt.Errorf("错误: %v\n", err)
	}
	if !deleted {
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Errorf("错误: %v\n", err)
		}
		defer file.Close()

		var wg sync.WaitGroup
		ch := make(chan string, 1000) // 缓冲 channel，用于存储生成的组合

		// 启动一个 goroutine 负责写入文件
		wg.Add(1)
		go func() {
			defer wg.Done()
			for combo := range ch {
				_, err := file.WriteString(combo + "\n")
				if err != nil {
					fmt.Printf("Error writing to file: %v\n", err)
					return
				}
			}
		}()

		// 递归生成组合
		var generate func(current string, length int)
		generate = func(current string, length int) {
			if length == 0 {
				if len(current) >= minLength { // 只发送长度 >= minLength 的组合
					ch <- current
					bar.Add(1) // 更新进度条
				}
				return
			}
			for _, char := range chars {
				generate(current+string(char), length-1)
			}
		}

		// 生成 minLength 到 maxLength 位的组合
		for i := minLength; i <= maxLength; i++ {
			generate("", i)
		}

		close(ch) // 关闭 channel，通知写入 goroutine 结束
		wg.Wait() // 等待写入完成

		bar.Finish() // 所有组合生成完成后，完成进度条
	}
}

// 计算总组合数
func CalculateTotalCombinations(minLength, maxLength int, chars string) int {
	total := 0
	for i := minLength; i <= maxLength; i++ {
		total += pow(len(chars), i)
	}
	return total
}

// 计算幂次
func pow(base, exponent int) int {
	result := 1
	for i := 0; i < exponent; i++ {
		result *= base
	}
	return result
}

var (
	base64URLRegex = regexp.MustCompile("[^A-Za-z0-9+/=]")
)

// parseJWTKeyBase64 解析 JWT 并验证签名
func ParseJWTKeyBase64(tokenString string, secretKeyString string, decodeKey bool) (*jwt.Token, error) {
	var secretKey []byte
	var err error

	// 如果 decodeKey 为 true，首先尝试 Base64 解码密钥
	if decodeKey {
		secretKey, err = decodeBase64(secretKeyString, true)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode key: %w", err)
		}
	} else {
		secretKey = []byte(secretKeyString)
	}

	// 解析 JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法是否为 HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("[-]Error:alg为:" + token.Header["alg"].(string))
		}
		return secretKey, nil
	}, jwt.WithoutClaimsValidation())

	if err != nil {
		return nil, errors.New("")
	}

	return token, nil
}

// decodeBase64 解码 Base64 或 Base64URL 字符串
func decodeBase64(input string, isBase64URL bool) ([]byte, error) {
	if isBase64URL {
		// 将 Base64URL 转为标准 Base64
		input = strings.ReplaceAll(input, "-", "+")
		input = strings.ReplaceAll(input, "_", "/")
		// 去除所有非 Base64 字符
		input = base64URLRegex.ReplaceAllString(input, "")
	}

	// 补齐输入的 Base64 字符串，使其长度为 4 的倍数
	padding := 4 - len(input)%4
	if padding != 4 {
		input += strings.Repeat("=", padding)
	}

	return base64.StdEncoding.DecodeString(input)
}
