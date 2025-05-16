package main

import (
	"Venom-JWT/content"
	"Venom-JWT/model"
	"Venom-JWT/service"
	"Venom-JWT/utils"
	"os"
	"strings"

	"github.com/gookit/color"
)

var (
	jwt          *model.Jwt = nil
	firstBodyStr            = ""
	thirdBodyStr            = ""
	txtArr                  = []string{}
	runPath                 = ""
)

// checkEmptySecret 检查JWT是否有空白密钥漏洞
func checkEmptySecret() {
	verify, encodeType := service.JWTWithAllTypeVerify(jwtString, "")
	if verify {
		color.Printf("<magentaB>[+]空白密钥漏洞存在，加密方式为: %s</>\n", encodeType)
		os.Exit(1)
	}
}

// parseJWT 解析JWT字符串
func parseJWT() {
	jwt, firstBodyStr, thirdBodyStr = service.JwtParseService(jwtString)
	if len(firstBodyStr) == 0 || len(thirdBodyStr) == 0 {
		color.Println("<red>[-]JWT解析失败：无法获取头部或签名部分</>")
		os.Exit(1)
	}

	color.Printf("<cyan>[*]成功解析JWT，头部算法: %s</>\n", jwt.GetAlgorithm())
}

// init 初始化函数
func init() {
	currentDir, err := os.Getwd()
	if err != nil {
		color.Printf("<red>[-]获取当前目录失败: %s</>\n", err.Error())
		os.Exit(1)
	}
	runPath = strings.ReplaceAll(currentDir, "\\", "/")
}

// main 主函数
func main() {
	// 获取命令行参数和用户输入
	cmd()

	// 复制JWT对象并修改Payload
	jwtCopy := utils.JwtCopy(jwt)
	jwtCopy.Payload = jwtBodyChange

	// 根据不同模式执行不同逻辑
	switch jwtModel {
	case model.JWTModePayloadChange:
		// 模式1：修改Payload越权测试
		color.Println("<cyan>[*]执行模式1：修改Payload越权测试</>")
		service.JwtChangeTest(jwtCopy, firstBodyStr, thirdBodyStr, payloadType, pemPath)

	case model.JWTModeFuzzPayload:
		// 模式2：PayloadFuzz越权测试
		color.Println("<cyan>[*]执行模式2：PayloadFuzz越权测试</>")
		if len(txtArr) == 0 {
			color.Println("<lightWhite>使用内置角色FUZZ字典...</>")
			txtArr = content.ROLE_FUZZ_CONTENT
		}
		service.JwtChangeFuzzTest(jwtCopy, firstBodyStr, thirdBodyStr, payloadType, txtArr, pemPath)

	case model.JWTModeSecretBruteForce:
		// 模式3：secret文本爆破
		color.Println("<cyan>[*]执行模式3：secret文本爆破</>")
		service.CoJwtCrack(jwtString, encryptModel, dictFilePath)

	case model.JWTModeSecretCharBruteForce:
		// 模式4：secret字符爆破
		color.Println("<cyan>[*]执行模式4：secret字符爆破</>")
		if fuzzSecretKey != "" && maxSecretNum == 0 {
			color.Println("<red>[-]ERROR!爆破位数为0无法开启爆破!!!</>")
			os.Exit(1)
		}
		service.CoJwtCrack(jwtString, encryptModel, content.FUZZ_DICT_GEN_PATH)

	case model.JWTModeVerifyWithSecret:
		// 模式5：对JWT的Secret进行验证
		color.Println("<cyan>[*]执行模式5：验证Secret</>")
		verify, encodeType := service.JWTWithAllTypeVerify(jwtString, jwtSecret)
		if verify {
			color.Printf("<magentaB>[+]JWT验证成功：密钥为 %s，加密方式为: %s</>\n", jwtSecret, encodeType)
		} else {
			color.Printf("<red>[-]JWT验证失败：密钥 %s 不正确</>\n", jwtSecret)
		}

	default:
		color.Println("<red>[-]未知的JWT模式</>\n")
		os.Exit(1)
	}

	// 模式1和2需要保存结果
	if jwtModel == model.JWTModePayloadChange || jwtModel == model.JWTModeFuzzPayload {
		service.SaveResult(runPath)
	}
}
