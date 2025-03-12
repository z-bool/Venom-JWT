package main

import (
	"Venom-JWT/content"
	"Venom-JWT/model"
	"Venom-JWT/service"
	"Venom-JWT/utils"
	"fmt"
	"github.com/gookit/color"
	"os"
	"strings"
)

var (
	jwt          *model.Jwt = nil
	firstBodyStr            = ""
	thirdBodyStr            = ""
	txtArr                  = []string{}
	runPath                 = ""
)

func checkEmptySecret() {
	verify, encodeType := service.JWTWithAllTypeVerify(jwtString, "")
	if verify {
		color.Println("<magentaB>[+]空白密钥漏洞存在，加密方式为: " + encodeType + "</>\n")
		os.Exit(1)
	}
}

func parseJWT() {
	jwt, firstBodyStr, thirdBodyStr = service.JwtParseService(jwtString)
	if len(firstBodyStr) == 0 || len(thirdBodyStr) == 0 {
		os.Exit(1)
	}
}
func init() {
	currentDir, err := os.Getwd()
	if err != nil {
		color.Println("<red>[-]</>" + err.Error() + "</>\n")
	}
	runPath = strings.ReplaceAll(currentDir, "\\", "/")
}

func main() {

	cmd()
	jwtCopy := utils.JwtCopy(jwt)
	jwtCopy.Payload = jwtBodyChange

	if jwtModel == 1 {
		// 越权修改测试
		service.JwtChangeTest(jwtCopy, firstBodyStr, thirdBodyStr, payloadType, pemPath)
	} else if jwtModel == 2 {
		// 越权fuzz测试
		if len(txtArr) == 0 {
			color.Println("<lightWhite>使用内置角色FUZZ字典~~~</>")
			txtArr = content.ROLE_FUZZ_CONTENT
		}
		service.JwtChangeFuzzTest(jwtCopy, firstBodyStr, thirdBodyStr, payloadType, txtArr, pemPath)
	} else if jwtModel == 3 {
		service.CoJwtCrack(jwt, jwtString, encryptModel, dictFilePath)
	} else if jwtModel == 4 {
		if fuzzSecretKey != "" {
			if maxSecretNum == 0 {
				color.Println("<red>[-]</>ERROR!爆破位数位0无法开启爆破!!!")
				os.Exit(1)
			}
		}
		service.CoJwtCrack(jwt, jwtString, encryptModel, content.FUZZ_DICT_GEN_PATH)
	} else if jwtModel == 5 {
		verify, s := service.JWTWithAllTypeVerify(jwtString, jwtSecret)
		if verify {
			color.Println("<magentaB>[+]</>此JWT的secret为 " + jwtSecret + "成功验证且加密方式为: " + s + "</>")
		} else {
			fmt.Println("<red>[-]</>此JWT的secret不为: " + jwtSecret)
		}
	}
	if jwtModel == 1 || jwtModel == 2 {
		service.EndDeal(runPath)
	}
}
