package main

import (
	"Venom-JWT/content"
	"Venom-JWT/model"
	"Venom-JWT/utils"
	"flag"
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/schollz/progressbar/v3"
)

var (
	jwtString     string
	payloadType   = model.AttackTypeAll        // 默认全执行所有攻击测试
	jwtModel      = model.JWTModePayloadChange // 默认使用修改Payload越权测试
	maxSecretNum  = 0                          // 爆破的字符数
	minSecretNum  = 1
	dictFilePath  = ""                    // 是否使用文件中的payload，默认为空使用角色内置字典（绑定模式2），默认使用默认字典(绑定模式3)
	fuzzSecretKey = model.DefaultCharset  // 爆破的默认字典，可以自行按猜测的规则修改(配合-fz 位数使用)
	jwtBodyChange = ""                    // 需要修改的JWT body
	jwtSecret     = ""                    // 是否已知Secret
	pemPath       = ""                    // pem的路径
	encryptModel  = model.EncryptModelAll // 密钥加密模式
)

// command_line 处理命令行参数
func command_line() {
	flag.StringVar(&jwtString, "jwtStr", "", "JWT字符串(eyxxxxxx.xxx.xxx)")
	flag.IntVar(&payloadType, "pt", model.AttackTypeAll, "选择模式：0为默认全执行，1为修改alg为none(CVE-2015-2951)，2为未验证签名导致的越权，3修改非对称密码算法为对称密码算法(CVE-2016-10555) 4为JWKS公钥注入--伪造密钥(CVE-2018-0114) 5 为空签名(CVE-2020-28042)")
	flag.IntVar(&jwtModel, "jm", model.JWTModePayloadChange, "模式1：(未知Secret)修改Payload越权测试 模式2: (先测试模式1)PayloadFuzz越权测试 模式3：secret文本爆破 模式4：secret字符爆破（如果字符爆破要指定位数-fz）模式5：对JWT的Secret进行验证")
	flag.IntVar(&encryptModel, "em", model.EncryptModelAll, "secret加密模式NONE/MD5/16位MD5/BASE64(默认ALL=>0,NONE=>1,MD5=>2,16位MD5=>3,BASE64=>4)")
	flag.IntVar(&maxSecretNum, "fz", 0, "字符爆破最大字符数（如果字符爆破要指定位数-fz）")
	flag.IntVar(&minSecretNum, "mz", 1, "字符爆破最小字符数（如果字符爆破要指定位数-mz）,默认为1")
	flag.StringVar(&dictFilePath, "df", "", "是否使用文件中的payload，默认为空使用角色内置字典（绑定模式2），模式3非空(绑定模式3)")
	flag.StringVar(&fuzzSecretKey, "fs", model.DefaultCharset, "爆破的默认字典，可以自行按猜测的规则修改(配合-fz 位数使用)")
	flag.StringVar(&jwtBodyChange, "jbc", "", "需要修改的JWT body")
	flag.StringVar(&jwtSecret, "s", "", "已知Secret，默认为空")
	flag.StringVar(&pemPath, "pem", "", "公钥pem的路径(最好绝对路径)")
	flag.Parse()
}

// cmd 通过交互方式获取用户输入
func cmd() {
	command_line()

	// 如果命令行没有指定JWT模式，通过交互获取
	if jwtModel == model.JWTModePayloadChange {
		var jwtModelMap = map[string]int{
			"模式1：(未知Secret)修改Payload越权测试": model.JWTModePayloadChange,
			"模式2：(先测试模式1)PayloadFuzz越权测试": model.JWTModeFuzzPayload,
			"模式3：secret文本爆破":              model.JWTModeSecretBruteForce,
			"模式4：secret字符爆破":              model.JWTModeSecretCharBruteForce,
			"模式5：对JWT的Secret进行验证":         model.JWTModeVerifyWithSecret,
		}
		jwtModelStr := ""
		prompt := &survey.Select{
			Message: "【前置选择】未知secret的情况下修改JWT测试越权，请选择模式:\n[·]",
			Options: []string{
				"模式1：(未知Secret)修改Payload越权测试",
				"模式2：(先测试模式1)PayloadFuzz越权测试",
				"模式3：secret文本爆破",
				"模式4：secret字符爆破",
				"模式5：对JWT的Secret进行验证",
			},
		}
		survey.AskOne(prompt, &jwtModelStr)
		jwtModel = jwtModelMap[jwtModelStr]
	}

	// 如果命令行没有指定JWT字符串，通过交互获取
	if jwtString == "" {
		prompt := &survey.Input{
			Message: "请输入你的JWT字符串:\n[·]",
		}
		survey.AskOne(prompt, &jwtString)
	}

	// 检查空白密钥并解析JWT
	checkEmptySecret()
	parseJWT()

	// 模式1和2需要额外的交互
	if jwtModel == model.JWTModePayloadChange || jwtModel == model.JWTModeFuzzPayload {
		var payloadTypeMap = map[string]int{
			"模式0：默认全执行":                            model.AttackTypeAll,
			"模式1：修改alg为none(CVE-2015-2951)":        model.AttackTypeAlgNone,
			"模式2：未验证签名(无效签名攻击)导致的越权":               model.AttackTypeNoCheckSignature,
			"模式3：修改非对称密码算法为对称密码算法(CVE-2016-10555)": model.AttackTypeAsymToSym,
			"模式4：JWKS公钥注入--伪造密钥(CVE-2018-0114)":    model.AttackTypeFakeKey,
			"模式5：空签名(CVE-2020-28042)":              model.AttackTypeNullSignature,
		}
		payloadTypeStr := ""
		prompt := &survey.Select{
			Message: "【模式1】【模式2】未知secret的情况下修改JWT测试越权，请选择具体测试模式:\n[·]",
			Options: []string{
				"模式0：默认全执行",
				"模式1：修改alg为none(CVE-2015-2951)",
				"模式2：未验证签名(无效签名攻击)导致的越权",
				"模式3：修改非对称密码算法为对称密码算法(CVE-2016-10555)",
				"模式4：JWKS公钥注入--伪造密钥(CVE-2018-0114)",
				"模式5：空签名(CVE-2020-28042)",
			},
		}
		survey.AskOne(prompt, &payloadTypeStr)
		payloadType = payloadTypeMap[payloadTypeStr]

		// RS256算法需要公钥
		if payloadType == model.AttackTypeAsymToSym || payloadType == model.AttackTypeAll {
			prompt := &survey.Input{
				Message: "请输入前端逆向获取的公钥pem文件保存的绝对路径。【若不输入，程序运行结果不可信】，【留空仅维持程序正常运行】 \n[·]",
			}
			survey.AskOne(prompt, &pemPath)
		}
	}

	// 模式5需要Secret
	if jwtModel == model.JWTModeVerifyWithSecret {
		prompt := &survey.Input{
			Message: "【模式5】是已知Secret情况下的测试，请输入您的Secret:\n[·]",
		}
		survey.AskOne(prompt, &jwtSecret)
	}

	// 模式1、2和5需要修改Payload
	if jwtModel == model.JWTModePayloadChange || jwtModel == model.JWTModeFuzzPayload || jwtModel == model.JWTModeVerifyWithSecret {
		prompt := &survey.Input{
			Message: "您在选择【模式1】【模式2】【模式5】中需要修改JWT的第二部分Payload中JSON字符串进行修改测试越权，请从上一步中复制Payload部分修改完后在此输入:\n" +
				"【模式1】【模式5】示例:{\"username\":\"admin\",\"role\":\"admin\"}\n" +
				"【模式2】示例:{\"usernmae\":\"admin\",\"role\":\"FUZZ\"}\n" +
				"请注意【模式2】中的FUZZ此处为字典替换位置，如果不修改可以直接为enter回车默认使用原Payload\n[·]",
		}
		survey.AskOne(prompt, &jwtBodyChange)
		if jwtBodyChange == "" {
			jwtBodyChange = jwt.Payload
		}
	}

	// 模式2可选择是否使用内置角色字典
	if jwtModel == model.JWTModeFuzzPayload {
		dictOr := false
		prompt := &survey.Confirm{
			Message: "您的选择【模式2】中带有是否使用内置的角色字典，如果不使用内置可以输入自定义路径字典，请选择:\n[·]",
		}
		survey.AskOne(prompt, &dictOr)
		if !dictOr {
			prompt := &survey.Input{
				Message: "【模式2】请输入您的FUZZ字典的绝对路径:\n[·]",
			}
			survey.AskOne(prompt, &dictFilePath)
		}
	}

	// 模式3需要字典路径
	if jwtModel == model.JWTModeSecretBruteForce {
		prompt := &survey.Input{
			Message: "【模式3】请输入您的字典的绝对路径:\n>[·]",
		}
		survey.AskOne(prompt, &dictFilePath)
	}

	// 模式4需要配置爆破字符集和长度
	if jwtModel == model.JWTModeSecretCharBruteForce {
		prompt := &survey.Input{
			Message: "【模式4】请输入你需要爆破的字符组默认：abcdefghijklmnopqrstuvwxyz0123456789，如要加入符号等自定义字符请自己加入\n[·]",
		}
		survey.AskOne(prompt, &fuzzSecretKey)

		if len(fuzzSecretKey) == 0 {
			fuzzSecretKey = model.DefaultCharset
		}
		fmt.Println(fuzzSecretKey)

		// 配置最小字符长度
		prompt = &survey.Input{
			Message: "【模式4】请输入你需要爆破的最小字符数:\n[·]",
		}
		survey.AskOne(prompt, &minSecretNum)
		if minSecretNum == 0 {
			minSecretNum = 1
		}

		// 配置最大字符长度
		prompt = &survey.Input{
			Message: "【模式4】请输入你需要爆破的最大字符数:\n[·]",
		}
		survey.AskOne(prompt, &maxSecretNum)

		// 计算组合数并生成字典
		combinations := utils.CalculateTotalCombinations(minSecretNum, maxSecretNum, fuzzSecretKey)
		bar := progressbar.NewOptions(combinations,
			progressbar.OptionSetWidth(15),                   // 设置进度条宽度
			progressbar.OptionSetDescription("生成FUZZ字典中..."), // 设置描述
			progressbar.OptionShowCount(),                    // 显示当前进度和总数
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}), // 自定义进度条样式
		)
		// 生成组合并写入文件
		utils.GenerateCombinations(minSecretNum, maxSecretNum, fuzzSecretKey, content.FUZZ_DICT_GEN_PATH, bar)
	}

	// 模式3和4需要选择加密方式
	if jwtModel == model.JWTModeSecretBruteForce || jwtModel == model.JWTModeSecretCharBruteForce {
		var encryptModelMap = map[string]int{
			"ALL:进行所有的加密方式的爆破":               model.EncryptModelAll,
			"NONE:原始Secret不加密":               model.EncryptModelNone,
			"MD5:对Secret进行MD5加密":             model.EncryptModelMD5,
			"16MD5：对Secret进行16位MD5加密":        model.EncryptModel16MD5,
			"Base64:对Secret进行Base64加密(JJWT)": model.EncryptModelBase64,
		}
		encryptStr := ""
		prompt := &survey.Select{
			Message: "请选择secret的加密方式（默认ALL）:\n[·]",
			Options: []string{
				"ALL:进行所有的加密方式的爆破",
				"NONE:原始Secret不加密",
				"MD5:对Secret进行MD5加密",
				"16MD5：对Secret进行16位MD5加密",
				"Base64:对Secret进行Base64加密(JJWT)",
			},
		}
		survey.AskOne(prompt, &encryptStr)
		encryptModel = encryptModelMap[encryptStr]
	}
}
