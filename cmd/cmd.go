package main

import (
	"Venom-JWT/content"
	"Venom-JWT/utils"
	"flag"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/schollz/progressbar/v3"
)

var (
	jwtString     string
	payloadType   = 0 // 0为默认全执行，1为修改alg为none，2为未验证签名导致的越权，3为将 alg 由 RS256 更改为 HS256
	jwtModel      = 1 //  模式1：修改Payload越权测试 模式2: PayloadFuzz越权测试 模式3：secret文本爆破 模式4：secret字符爆破（如果字符爆破要指定位数-fz）模式5：已知secret传入Payload进行修改
	maxSecretNum  = 0 // 爆破的字符数
	minSecretNum  = 1
	dictFilePath  = ""                                     // 是否使用文件中的payload，默认为空使用角色内置字典（绑定模式2），默认使用默认字典(绑定模式3)
	fuzzSecretKey = "abcdefghijklmnopqrstuvwxyz0123456789" // 爆破的默认字典，可以自行按猜测的规则修改(配合-fz 位数使用)
	jwtBodyChange = ""                                     //需要修改的JWT body
	jwtSecret     = ""                                     // 是否已知Secret
	pemPath       = ""                                     // pem的路径
	encryptModel  = 0                                      // 密钥加密模式
	cmdline       bool                                     // 是否默认开启命令行模式
)

func command_line() {
	flag.StringVar(&jwtString, "jwtStr", "", "JWT字符串(eyxxxxxx.xxx.xxx)")
	flag.IntVar(&payloadType, "pt", 0, "选择模式：0为默认全执行，1为修改alg为none(CVE-2015-2951)，2为未验证签名导致的越权，3修改非对称密码算法为对称密码算法(CVE-2016-10555) 4为JWKS公钥注入--伪造密钥(CVE-2018-0114) 5 为空签名(CVE-2020-28042)")
	flag.IntVar(&jwtModel, "jm", 1, "模式1：(未知Secret)修改Payload越权测试 模式2: (先测试模式1)PayloadFuzz越权测试 模式3：secret文本爆破 模式4：secret字符爆破（如果字符爆破要指定位数-fz）模式5：对JWT的Secret进行验证")
	flag.IntVar(&encryptModel, "em", 0, "secret加密模式NONE/MD5/16位MD5/BASE64(默认ALL=>0,NONE=>1,MD5=>2,16位MD5=>3,BASE64=>4)")
	flag.IntVar(&maxSecretNum, "fz", 0, "字符爆破最大字符数（如果字符爆破要指定位数-fz）")
	flag.IntVar(&minSecretNum, "mz", 1, "字符爆破最小字符数（如果字符爆破要指定位数-mz）,默认为1")
	flag.StringVar(&dictFilePath, "df", "", "是否使用文件中的payload，默认为空使用角色内置字典（绑定模式2），模式3非空(绑定模式3)")
	flag.StringVar(&fuzzSecretKey, "fs", "abcdefghijklmnopqrstuvwxyz0123456789", "爆破的默认字典，可以自行按猜测的规则修改(配合-fz 位数使用)")
	flag.StringVar(&jwtBodyChange, "jbc", "", "需要修改的JWT body")
	flag.StringVar(&jwtSecret, "s", "", "已知Secret，默认为空")
	flag.StringVar(&pemPath, "pem", "", "公钥pem的路径(最好绝对路径)")
	flag.BoolVar(&cmdline, "isCmd", false, "命令行参数运行必填true")
	flag.Parse()
}

func cmd() {

	command_line()
	if !cmdline {
		if jwtModel == 1 {
			var jwtModelMap = map[string]int{"模式1：(未知Secret)修改Payload越权测试": 1, "模式2：(先测试模式1)PayloadFuzz越权测试": 2, "模式3：secret文本爆破": 3, "模式4：secret字符爆破": 4, "模式5：对JWT的Secret进行验证": 5}
			jwtModelStr := ""
			prompt := &survey.Select{
				Message: "【前置选择】未知secret的情况下修改JWT测试越权，请选择模式:\n[·]",
				Options: []string{"模式1：(未知Secret)修改Payload越权测试", "模式2：(先测试模式1)PayloadFuzz越权测试", "模式3：secret文本爆破", "模式4：secret字符爆破", "模式5：对JWT的Secret进行验证"},
			}
			survey.AskOne(prompt, &jwtModelStr)
			jwtModel = jwtModelMap[jwtModelStr]
		}
		if jwtString == "" {
			prompt := &survey.Input{
				Message: "请输入你的JWT字符串:\n[·]",
			}
			survey.AskOne(prompt, &jwtString)
		}
		checkEmptySecret()
		parseJWT()
		if jwtModel == 1 || jwtModel == 2 {
			var payloadTypeMap = map[string]int{"模式0：默认全执行": 0, "模式1：修改alg为none(CVE-2015-2951)": 1, "模式2：未验证签名(无效签名攻击)导致的越权": 2, "模式3：修改非对称密码算法为对称密码算法(CVE-2016-10555)": 3, "模式4：JWKS公钥注入--伪造密钥(CVE-2018-0114)": 4, "模式5：空签名(CVE-2020-28042)": 5}
			payloadTypeStr := ""
			prompt := &survey.Select{
				Message: "【模式1】【模式2】未知secret的情况下修改JWT测试越权，请选择具体测试模式:\n[·]",
				Options: []string{"模式0：默认全执行", "模式1：修改alg为none(CVE-2015-2951)", "模式2：未验证签名(无效签名攻击)导致的越权", "模式3：修改非对称密码算法为对称密码算法(CVE-2016-10555)", "模式4：JWKS公钥注入--伪造密钥(CVE-2018-0114)", "模式5：空签名(CVE-2020-28042)"},
			}
			survey.AskOne(prompt, &payloadTypeStr)
			payloadType = payloadTypeMap[payloadTypeStr]
			if payloadType == 3 || payloadType == 0 {
				prompt := &survey.Input{
					Message: "请输入前端逆向获取的公钥pem文件保存的绝对路径。【若不输入，程序运行结果不可信】，【留空仅维持程序正常运行】 \n[·]",
				}
				survey.AskOne(prompt, &pemPath)
			}
		}
		if jwtModel == 5 {
			prompt := &survey.Input{
				Message: "【模式5】是已知Secret情况下的测试，请输入您的Secret:\n[·]",
			}
			survey.AskOne(prompt, &jwtSecret)
		}

		if jwtModel == 1 || jwtModel == 2 {
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

		// 判断是否需要填入文本信息
		if jwtModel == 2 {
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
		if jwtModel == 3 {
			prompt := &survey.Input{
				Message: "【模式3】请输入您的字典的绝对路径:\n>[·]",
			}
			survey.AskOne(prompt, &dictFilePath)
		}

		if jwtModel == 4 {
			prompt := &survey.Input{
				Message: "【模式4】请输入你需要爆破的字符组默认：abcdefghijklmnopqrstuvwxyz0123456789，如要加入符号等自定义字符请自己加入\n[·]",
			}
			survey.AskOne(prompt, &fuzzSecretKey)

			if len(fuzzSecretKey) == 0 {
				fuzzSecretKey = "abcdefghijklmnopqrstuvwxyz0123456789"
			}
			fmt.Println(fuzzSecretKey)
			prompt = &survey.Input{
				Message: "【模式4】请输入你需要爆破的最小字符数:\n[·]",
			}
			survey.AskOne(prompt, &minSecretNum)
			if minSecretNum == 0 {
				minSecretNum = 1
			}
			prompt = &survey.Input{
				Message: "【模式4】请输入你需要爆破的最大字符数:\n[·]",
			}
			survey.AskOne(prompt, &maxSecretNum)
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
		if jwtModel == 3 || jwtModel == 4 {
			var jwtModelMap = map[string]int{"ALL:进行所有的加密方式的爆破": 0, "NONE:原始Secret不加密": 1, "MD5:对Secret进行MD5加密": 2, "16MD5：对Secret进行16位MD5加密": 3, "Base64:对Secret进行Base64加密(JJWT)": 4}
			encryptStr := ""
			prompt := &survey.Select{
				Message: "请选择secret的加密方式（默认ALL）:\n[·]",
				Options: []string{"ALL:进行所有的加密方式的爆破", "NONE:原始Secret不加密", "MD5:对Secret进行MD5加密", "16MD5：对Secret进行16位MD5加密", "Base64:对Secret进行Base64加密(JJWT)"},
			}
			survey.AskOne(prompt, &encryptStr)
			encryptModel = jwtModelMap[encryptStr]
		}
	} else {
		parseJWT()
		if minSecretNum == 0 {
			minSecretNum = 1
		}
		if jwtModel == 4 {
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

	}
}
