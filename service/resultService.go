package service

import (
	"Venom-JWT/utils"
	"os"

	"github.com/gookit/color"
)

// SaveResultToFile 保存结果到文件
func saveTxt(path string) {
	utils.SaveResultTxt(path, jwtArr)
	color.Println("<yellow>注意：</>所有JWT结果都已经保存在运行目录下的result.txt中，可以去重放Intruder测试是否为可行Token\n")
}

// SaveResult 完成JWT测试后保存结果
func SaveResult(path string) {
	saveTxt(path)
	SaveJWTResultToLog(path)
}

// SaveJWTResultToLog 保存JWT测试结果到日志文件
func SaveJWTResultToLog(runPath string) {
	fileName := runPath + "/log.txt"
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		color.Printf("<red>[-]创建日志文件失败: %s</>\n", err.Error())
		return
	}
	defer file.Close()

	// 写入时间戳
	timeStr := utils.GetTimeNowStr()
	file.WriteString("\n================" + timeStr + "================\n")

	// 写入生成的JWT令牌
	for _, jwtString := range jwtArr {
		file.WriteString(jwtString + "\n")
	}

	color.Printf("\n<green>[+]生成的JWT已保存到: %s</>\n", fileName)
}
