package service

import (
	"Venom-JWT/utils"
	"github.com/gookit/color"
)

func saveTxt(path string) {
	utils.SaveResultTxt(path, jwtArr)
	color.Println("<yellow>注意：</>所有JWT结果都已经保存在运行目录下的result.txt中，可以去重放Intruder测试是否为可行Token\n")
}
func EndDeal(path string) {
	saveTxt(path)
}
