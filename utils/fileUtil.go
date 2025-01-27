package utils

import (
	"bufio"
	"context"
	"fmt"
	"github.com/gookit/color"
	"github.com/schollz/progressbar/v3"
	"os"
	"runtime"
	"sync"
	"time"
)

func GetWorkerCount() int {
	numCPU := runtime.NumCPU()
	fmt.Printf("CPU cores: %d\n", numCPU)

	// 如果是 I/O 密集型任务，可以增加 worker 数量
	return numCPU * 2
}

// ProcessFileByLine 逐行读取文件并通过 channel 处理
func ProcessFileByLine(filePath string, worker func(string) bool, numWorkers int) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var wg sync.WaitGroup
	ch := make(chan string, 1000)                           // 缓冲 channel，用于存储每一行数据
	ctx, cancel := context.WithCancel(context.Background()) // 创建 context 用于取消操作
	defer cancel()

	// 启动多个 worker goroutine 处理数据
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range ch {
				shouldStop := worker(line) // 调用处理函数
				if shouldStop {
					cancel() // 如果 worker 返回 true，取消 context
					return
				}
			}
		}()
	}

	// 逐行读取文件
	scanner := bufio.NewScanner(file)
	lineCount := 0 // 用于记录当前读取的行数

	// 创建并启动 progressbar
	bar := progressbar.NewOptions(-1, // -1 表示未知总行数
		progressbar.OptionSetDescription("正在读取文件"),
		progressbar.OptionSetWriter(os.Stderr),           // 将进度条输出到标准错误
		progressbar.OptionShowCount(),                    // 显示当前行数
		progressbar.OptionSetWidth(10),                   // 设置进度条宽度
		progressbar.OptionThrottle(100*time.Microsecond), // 控制刷新频率
	)

	for scanner.Scan() {
		select {
		case <-ctx.Done(): // 如果 context 被取消，停止读取文件
			break
		default:
			lineCount++
			ch <- scanner.Text() // 将每一行发送到 channel
			bar.Add(1)           // 更新进度条
		}
	}

	close(ch)                          // 关闭 channel，通知 worker goroutine 结束
	wg.Wait()                          // 等待所有 worker 完成
	bar.Finish()                       // 完成进度条
	time.Sleep(100 * time.Microsecond) // 等待最后一次进度条更新

	if err := scanner.Err(); err != nil {
		return err
	}

	fmt.Printf("\r字典读取完成，共执行 %d 行\n", lineCount)
	return nil
}

// 保存文件
func SaveResultTxt(path string, strArr []string) {
	file, err := os.Create(path + "/result.txt")
	if err != nil {
		color.Println("<red>[-]</>" + err.Error())
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, line := range strArr {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			color.Println("<red>[-]</>" + err.Error())
		}
	}
	err = writer.Flush()
	if err != nil {
		color.Println("<red>[-]</>" + err.Error())
	}
}

// 删除文件
func DeleteResultTxt(path string) {
	err := os.Remove(path)
	if err == nil {
		color.Printf("<magentaB>[+]</>文件" + path + "已成功删除。\n")
	}
}

// 判断文件是否存在，如果存在则删除
func DeleteFileIfExists(filename string) (bool, error) {
	// 检查文件是否存在
	_, err := os.Stat(filename)
	if err == nil {
		// 文件存在，尝试删除
		err := os.Remove(filename)
		if err != nil {
			return false, fmt.Errorf("无法删除文件: %v", err)
		}
		return true, nil // 文件存在并已删除
	}

	// 如果文件不存在
	if os.IsNotExist(err) {
		return false, nil // 文件不存在
	}

	// 其他错误（如权限问题）
	return false, fmt.Errorf("检查文件时出错: %v", err)
}
