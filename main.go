package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	setConsoleCtrlHandler = kernel32.NewProc("SetConsoleCtrlHandler")
	k                     registry.Key
	cmd                   *exec.Cmd
	sigs                  = make(chan os.Signal, 1)
	selfExit              = make(chan struct{}, 1)
)

func main() {
	socksAddr := flag.String("listen_addr", "127.0.0.1:1080", "proxy server's local listen address")
	sshTimeout := flag.Int("ssh_timeout", 5, "seconds of timeout for connecting to remote ssh server")
	sshAddr := flag.String("ssh_addr", "127.0.0.1:22", "remote ssh server address")
	sshUser := flag.String("ssh_user", "root", "ssh username for remote server")
	sshPasswd := flag.String("ssh_password", "123456", "ssh password for remote server")
	flag.Parse()

	// 设置日志前缀和日期打印
	log.Default().SetPrefix("proxy ")
	log.Default().SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	var err error
	k, err = registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.ALL_ACCESS)
	if err != nil {
		log.Println("打开注册表项失败：", err)
		return
	}
	defer k.Close()

	// 设置值，假设设置一个名为 ProxyEnable
	err = k.SetDWordValue("ProxyEnable", 1)
	if err != nil {
		log.Println("设置注册表值ProxyEnable失败：", err)
		return
	}

	wg := sync.WaitGroup{}

	// 启动代理协程
	wg.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer wg.Done()
		if err := Proxy(ctx, time.Duration(*sshTimeout)*time.Second, *socksAddr, *sshAddr, *sshUser, *sshPasswd); err != nil {
			log.Println("proxy error: ", err)
		}

		log.Println("proxy协程已退出")
		go func() {
			sigs <- syscall.SIGQUIT
		}()
	}()

	// 设置信号处理函数
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	wg.Add(1)
	go func() {
		defer wg.Done()
		sig := <-sigs
		log.Println("Received signal:", sig)
		clean()
		log.Println("信号清理已经完成")
		cancel()
	}()

	// 获取控制台窗口句柄
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd == 0 {
		log.Println("Failed to get console window handle.")
		return
	}

	// 设置控制台控制处理程序
	ret, _, _ := setConsoleCtrlHandler.Call(syscall.NewCallback(windowsHandler), 1)
	if ret == 0 {
		log.Println("Failed to set console control handler.")
		return
	}

	// 设置值，假设设置一个名为 ProxyServer
	//err = k.SetStringValue("ProxyServer", "socks://"+*socksAddr)
	err = k.SetStringValue("ProxyServer", "http://"+*socksAddr)
	if err != nil {
		log.Println("设置注册表值ProxyServer失败：", err)
		return
	}
	log.Println("注册表代理设置成功")

	wg.Wait()
	log.Println("进程退出!")
	time.Sleep(time.Second * 4)
	selfExit <- struct{}{}
}

// windowsHandler 是 Windows 平台上的处理函数, 这里处理窗口关闭事件
func windowsHandler(ctrlType uint32) uintptr {
	log.Println("windowsHandler triggered")
	switch ctrlType {
	case windows.CTRL_C_EVENT, windows.CTRL_BREAK_EVENT, windows.CTRL_CLOSE_EVENT:
		go func() {
			sigs <- syscall.SIGQUIT
		}()
	}
	<-selfExit
	return 1
}

// 关闭窗口时自动关闭系统的代理
func clean() {
	err := k.SetDWordValue("ProxyEnable", 0)
	if err != nil {
		log.Println("重置注册表值ProxyEnable失败：", err)
	}
	log.Println("完成: 重置注册表代理和关闭监听端口")
}
