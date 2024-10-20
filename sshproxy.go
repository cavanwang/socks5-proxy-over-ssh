package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"golang.org/x/crypto/ssh"
)

const (
	socks5Ver = 0x05
	cmdBind   = 0x01
	atypeIPV4 = 0x01
	atypeHOST = 0x03
	atypeIPV6 = 0x04
)

const (
	ProxyTypeUnknown = iota
	ProxyTypeHTTP
	ProxyTypeHTTPS
	ProxySocks5
)

type ProxyType = int

var (
	httpProxyBeginRegex = regexp.MustCompile(`^(CONNECT|GET|POST|PUT|PATCH|DELETE) (\S+) HTTP/(1.1|1.0|2)\r\n`)

	forignDomainCache sync.Map
)

func Proxy(ctx context.Context, timeout time.Duration, loaclListenAddr, remoteSshAddr, sshUser, sshPassword string) error {
	server, err := net.Listen("tcp", loaclListenAddr)
	if err != nil {
		return err
	}
	sshConn, err := getSshConn(ctx, timeout, remoteSshAddr, sshUser, sshPassword)
	if err != nil {
		return err
	}

	wg := sync.WaitGroup{}
	defer wg.Wait()
	// 启动sshConn定期探活重连，避免断网后永久连接失败
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second * 5):
				if !isSshLive(sshConn) {
					c, err := getSshConn(ctx, timeout, remoteSshAddr, sshUser, sshPassword)
					if err != nil {
						log.Print("ssh reconnect error: ", err)
						continue
					}
					tmp := sshConn
					sshConn = c
					tmp.Close()
					continue
				}
				log.Print("ssh is still alive!!!!!!!!!!!!!!!!!!!!")
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		if err := sshConn.Close(); err != nil {
			log.Println("close ssh connection error: ", err)
		}
		if err := server.Close(); err != nil {
			log.Println("close listener error: ", err)
		}
		log.Println("local listener closed!")
	}()

	var connCount atomic.Int64
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		client, err := server.Accept()
		if err != nil {
			log.Printf("Accept failed %v", err)
			continue
		}
		wg.Add(1)
		connCount.Add(1)
		log.Println("current total connection is: ", connCount.Load())
		go func() {
			defer wg.Done()
			process(ctx, client, sshConn)
			connCount.Add(-1)
			log.Print("process goroutine exited")
		}()
	}
}

func getSshConn(ctx context.Context, timeout time.Duration, remoteSshAddr, sshUser, sshPassword string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 非生产环境使用
		Timeout:         timeout,
	}

	// 建立SSH连接
	conn, err := ssh.Dial("tcp", remoteSshAddr, config)
	if err != nil {
		log.Fatalf("Failed to dial: %s", err)
		return nil, err
	}
	log.Println("ssh conn ok!")

	return conn, nil
}

func process(ctx context.Context, conn net.Conn, sshConn *ssh.Client) {
	startTime := time.Now()
	defer func() {
		conn.Close()
		log.Printf("cost=%dms for connection %s", time.Since(startTime)/time.Millisecond, conn.RemoteAddr().String())
	}()

	err := connect(ctx, conn, sshConn)
	if err != nil {
		log.Printf("client %v auth failed:%v", conn.RemoteAddr(), err)
		return
	}
}

// 探测ssh底层连接是否已经断开
func isSshLive(sshConn *ssh.Client) bool {
	if sshConn == nil {
		return false
	}
	s, err := sshConn.NewSession()
	if err != nil {
		log.Print("ssh new session error: ", err)
		return false
	}
	defer s.Close()
	respBytes, err := s.Output("echo ok")
	if err != nil {
		log.Print("ssh run remote command echo error: ", err)
		return false
	}
	if len(respBytes) == 0 {
		log.Print("ssh run remote command echo no response")
		return false
	}
	return true
}

func connect(ctx context.Context, conn net.Conn, sshConn *ssh.Client) (err error) {
	// 检测代理类型
	b := make([]byte, 512)
	n, err := conn.Read(b)
	if err != nil {
		return err
	}
	proxyType := detectProxyType(b[:n])
	if proxyType == ProxyTypeUnknown {
		return errors.New("unknown proxy type")
	}
	//log.Printf("detect req type is: %v, read first bytes=%s", proxyType, b[:n])
	r := NewReaderWithBegin(b[:n], conn)

	// http代理走http逻辑
	switch proxyType {
	case ProxyTypeHTTP:
		return proxyHTTP(ctx, r, conn, sshConn)
	case ProxyTypeHTTPS:
		return proxyHTTPs(ctx, r, conn, sshConn)
	case ProxySocks5:
		return proxySocks5(ctx, r, conn, sshConn)
	default:
		return errors.New("walk to an unreachable code")
	}
}

func proxySocks5(ctx context.Context, reader io.Reader, conn net.Conn, sshConn *ssh.Client) (err error) {
	// 首先处理认证请求
	bufReader := bufio.NewReader(reader)
	if err = auth(bufReader, conn); err != nil {
		log.Printf("client %v auth failed:%v", conn.RemoteAddr(), err)
		return err
	}

	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// VER 版本号，socks5的值为0x05
	// CMD 0x01表示CONNECT请求
	// RSV 保留字段，值为0x00
	// ATYP 目标地址类型，DST.ADDR的数据对应这个字段的类型。
	//   0x01表示IPv4地址，DST.ADDR为4个字节
	//   0x03表示域名，DST.ADDR是一个可变长度的域名
	// DST.ADDR 一个可变长度的值
	// DST.PORT 目标端口，固定2个字节
	var buf [4]byte
	if _, err = io.ReadFull(reader, buf[:]); err != nil {
		return err
	}
	atyp := buf[3]
	addr := ""
	switch atyp {
	case atypeIPV4:
		_, err = io.ReadFull(reader, buf[:])
		if err != nil {
			return fmt.Errorf("read atyp failed:%w", err)
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case atypeHOST:
		var b [1]byte
		if n, err := reader.Read(b[:]); err != nil {
			return fmt.Errorf("read hostSize failed:%w", err)
		} else if n == 0 {
			return errors.New("miss hostsize field")
		}
		hostSize := b[0]
		host := make([]byte, hostSize)
		_, err = io.ReadFull(reader, host)
		if err != nil {
			return fmt.Errorf("read host failed:%w", err)
		}
		addr = string(host)
	case atypeIPV6:
		return errors.New("IPv6: no supported yet")
	default:
		return errors.New("invalid atyp")
	}
	_, err = io.ReadFull(reader, buf[:2])
	if err != nil {
		return fmt.Errorf("read port failed:%w", err)
	}
	port := binary.BigEndian.Uint16(buf[:2])

	reqAddr := fmt.Sprintf("%v:%v", addr, port)
	//log.Println("will ssh forward to: ", reqAddr)

	// 建立远程连接
	dest, err := getCountryDestConn(ctx, addr, reqAddr, sshConn)
	if err != nil {
		return err
	}
	log.Println("connected to ", addr, port)
	defer dest.Close()

	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// VER socks版本，这里为0x05
	// REP Relay field,内容取值如下 X’00’ succeeded
	// RSV 保留字段
	// ATYPE 地址类型
	// BND.ADDR 服务绑定的地址
	// BND.PORT 服务绑定的端口DST.PORT
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	b := make([]byte, 1024*32)
	go func() { // local server -> remote http/https url
		defer wg.Done()
		for {
			n, err := reader.Read(b)
			var r io.Reader
			if n > 0 {
				r = bytes.NewReader(b[:n])
				_, _ = io.Copy(dest, r)
				log.Printf("got http req from %s len=%d", reqAddr, n)
			}
			if err != nil {
				return
			}
		}
	}()
	wg.Add(1)
	// the dest stands for a http/tcp connection over ssh.
	bb := make([]byte, 1024*32)
	go func() { // remote http/https response -> local http/https client
		defer wg.Done()
		for {
			n, err := dest.Read(bb)
			var r io.Reader
			if n > 0 {
				r = bytes.NewReader(bb[:n])
				_, _ = io.Copy(conn, r)
				log.Printf("got http resp from %s len=%d", reqAddr, n)
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		conn.Close()
		dest.Close()
	}()
	wg.Wait()
	return nil
}

func proxyHTTP(ctx context.Context, reader io.Reader, conn net.Conn, sshConn *ssh.Client) error {
	bufReader := bufio.NewReader(reader)
	// 读取请求行
	_, err := bufReader.ReadString('\n')
	if err != nil {
		return err
	}

	// 读取请求头
	var host string
	for {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)

		// 空行表示请求头结束
		if line == "" {
			break
		}

		// 将请求头分割成 key-value 对
		if strings.Contains(line, ": ") {
			parts := strings.SplitN(line, ": ", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if strings.ToLower(key) == "host" {
				host = value
				break
			}
		}
	}
	if host == "" {
		return errors.New("http request misses host header")
	}
	ss := strings.Split(host, ":")
	addr := ss[0]
	if len(ss) == 1 {
		host += ":80"
	}

	// 建立远程连接
	dest, err := getCountryDestConn(ctx, addr, host, sshConn)
	if err != nil {
		return err
	}
	log.Println("proxy http connected to ", host)
	defer dest.Close()

	// 开始转发数据
	forwardData(ctx, host, reader, conn, dest)
	return nil
}

func proxyHTTPs(ctx context.Context, reader io.Reader, conn net.Conn, sshConn *ssh.Client) error {
	bufReader := bufio.NewReader(reader)
	// 读取请求行,提取连接的远程服务域名
	line, err := bufReader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	fs := strings.Fields(line)
	reqAddr := fs[1]
	addr := strings.Split(reqAddr, ":")[0]
	//log.Printf("req line is %q, reqAddr is %q", line, reqAddr)

	// 建立远程连接
	dest, err := getCountryDestConn(ctx, addr, reqAddr, sshConn)
	if err != nil {
		return err
	}
	log.Println("proxy https connected to ", reqAddr)
	defer dest.Close()

	// 回应客户端connect请求
	if _, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return err
	}

	// 开始转发数据
	forwardData(ctx, reqAddr, reader, conn, dest)
	return nil
}

// 决定是否要走国外代理，如果dns解析为国内地址则直接转发，否则走国外ssh隧道转发。
func getCountryDestConn(ctx context.Context, ipOrHost, reqAddr string, sshConn *ssh.Client) (dest net.Conn, err error) {
	// 判断是否为国内网站，国内地址直接转发
	var isOurCountry bool
	if forign, ok := forignDomainCache.Load(ipOrHost); !ok {
		// 查看是ipOrHost否为IP地址
		isIP := false
		if net.ParseIP(ipOrHost) != nil {
			isIP = true
		}

		timeoutCtx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Second*2))
		defer cancel()
		isOurCountryFn := func(addr string) (yes bool, ipAddr string) {
			// 解析域名对应的IP地址
			if !isIP {
				records, err := net.DefaultResolver.LookupIPAddr(timeoutCtx, ipOrHost)
				if err != nil {
					log.Printf("nslookup %q error: %v", addr, err)
					return
				}
				for _, ip := range records {
					if strings.Contains(ip.String(), ":") {
						continue
					}
					ipAddr = ip.IP.String()
					break
				}
				log.Printf("nslookup %s got: %s", addr, ipAddr)
				if ipAddr == "" {
					return false, ""
				}
			} else {
				ipAddr = addr
			}

			// 查询IP对应的国家
			yes = isFromChina(ipAddr)
			return
		}
		isOurCountry, _ = isOurCountryFn(ipOrHost)
		// 记录一下避免下次重复查询
		forignDomainCache.Store(ipOrHost, !isOurCountry)
		//log.Printf("addr %q is ourCountry? %t", ipOrHost, isOurCountry)
	} else {
		isOurCountry = !forign.(bool)
	}

	// 如果是国内则直接转发
	if isOurCountry {
		// 连接到目标服务器
		dest, err = net.Dial("tcp", reqAddr)
		if err != nil {
			log.Printf("Dial %q error: %v", ipOrHost, err)
			return nil, err
		}
	} else {
		// 国外网站，走ssh隧道转发
		dest, err = sshConn.Dial("tcp", reqAddr)
		if err != nil {
			return nil, fmt.Errorf("dial dst failed:%w", err)
		}
	}
	return dest, nil
}

func auth(reader *bufio.Reader, conn net.Conn) (err error) {
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	// VER: 协议版本，socks5为0x05
	// NMETHODS: 支持认证的方法数量
	// METHODS: 对应NMETHODS，NMETHODS的值为多少，METHODS就有多少个字节。RFC预定义了一些值的含义，内容如下:
	// X’00’ NO AUTHENTICATION REQUIRED
	// X’02’ USERNAME/PASSWORD

	ver, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("read ver failed:%w", err)
	}
	if ver != socks5Ver {
		return fmt.Errorf("not supported ver:%v", ver)
	}
	methodSize, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("read methodSize failed:%w", err)
	}
	method := make([]byte, methodSize)
	_, err = io.ReadFull(reader, method)
	if err != nil {
		return fmt.Errorf("read method failed:%w", err)
	}

	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	_, err = conn.Write([]byte{socks5Ver, 0x00})
	if err != nil {
		return fmt.Errorf("write failed:%w", err)
	}
	return nil
}

func isFromChina(ip string) bool {
	searcher, err := xdb.NewWithFileOnly("./ip.xdb")
	if err != nil {
		fmt.Printf("failed to create searcher: %s\n", err.Error())
		return false
	}

	defer searcher.Close()

	region, err := searcher.SearchByStr(ip)
	if err != nil {
		fmt.Printf("failed to SearchIP(%s): %s\n", ip, err)
		return false
	}
	return strings.HasPrefix(region, "中国")
}

func detectProxyType(firstReqData []byte) ProxyType {
	if len(firstReqData) < 3 {
		return ProxyTypeUnknown
	}

	// socks5
	if firstReqData[0] == socks5Ver {
		return ProxySocks5
	}

	// 不匹配
	if !httpProxyBeginRegex.Match(firstReqData) {
		return ProxyTypeUnknown
	}

	// https匹配
	if strings.HasPrefix(string(firstReqData), "CONNECT") {
		return ProxyTypeHTTPS
	}

	return ProxyTypeHTTP
}

func forwardData(ctx context.Context, reqAddr string, reader io.Reader, conn net.Conn, dest net.Conn) {
	//log.Print("start to forward request:", reqAddr)
	wg := sync.WaitGroup{}
	wg.Add(1)
	b := make([]byte, 1024*32)
	go func() { // local server -> remote http/https url
		defer wg.Done()
		for {
			n, err := reader.Read(b)
			var r io.Reader
			if n > 0 {
				r = bytes.NewReader(b[:n])
				_, _ = io.Copy(dest, r)
				//log.Printf("got http req from %s len=%d", reqAddr, n)
			}
			if err != nil {
				return
			}
		}
	}()
	wg.Add(1)
	// the dest stands for a http/tcp connection over ssh.
	bb := make([]byte, 1024*32)
	go func() { // remote http/https response -> local http/https client
		defer wg.Done()
		last := time.Now()
		var total int64
		for {
			n, err := dest.Read(bb)
			if n > 0 {
				total += int64(n)
				_, err = conn.Write(bb[:n])
				if time.Since(last) > time.Second {
					log.Printf("got http resp from %s total data=%fKB", reqAddr, float64(total)/1024)
					last = time.Now()
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		conn.Close()
		dest.Close()
	}()
	wg.Wait()
}
