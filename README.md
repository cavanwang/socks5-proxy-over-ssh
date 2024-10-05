# main.go is based on Windows 10 with a global proxy configured (modifying the registry table).

# run on windows10:
  `.\proxy.exe -socks5_addr 127.0.0.1:1090  -ssh_addr <forign-ip>:22 -ssh_password <password> -ssh_timeout 5 -ssh_user root`

<span>Above proxy.exe will listen at 127.0.0.1:1090 and accepts the browser's/curl/... connection request. And it will forward the http/https/tcp requests to a final destination server over a ssh connection. Usually you need to have a ssh server located abroad. This is like `ssh -Nf -D 127.0.0.1:1090 root@xxxxxx` parameter.</span>

# run on linux/mac
You should use the sshproxy.go's `Proxy` function, and build a execution by changing the main.go on your `machine`(It currently works well only on Windows10.)
