package main

import (
	"fmt"
	"os"
	"os/exec"
)

func CreateMyCert(domain string) {
	file, err := os.OpenFile("domain.ext", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	file.Write([]byte("authorityKeyIdentifier=keyid,issuer\n"))
	file.Write([]byte("basicConstraints=CA:FALSE\n"))
	file.Write([]byte("subjectAltName = @alt_names\n"))
	file.Write([]byte("[alt_names]\n"))
	file.Write([]byte("DNS.1 = " + domain))
	cmd := exec.Command("bash", "-c", "openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in domain.csr -out domain.crt -days 365 -CAcreateserial -extfile domain.ext")
	err = cmd.Run()
	if err != nil {
		fmt.Println(err)
		return
	}
}

func main() {
	CreateMyCert("www.baidu.com")
}
