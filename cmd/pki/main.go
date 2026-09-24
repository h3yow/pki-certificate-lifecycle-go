// pki 是本地证书生命周期组件的命令行入口。
// 子命令：issue / verify / rotate / revoke，状态保存在 -dir 目录。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/h3yow/pki-certificate-lifecycle-go/pki"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "rotate":
		err = cmdRotate(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法: pki <子命令> [选项]
  issue   -dir D -identity ID -usages sign,encrypt,auth -not-before T -not-after T [-serial N] [-subject-id S]
  verify  -dir D -cert FILE [-at T] -usage sign
  rotate  -dir D
  revoke  -dir D -serial N
时间格式为 RFC3339。`)
}

func parseUsages(s string) (pki.KeyUsage, error) {
	var u pki.KeyUsage
	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(part) {
		case "sign":
			u |= pki.UsageSign
		case "encrypt":
			u |= pki.UsageEncrypt
		case "auth":
			u |= pki.UsageAuth
		default:
			return 0, fmt.Errorf("未知用途 %q", part)
		}
	}
	return u, nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	dir := fs.String("dir", ".pki", "状态目录")
	identity := fs.String("identity", "", "实体标识")
	usages := fs.String("usages", "", "用途，逗号分隔: sign,encrypt,auth")
	notBefore := fs.String("not-before", "", "生效时刻 (RFC3339)")
	notAfter := fs.String("not-after", "", "失效时刻 (RFC3339)")
	serial := fs.Uint64("serial", 0, "显式序列号，0 表示自动分配")
	subjectID := fs.String("subject-id", "", "实体密钥标识")
	if err := fs.Parse(args); err != nil {
		return err
	}
	u, err := parseUsages(*usages)
	if err != nil {
		return err
	}
	nb, err := parseTime(*notBefore)
	if err != nil {
		return err
	}
	na, err := parseTime(*notAfter)
	if err != nil {
		return err
	}
	ca, err := pki.NewCA(*dir)
	if err != nil {
		return err
	}
	cert, err := ca.Issue(pki.IssueRequest{
		Identity: *identity, Usages: u,
		NotBefore: nb, NotAfter: na,
		Serial: *serial, SubjectID: *subjectID,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(cert)
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dir := fs.String("dir", ".pki", "状态目录")
	certFile := fs.String("cert", "", "证书 JSON 文件")
	at := fs.String("at", "", "校验时刻 (RFC3339)，缺省为当前时间")
	usage := fs.String("usage", "", "要求的用途")
	if err := fs.Parse(args); err != nil {
		return err
	}
	u, err := parseUsages(*usage)
	if err != nil {
		return err
	}
	moment, err := parseTime(*at)
	if err != nil {
		return err
	}
	if moment.IsZero() {
		moment = time.Now()
	}
	data, err := os.ReadFile(*certFile)
	if err != nil {
		return err
	}
	var cert pki.Certificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return err
	}
	ca, err := pki.NewCA(*dir)
	if err != nil {
		return err
	}
	v := ca.Verify(&cert, moment, u)
	fmt.Println("结论:", v)
	if !v.OK() {
		os.Exit(1)
	}
	return nil
}

func cmdRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	dir := fs.String("dir", ".pki", "状态目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ca, err := pki.NewCA(*dir)
	if err != nil {
		return err
	}
	epoch, err := ca.Rotate()
	if err != nil {
		return err
	}
	fmt.Println("新密钥代:", epoch)
	return nil
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	dir := fs.String("dir", ".pki", "状态目录")
	serial := fs.Uint64("serial", 0, "待吊销序列号")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ca, err := pki.NewCA(*dir)
	if err != nil {
		return err
	}
	if err := ca.Revoke(*serial); err != nil {
		if errors.Is(err, pki.ErrAlreadyRevoked) || errors.Is(err, pki.ErrCertNotFound) {
			return err
		}
		return err
	}
	fmt.Println("已吊销:", *serial)
	return nil
}
