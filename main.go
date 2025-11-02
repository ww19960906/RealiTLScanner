package main

import (
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var addr string
var in string
var port int
var thread int
var out string
var timeout time.Duration
var verbose bool
var enableIPv6 bool
var url string
var rps int

func main() {
	_ = os.Unsetenv("ALL_PROXY")
	_ = os.Unsetenv("HTTP_PROXY")
	_ = os.Unsetenv("HTTPS_PROXY")
	_ = os.Unsetenv("NO_PROXY")
	flag.StringVar(&addr, "addr", "", "指定要扫描的 IP, IP段 或 域名")
	flag.StringVar(&in, "in", "", "指定包含多个扫描目标的文件, 每行一个")
	flag.IntVar(&port, "port", 443, "指定要检查的 HTTPS 端口 (默认 443)")
	flag.IntVar(&thread, "thread", 2, "并发扫描任务数 (默认 2)")
	flag.StringVar(&out, "out", "out.csv", "用于存储结果的输出文件 (默认 out.csv)")
	flag.DurationVar(&timeout, "timeout", 2*time.Second, "每次检查的超时时间 (例如: 5s, 2000ms)")
	flag.BoolVar(&verbose, "v", false, "启用详细输出模式")
	flag.BoolVar(&enableIPv6, "46", false, "同时启用 IPv6 扫描")
	flag.StringVar(&url, "url", "", "从一个URL中抓取域名列表进行扫描")
	flag.IntVar(&rps, "rps", 50, "每秒最大请求数 (默认 50, 0 代表无限制)")
	flag.Parse()
	if verbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})))
	}
	if !ExistOnlyOne([]string{addr, in, url}) {
		slog.Error("参数 'addr', 'in', 'url' 只能指定其中一个")
		flag.PrintDefaults()
		return
	}
	outWriter := io.Discard
	if out != "" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			slog.Error("打开输出文件时出错", "path", out)
			return
		}
		defer f.Close()
		_, _ = f.WriteString("IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n")
		outWriter = f
	}
	var hostChan <-chan Host
	if addr != "" {
		hostChan = IterateAddr(addr)
	} else if in != "" {
		f, err := os.Open(in)
		if err != nil {
			slog.Error("读取输入文件时出错", "path", in)
			return
		}
		defer f.Close()
		hostChan = Iterate(f)
	} else {
		slog.Info("正在抓取URL...")
		resp, err := http.Get(url)
		if err != nil {
			slog.Error("抓取URL时出错", "err", err)
			return
		}
		defer resp.Body.Close()
		v, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("读取响应内容时出错", "err", err)
			return
		}
		arr := regexp.MustCompile("(http|https)://(.*?)[/\"<>\\s]+").FindAllStringSubmatch(string(v), -1)
		var domains []string
		for _, m := range arr {
			domains = append(domains, m[2])
		}
		domains = RemoveDuplicateStr(domains)
		slog.Info("已解析域名", "count", len(domains))
		hostChan = Iterate(strings.NewReader(strings.Join(domains, "\n")))
	}
	outCh := OutWriter(outWriter)
	defer close(outCh)
	geo := NewGeo()
	var wg sync.WaitGroup
	wg.Add(thread)
	for i := 0; i < thread; i++ {
		go func() {
			for ip := range hostChan {
				ScanTLS(ip, outCh, geo)
			}
			wg.Done()
		}()
	}
	t := time.Now()
	slog.Info("所有扫描线程已启动", "time", t)
	wg.Wait()
	slog.Info("扫描完成", "time", time.Now(), "elapsed", time.Since(t).String())
}
