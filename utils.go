package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

const (
	_ = iota
	HostTypeIP
	HostTypeCIDR
	HostTypeDomain
)

type HostType int

type Host struct {
	IP     net.IP
	Origin string
	Type   HostType
}

var domainRegex = regexp.MustCompile(`(?m)^[A-Za-z0-9\-.]+$`)

func Iterate(reader io.Reader) <-chan Host {
	scanner := bufio.NewScanner(reader)
	hostChan := make(chan Host, 100)
	go func() {
		defer close(hostChan)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ip := net.ParseIP(line)
			if ip != nil && (ip.To4() != nil || enableIPv6) {
				hostChan <- Host{
					IP:     ip,
					Origin: line,
					Type:   HostTypeIP,
				}
				continue
			}
			_, _, err := net.ParseCIDR(line)
			if err == nil {
				p, err := netip.ParsePrefix(line)
				if err != nil {
					slog.Warn("无效的CIDR地址段", "cidr", line, "err", err)
				}
				if !p.Addr().Is4() && !enableIPv6 {
					continue
				}
				p = p.Masked()
				addr := p.Addr()
				for {
					if !p.Contains(addr) {
						break
					}
					ip = net.ParseIP(addr.String())
					if ip != nil {
						hostChan <- Host{
							IP:     ip,
							Origin: line,
							Type:   HostTypeCIDR,
						}
					}
					addr = addr.Next()
				}
				continue
			}
			if ValidateDomainName(line) {
				hostChan <- Host{
					IP:     nil,
					Origin: line,
					Type:   HostTypeDomain,
				}
				continue
			}
			slog.Warn("无效的IP, IP段或域名", "line", line)
		}
		if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
			slog.Error("读取文件时出错", "err", err)
		}
	}()
	return hostChan
}
func ValidateDomainName(domain string) bool {
	return domainRegex.MatchString(domain)
}
func ExistOnlyOne(arr []string) bool {
	exist := false
	for _, item := range arr {
		if item != "" {
			if exist {
				return false
			} else {
				exist = true
			}
		}
	}
	return exist
}
func IterateAddr(addr string) <-chan Host {
	if _, _, err := net.ParseCIDR(addr); err == nil {
		return Iterate(strings.NewReader(addr))
	}

	hostChan := make(chan Host, 256)
	go func() {
		defer close(hostChan)

		var ipsToScan []net.IP
		isDomain := false

		if ip := net.ParseIP(addr); ip != nil {
			ipsToScan = append(ipsToScan, ip)
		} else {
			isDomain = true
			allIPs, err := net.LookupIP(addr)
			if err != nil {
				slog.Error("域名解析失败", "domain", addr, "err", err)
				return
			}
			for _, lookupIP := range allIPs {
				if ipv4 := lookupIP.To4(); ipv4 != nil {
					ipsToScan = append(ipsToScan, ipv4)
				}
			}
		}

		if len(ipsToScan) == 0 {
			slog.Error("未找到与目标关联的有效IPv4地址", "target", addr)
			return
		}

		var hostType HostType
		if isDomain {
			hostType = HostTypeDomain
		} else {
			hostType = HostTypeIP
		}

		for _, baseIP := range ipsToScan {
			ipv4 := baseIP.To4()
			if ipv4 == nil {
				continue
			}

			slog.Info("开始扫描 /24 子网", "baseIP", ipv4.String())
			subnetBase := net.IPv4(ipv4[0], ipv4[1], ipv4[2], 0)

			for i := 0; i < 256; i++ {
				targetIP := net.IPv4(subnetBase[0], subnetBase[1], subnetBase[2], byte(i))
				hostChan <- Host{
					IP:     targetIP,
					Origin: addr,
					Type:   hostType,
				}
			}
		}
	}()

	return hostChan
}
func LookupIP(addr string) (net.IP, error) {
	ips, err := net.LookupIP(addr)
	if err != nil {
		return nil, fmt.Errorf("域名解析失败: %w", err)
	}
	var arr []net.IP
	for _, ip := range ips {
		if ip.To4() != nil || enableIPv6 {
			arr = append(arr, ip)
		}
	}
	if len(arr) == 0 {
		return nil, errors.New("未找到IP地址")
	}
	return arr[0], nil
}
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	var list []string
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
func OutWriter(writer io.Writer) chan<- string {
	ch := make(chan string)
	go func() {
		for s := range ch {
			_, _ = io.WriteString(writer, s)
		}
	}()
	return ch
}
