package utils

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"go.uber.org/zap"
	"xojoc.pw/useragent"
)

var IP = new(ipUtil)

type ipUtil struct{}

// 获取通用信息: ipAddress, ipSource, browser, os
func (i *ipUtil) GetInfo(c *gin.Context) (ipAddress, browser, os string) {
	ipAddress = i.GetIpAddress(c)
	userAgent := i.GetUserAgent(c)
	browser = userAgent.Name + " " + userAgent.Version.String()
	os = userAgent.OS + " " + userAgent.OSVersion.String()
	return
}

// FIXME: 获取用户发送请求的 IP 地址
func (*ipUtil) GetIpAddress(c *gin.Context) (ipAddress string) {
	// fmt.Println("c.ClientIP: ", c.ClientIP())
	ipAddress = c.Request.Header.Get("X-Real-IP")
	if ipAddress == "" || len(ipAddress) == 0 || strings.EqualFold("unknown", ipAddress) {
		ipAddress = c.Request.Header.Get("Proxy-Client-IP")
	}
	if ipAddress == "" || len(ipAddress) == 0 || strings.EqualFold("unknown", ipAddress) {
		ipAddress = c.Request.Header.Get("WL-Proxy-Client-IP")
	}
	if ipAddress == "" || len(ipAddress) == 0 || strings.EqualFold("unknown", ipAddress) {
		ipAddress = c.Request.RemoteAddr
	}

	// fmt.Println("GetIpAddress: ", ipAddress)
	if ipAddress == "127.0.0.1" || strings.HasPrefix(ipAddress, "[::1]") {
		ip, err := externalIP()
		if err != nil {
			Logger.Error("GetIpAddress, externalIP, err: ", zap.Error(err))
		}
		ipAddress = ip.String()
	}
	// fmt.Println("GetIpAddress: ", ipAddress)
	if ipAddress != "" && len(ipAddress) > 15 {
		if strings.Index(ipAddress, ",") > 0 {
			ipAddress = ipAddress[:strings.Index(ipAddress, ",")]
		}
	}
	return ipAddress

	// c.ClientIP() 有时无法获取到真实 IP
	// return c.ClientIP()
}

// 获取 IP 来源
func (*ipUtil) GetIpSource(ipAddress string) string {
	var dbPath = "./config/ip2region.xdb"
	searcher, err := xdb.NewWithFileOnly(dbPath)
	if err != nil {
		Logger.Error("failed to create searcher: ", zap.Error(err))
		return ""
	}
	defer searcher.Close()
	region, err := searcher.SearchByStr(ipAddress)
	if err != nil {
		Logger.Error(fmt.Sprintf("failed to SearchIP(%s): %s\n", ipAddress, err))
		return "未知"
	}
	fmt.Println(region)
	return region
}

func (i *ipUtil) GetIpSourceSimpleIdle(ipAddress string) string {
	return i.IpSourceSimpleSplit(i.GetIpSource(ipAddress))
}

func (*ipUtil) IpSourceSimpleSplit(region string) string {
	// 中国|0|江苏省|苏州市|电信
	// 0|0|0|内网IP|内网IP
	if strings.Contains(region, "内网IP") {
		return "内容IP"
	}

	ipSource := strings.Split(region, "|")
	if ipSource[0] != "中国" && ipSource[0] != "0" {
		return ipSource[0]
	}
	if ipSource[2] == "0" {
		ipSource[2] = ""
	}
	if ipSource[3] == "0" {
		ipSource[3] = ""
	}
	if ipSource[4] == "0" {
		ipSource[4] = ""
	}
	if ipSource[2] == "" && ipSource[3] == "" && ipSource[4] == "" {
		return ipSource[0]
	}
	return ipSource[2] + ipSource[3] + " " + ipSource[4]
}

func (*ipUtil) GetUserAgent(c *gin.Context) *useragent.UserAgent {
	ua := useragent.Parse(c.Request.UserAgent())
	return ua
}

func externalIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip := getIpFromAddr(addr)
			if ip == nil {
				continue
			}
			return ip, nil
		}
	}
	return nil, errors.New("connected to the network")
}

func getIpFromAddr(addr net.Addr) net.IP {
	var ip net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	if ip == nil || ip.IsLoopback() {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil
	}
	return ip
}
