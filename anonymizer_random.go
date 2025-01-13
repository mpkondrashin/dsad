package main

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"regexp"
	"strings"
)

func GenerateIP(ipString string) string {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		fmt.Println("Not an IPv4 address")
		return ""
	}
	if ip[0] == 10 {
		return fmt.Sprintf("10.%d.%d.%d", random.Intn(256), random.Intn(256), random.Intn(255))
	}
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return fmt.Sprintf("172.%d.%d.%d", random.Intn(32), random.Intn(256), random.Intn(255))
	}
	if ip[0] == 192 && ip[1] == 168 {
		return fmt.Sprintf("192.168.%d.%d", random.Intn(256), random.Intn(255))
	}
	return ipString //fmt.Sprintf("%d.%d.%d.%d", random.Intn(256), random.Intn(256), random.Intn(256), random.Intn(255))
}

type AnonymizerRandom struct {
	replaceList  map[string]string
	replaceData  map[string]struct{}
	hostnameList []string
}

func NewAnonymizerRandom() *AnonymizerRandom {
	return &AnonymizerRandom{
		replaceList: make(map[string]string),
		replaceData: make(map[string]struct{}),
	}
}

func (a *AnonymizerRandom) AddHostname(hostname string) *AnonymizerRandom {
	a.hostnameList = append(a.hostnameList, hostname)
	return a
}

func (a *AnonymizerRandom) IP(ip string) string {
	newIP := a.replaceList[ip]
	if newIP != "" {
		return newIP
	}
	for {
		newIP = GenerateIP(ip)
		_, ok := a.replaceData[newIP]
		if !ok {
			a.replaceList[ip] = newIP
			a.replaceData[newIP] = struct{}{}
			return newIP
		}
	}
}

func (a *AnonymizerRandom) Hostname(hostname string) string {
	newHostname := a.replaceList[hostname]
	if newHostname != "" {
		return newHostname
	}
	for {
		newHostname = fmt.Sprintf("host%06d", rand.Intn(1000000))
		_, ok := a.replaceData[newHostname]
		if !ok {
			a.replaceList[hostname] = newHostname
			a.replaceData[newHostname] = struct{}{}
			return newHostname
		}
	}
}

var (
	privateIPre    = `\b(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})\b`
	privateIPRegex = regexp.MustCompile(privateIPre)
)

func (a *AnonymizerRandom) AnonymyzeIPs(data string) string {
	return privateIPRegex.ReplaceAllStringFunc(data, func(match string) string {
		return a.IP(match)
	})
}

func (a *AnonymizerRandom) AnonymizeHostnames(data string) string {
	regexStr := fmt.Sprintf("(?i)(%s)", strings.Join(a.hostnameList, "|"))
	re := regexp.MustCompile(regexStr)
	return re.ReplaceAllStringFunc(data, func(match string) string {
		h := a.Hostname(match)
		fmt.Printf("%s -> %s\n", match, h)
		return h
		//		return a.Hostname(match)
	})
}

func (a *AnonymizerRandom) Process(data string) string {
	data = a.AnonymyzeIPs(data)
	data = a.AnonymizeHostnames(data)
	return data
}

func (a *AnonymizerRandom) FilterFilenames(dst io.Writer, src io.Reader) error {
	var sb strings.Builder
	_, err := io.Copy(&sb, src)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %v", err)
	}
	resultData := a.Process(sb.String())
	_, err = dst.Write([]byte(resultData))
	if err != nil {
		return fmt.Errorf("failed to write file contents: %v", err)
	}
	return nil
}
