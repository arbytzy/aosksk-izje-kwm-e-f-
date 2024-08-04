package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	client    = &http.Client{Timeout: 10 * time.Second}
	resolver  = &dns.Client{
		Net:          "udp",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	nameservers = []string{"8.8.8.8:53", "8.8.4.4:53"}
)

var cloudflareIPRanges = []string{
	"104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
	"104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
	"104.28.", "104.29.", "104.30.", "104.31.",
}

var relevantPorts = []int{80, 443, 8080, 8443}

func isCloudflareIP(ip string) bool {
	for _, prefix := range cloudflareIPRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

func isCloudFrontIP(ip string) bool {
	// Implementasi cek IP CloudFront (masukkan range IP CloudFront jika tersedia)
	return false
}

func detectRealIP(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func fetchJSON(url string) ([]map[string]interface{}, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result []map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	return result, err
}

func fetchText(url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return string(body), err
}

func findSubdomains(domain string) (map[string]bool, error) {
	subdomains := make(map[string]bool)

	sources := []string{
		fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain),
		fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=2d39b7e63cccd0f8d3f33e4c821a4e39c3a7c3af61dd768fbefce2d6caf57b5a&domain=%s", domain),
		fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain),
		fmt.Sprintf("https://sonar.omnisint.io/subdomains/%s", domain),
		fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain),
		fmt.Sprintf("https://riddler.io/search/exportcsv?q=pld:%s", domain),
		fmt.Sprintf("https://api.sublist3r.com/search.php?domain=%s", domain),
		fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain),
		fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?apikey=xruw2Du1IZ3OHG7mggGvKA80GkJAMXyb", domain),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, url := range sources {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			switch url {
			case fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain):
				data, err := fetchJSON(url)
				if err == nil {
					for _, entry := range data {
						if nameValue, ok := entry["name_value"].(string); ok {
							mu.Lock()
							subdomains[nameValue] = false
							mu.Unlock()
						}
					}
				}
			case fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=2d39b7e63cccd0f8d3f33e4c821a4e39c3a7c3af61dd768fbefce2d6caf57b5a&domain=%s", domain),
				fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain):
				data, err := fetchJSON(url)
				if err == nil {
					for _, entry := range data {
						if subdomainsList, ok := entry["subdomains"].([]interface{}); ok {
							for _, sub := range subdomainsList {
								if subdomain, ok := sub.(string); ok {
									mu.Lock()
									subdomains[fmt.Sprintf("%s.%s", subdomain, domain)] = false
									mu.Unlock()
								}
							}
						}
					}
				}
			case fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain),
				fmt.Sprintf("https://api.sublist3r.com/search.php?domain=%s", domain):
				body, err := fetchText(url)
				if err == nil {
					lines := strings.Split(body, "\n")
					for _, line := range lines {
						parts := strings.Split(line, ",")
						if len(parts) > 0 {
							mu.Lock()
							subdomains[parts[0]] = false
							mu.Unlock()
						}
					}
				}
			case fmt.Sprintf("https://sonar.omnisint.io/subdomains/%s", domain):
				body, err := fetchText(url)
				if err == nil {
					var subList []string
					if err := json.Unmarshal([]byte(body), &subList); err == nil {
						for _, sub := range subList {
							mu.Lock()
							subdomains[sub] = false
							mu.Unlock()
						}
					}
				}
			case fmt.Sprintf("https://riddler.io/search/exportcsv?q=pld:%s", domain):
				body, err := fetchText(url)
				if err == nil {
					lines := strings.Split(body, "\n")
					for _, line := range lines {
						parts := strings.Split(line, ",")
						if len(parts) > 1 {
							mu.Lock()
							subdomains[parts[1]] = false
							mu.Unlock()
						}
					}
				}
			case fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain):
				data, err := fetchJSON(url)
				if err == nil {
					for _, entry := range data {
						if dnsNames, ok := entry["dns_names"].([]interface{}); ok {
							for _, name := range dnsNames {
								if nameStr, ok := name.(string); ok {
									mu.Lock()
									subdomains[nameStr] = false
									mu.Unlock()
								}
							}
						}
					}
				}
			case fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?apikey=xruw2Du1IZ3OHG7mggGvKA80GkJAMXyb", domain):
				resp, err := client.Get(url)
				if err == nil {
					defer resp.Body.Close()
					var result map[string]interface{}
					if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
						if subList, ok := result["subdomains"].([]interface{}); ok {
							for _, sub := range subList {
								if subStr, ok := sub.(string); ok {
									mu.Lock()
									subdomains[fmt.Sprintf("%s.%s", subStr, domain)] = false
									mu.Unlock()
								}
							}
						}
					}
				}
			}
		}(url)
	}

	wg.Wait()
	return subdomains, nil
}

func detectCDN(domainOrIP string) (map[string]string, error) {
	ip := detectRealIP(domainOrIP)
	subdomains, err := findSubdomains(domainOrIP)
	if err != nil {
		return nil, err
	}

	cdnDomainsOrIPs := make(map[string]string)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for subdomain := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			ips, err := net.LookupIP(subdomain)
			if err == nil {
				for _, subIP := range ips {
					if isCloudflareIP(subIP.String()) {
						mu.Lock()
						cdnDomainsOrIPs[subdomain] = "Cloudflare"
						mu.Unlock()
					} else if isCloudFrontIP(subIP.String()) {
						mu.Lock()
						cdnDomainsOrIPs[subdomain] = "CloudFront"
						mu.Unlock()
					}
				}
			}
		}(subdomain)
	}

	wg.Wait()

	if isCloudflareIP(ip) {
		cdnDomainsOrIPs[domainOrIP] = "Cloudflare"
	} else if isCloudFrontIP(ip) {
		cdnDomainsOrIPs[domainOrIP] = "CloudFront"
	}

	return cdnDomainsOrIPs, nil
}

func getIPsFromHost(host string) []string {
	ips, err := net.LookupIP(host)
	if err != nil {
		return []string{}
	}
	var ipList []string
	for _, ip := range ips {
		ipList = append(ipList, ip.String())
	}
	return ipList
}

func checkHostAvailability(ip string) bool {
	resp, err := client.Get("http://" + ip)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func scanPort(ip string, port int, wg *sync.WaitGroup, results chan<- int) {
	defer wg.Done()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 1*time.Second)
	if err == nil {
		results <- port
		conn.Close()
	}
}

func scanPorts(ip string, ports []int) []int {
	var openPorts []int
	var wg sync.WaitGroup
	results := make(chan int, len(ports))

	for _, port := range ports {
		wg.Add(1)
		go scanPort(ip, port, &wg, results)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for port := range results {
		openPorts = append(openPorts, port)
	}

	return openPorts
}

func scanRelevantPorts(ip string) []int {
	return scanPorts(ip, relevantPorts)
}

func checkSubdomain(subdomain string) (string, int) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + subdomain)
	if err != nil {
		return "[FAILED]", 0
	}
	defer resp.Body.Close()
	return fmt.Sprintf("[SUCCESS] [%d]", resp.StatusCode), resp.StatusCode
}

func getIPExplanation(ip string) string {
	resp, err := client.Get(fmt.Sprintf("https://ipinfo.io/%s/json", ip))
	if err != nil {
		return "[Unknown]"
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	as, _ := result["org"].(string)
	country, _ := result["country"].(string)
	return fmt.Sprintf("[%s, %s, %s]", as, country, ip)
}

func createProxyPayload(ip, port, service, host string) map[string]string {
	if service == "Cloudflare" || service == "CloudFront" {
		return map[string]string{
			"http":           fmt.Sprintf("http://%s:%s", host, port),
			"socks4":         fmt.Sprintf("socks4://%s:%s", host, port),
			"socks5":         fmt.Sprintf("socks5://%s:%s", host, port),
			"direct_http":    fmt.Sprintf("shttp://%s:%s", host, port),
			"direct_socks4":  fmt.Sprintf("shttp4://%s:%s", host, port),
			"direct_socks5":  fmt.Sprintf("shttp5://%s:%s", host, port),
		}
	} else {
		return map[string]string{
			"http":           fmt.Sprintf("http://%s:%s", ip, port),
			"socks4":         fmt.Sprintf("socks4://%s:%s", ip, port),
			"socks5":         fmt.Sprintf("socks5://%s:%s", ip, port),
			"direct_http":    fmt.Sprintf("shttp://%s:%s", ip, port),
			"direct_socks4":  fmt.Sprintf("shttp4://%s:%s", ip, port),
			"direct_socks5":  fmt.Sprintf("shttp5://%s:%s", ip, port),
		}
	}
}

func intSliceToStringSlice(ints []int) []string {
	strs := make([]string, len(ints))
	for i, v := range ints {
		strs[i] = fmt.Sprintf("%d", v)
	}
	return strs
}

type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

type Host struct {
	XMLName xml.Name `xml:"host"`
	Ports   Ports    `xml:"ports"`
}

type Ports struct {
	XMLName xml.Name `xml:"ports"`
	Ports   []Port   `xml:"port"`
}

type Port struct {
	XMLName xml.Name `xml:"port"`
	PortID  int      `xml:"portid,attr"`
	State   State    `xml:"state"`
	Service Service  `xml:"service"`
}

type State struct {
	XMLName xml.Name `xml:"state"`
	State   string   `xml:"state,attr"`
}

type Service struct {
	XMLName xml.Name `xml:"service"`
	Name    string   `xml:"name,attr"`
}

func performNmapScan(target string) ([]Port, error) {
	cmd := exec.Command("nmap", "-oX", "-", "-p", "80,443,8080,8443", target)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var nmapRun NmapRun
	err = xml.Unmarshal(output, &nmapRun)
	if err != nil {
		return nil, err
	}

	var ports []Port
	for _, host := range nmapRun.Hosts {
		for _, port := range host.Ports.Ports {
			if port.State.State == "open" {
				ports = append(ports, port)
			}
		}
	}

	return ports, nil
}

const (
	yellowText = "\033[93m"
	redText    = "\033[91m"
	resetText  = "\033[0m"
)

func clearDisplay() {
	fmt.Print("\033[H\033[2J")
}

func main() {
	clearDisplay()
	fmt.Println(yellowText + "Advanced Host, IP, Port, and DNS Checker" + resetText)
	fmt.Println(yellowText + "========================================" + resetText)
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(yellowText + "Enter a host or SNI: " + resetText)
	userInput, _ := reader.ReadString('\n')
	userInput = strings.TrimSpace(userInput)

	host := userInput
	ips := getIPsFromHost(host)
	if len(ips) > 0 && checkHostAvailability(ips[0]) {
		fmt.Println(yellowText + "Host is reachable" + resetText)
	} else {
		fmt.Println(redText + "Host is not reachable" + resetText)
	}

	subdomains, _ := findSubdomains(host)
	cdnDomainsOrIPs, _ := detectCDN(host)
	var subdomainDetails []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	for subdomain := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			cdnType := "Unknown"
			if cdn, ok := cdnDomainsOrIPs[subdomain]; ok {
				cdnType = cdn
			}
			status, statusCode := checkSubdomain(subdomain)
			ipExplanations := getIPsFromHost(subdomain)
			ipExplanationStrs := []string{}
			for _, ip := range ipExplanations {
				ipExplanationStrs = append(ipExplanationStrs, getIPExplanation(ip))
			}
			ipExplanationsStr := strings.Join(ipExplanationStrs, ", ")
			mu.Lock()
			subdomainDetails = append(subdomainDetails, fmt.Sprintf("https://%s %s [%d] [%s] [%s]", subdomain, status, statusCode, cdnType, ipExplanationsStr))
			mu.Unlock()
		}(subdomain)
	}

	wg.Wait()

	cloudflareFile, err := os.Create("/sdcard/TERMUX/cloudflare.txt")
	if err != nil {
		fmt.Println(yellowText + "Could not create Cloudflare result file:" + resetText, err)
		return
	}
	defer cloudflareFile.Close()

	cloudfrontFile, err := os.Create("/sdcard/TERMUX/cloudfront.txt")
	if err != nil {
		fmt.Println(yellowText + "Could not create CloudFront result file:" + resetText, err)
		return
	}
	defer cloudfrontFile.Close()

	otherFile, err := os.Create("/sdcard/TERMUX/other.txt")
	if err != nil {
		fmt.Println(yellowText + "Could not create Other result file:" + resetText, err)
		return
	}
	defer otherFile.Close()

	cloudflareWriter := bufio.NewWriter(cloudflareFile)
	defer cloudflareWriter.Flush()

	cloudfrontWriter := bufio.NewWriter(cloudfrontFile)
	defer cloudfrontWriter.Flush()

	otherWriter := bufio.NewWriter(otherFile)
	defer otherWriter.Flush()

	printAndWrite := func(text string, writer *bufio.Writer, color string) {
		coloredText := color + text + resetText
		fmt.Println(coloredText)
		writer.WriteString(text + "\n")
	}

	for _, detail := range subdomainDetails {
		parts := strings.Split(detail, " ")
		subdomain := parts[0][8:]
		cdnType := parts[3]

		var writer *bufio.Writer
		var color string

		if cdnType == "[Cloudflare]" {
			writer = cloudflareWriter
			color = yellowText
		} else if cdnType == "[CloudFront]" {
			writer = cloudfrontWriter
			color = redText
		} else {
			writer = otherWriter
			color = resetText
		}

		printAndWrite(detail, writer, color)

		subIPs := getIPsFromHost(subdomain)
		if len(subIPs) > 0 {
			printAndWrite("  Open Ports:", writer, color)
			for _, subIP := range subIPs {
				subOpenPorts, err := performNmapScan(subIP)
				if err != nil {
					printAndWrite(fmt.Sprintf("Error scanning ports for %s: %v", subIP, err), writer, color)
					continue
				}
				portStrs := []string{}
				for _, port := range subOpenPorts {
					portStrs = append(portStrs, fmt.Sprintf("%d/%s", port.PortID, port.Service.Name))
				}
				printAndWrite(fmt.Sprintf("        %s: %s", subIP, strings.Join(portStrs, ", ")), writer, color)
			}
			printAndWrite("  IP Explanations:", writer, color)
			for _, subIP := range subIPs {
				cdnType := ""
				if isCloudflareIP(subIP) {
					cdnType = "Cloudflare"
				} else if isCloudFrontIP(subIP) {
					cdnType = "CloudFront"
				}
				explanation := getIPExplanation(subIP)
				printAndWrite(fmt.Sprintf("    %s [%s]: %s", subIP, cdnType, explanation), writer, color)
			}
		}
		printAndWrite("========================================", writer, color)
	}

	fmt.Println(yellowText + "Results saved to /sdcard/TERMUX/cloudflare.txt, /sdcard/TERMUX/cloudfront.txt, and /sdcard/TERMUX/other.txt" + resetText)
}
