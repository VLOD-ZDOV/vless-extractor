package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"
)

var vlessRegex = regexp.MustCompile(`vless://[^\s"'<>]+`)

type SingBoxConfig struct {
	Outbounds []SingBoxOutbound `json:"outbounds"`
}

type SingBoxOutbound struct {
	Type       string                 `json:"type"`
	Tag        string                 `json:"tag"`
	Server     string                 `json:"server"`
	ServerPort int                    `json:"server_port"`
	UUID       string                 `json:"uuid"`
	Flow       string                 `json:"flow"`
	Network    string                 `json:"network"`
	TLS        *SingBoxTLS            `json:"tls"`
	Transport  map[string]interface{} `json:"transport"`
}

type SingBoxTLS struct {
	Enabled    bool            `json:"enabled"`
	ServerName string          `json:"server_name"`
	Insecure   bool            `json:"insecure"`
	UTLS       *SingBoxUTLS    `json:"utls"`
	Reality    *SingBoxReality `json:"reality"`
}

type SingBoxUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type SingBoxReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

func main() {
	outputFile := flag.String("o", "", "Output file to save links (e.g. -o vless.txt)")
	insecure := flag.Bool("k", false, "Ignore SSL certificate errors")
	verbose := flag.Bool("v", false, "Verbose output with node remarks and settings")
	decodeNames := flag.Bool("d", false, "Decode URL-encoded server names in #fragment")
	pause := flag.Bool("pause", false, "Wait for Enter before exiting")
	hwidFlag := flag.String("hwid", "", "Custom HWID string (default: persistent hash of URL)")
	flag.Parse()

	args := flag.Args()
	var rawInput string

	if len(args) > 0 {
		rawInput = strings.TrimSpace(args[0])
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			bytes, err := io.ReadAll(os.Stdin)
			if err == nil {
				rawInput = strings.TrimSpace(string(bytes))
			}
		}
	}

	isInteractive := false
	if rawInput == "" {
		isInteractive = true
		fmt.Println("==================================================")
		fmt.Println("          VLESS Link Extractor (CLI)              ")
		fmt.Println("==================================================")
		fmt.Print("Enter subscription URL or file path: ")
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Input error:", err)
			waitIfInteractive(isInteractive, *pause)
			return
		}
		rawInput = strings.TrimSpace(input)

		if *hwidFlag == "" {
			fmt.Print("Enter HWID (press Enter for auto): ")
			hwidInput, _ := reader.ReadString('\n')
			*hwidFlag = strings.TrimSpace(hwidInput)
		}
	}

	if rawInput == "" {
		fmt.Println("Error: No input provided.")
		waitIfInteractive(isInteractive, *pause)
		return
	}

	var content string
	if strings.HasPrefix(rawInput, "http://") || strings.HasPrefix(rawInput, "https://") {
		fmt.Fprintf(os.Stderr, "[*] Fetching subscription: %s ...\n", rawInput)
		hwid := *hwidFlag
		if hwid == "" {
			hwid = getDeterministicHWID(rawInput)
		}
		fetched, err := fetchURL(rawInput, hwid, *insecure)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Fetch error: %v\n", err)
			waitIfInteractive(isInteractive, *pause)
			os.Exit(1)
		}
		content = fetched
	} else if fileExists(rawInput) {
		fmt.Fprintf(os.Stderr, "[*] Reading file: %s ...\n", rawInput)
		data, err := os.ReadFile(rawInput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] File read error: %v\n", err)
			waitIfInteractive(isInteractive, *pause)
			os.Exit(1)
		}
		content = string(data)
	} else {
		content = rawInput
	}

	links := extractVlessLinks(content)
	if len(links) == 0 {
		fmt.Println("[-] No vless:// links found in the provided content.")
		waitIfInteractive(isInteractive, *pause)
		return
	}

	fmt.Fprintf(os.Stderr, "[+] Found VLESS links: %d\n\n", len(links))

	var outputLines []string
	for i, link := range links {
		finalLink := link
		if *decodeNames {
			finalLink = decodeRemark(link)
		}
		outputLines = append(outputLines, finalLink)

		if *verbose {
			remark := extractRemark(link)
			fmt.Printf("[%d] %s\n    %s\n\n", i+1, remark, finalLink)
		} else {
			fmt.Println(finalLink)
		}
	}

	if *outputFile != "" {
		err := os.WriteFile(*outputFile, []byte(strings.Join(outputLines, "\n")+"\n"), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to write file %s: %v\n", *outputFile, err)
		} else {
			fmt.Fprintf(os.Stderr, "[+] Links saved to: %s\n", *outputFile)
		}
	}

	waitIfInteractive(isInteractive, *pause)
}

func getDeterministicHWID(urlStr string) string {
	h := sha256.Sum256([]byte("hwid_salt:" + urlStr))
	return hex.EncodeToString(h[:16])
}

func fetchURL(targetURL string, hwid string, insecure bool) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   20 * time.Second,
	}

	userAgents := []string{
		"v2rayN/6.40",
		"curl/8.23.0",
		"sing-box/1.9.0",
		"NekoBox/1.3.0",
	}

	var lastErr error
	for _, ua := range userAgents {
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "ru,en;q=0.9")

		if hwid != "" {
			req.Header.Set("x-hwid", hwid)
			req.Header.Set("x-device-os", "Windows")
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return "", err
			}
			return string(body), nil
		}
		lastErr = fmt.Errorf("HTTP %d (%s)", resp.StatusCode, resp.Status)
	}

	return "", lastErr
}

func extractVlessLinks(raw string) []string {
	seen := make(map[string]bool)
	var result []string

	addLink := func(link string) {
		link = strings.TrimSpace(link)
		if link == "" || seen[link] {
			return
		}
		seen[link] = true
		result = append(result, link)
	}

	for _, match := range vlessRegex.FindAllString(raw, -1) {
		addLink(match)
	}

	decoded, ok := tryDecodeBase64(raw)
	if ok {
		for _, match := range vlessRegex.FindAllString(decoded, -1) {
			addLink(match)
		}

		if doubleDecoded, ok2 := tryDecodeBase64(decoded); ok2 {
			for _, match := range vlessRegex.FindAllString(doubleDecoded, -1) {
				addLink(match)
			}
		}

		extractFromJSON(decoded, addLink)
	}

	extractFromJSON(raw, addLink)

	return result
}

func tryDecodeBase64(raw string) (string, bool) {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, raw)

	if len(clean) < 4 {
		return "", false
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}

	for _, enc := range encodings {
		data, err := enc.DecodeString(clean)
		if err == nil && len(data) > 0 && isPrintable(data) {
			return string(data), true
		}

		if pad := len(clean) % 4; pad != 0 {
			padded := clean + strings.Repeat("=", 4-pad)
			data, err = enc.DecodeString(padded)
			if err == nil && len(data) > 0 && isPrintable(data) {
				return string(data), true
			}
		}
	}

	return "", false
}

func isPrintable(data []byte) bool {
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 32 && b <= 126) || b >= 128 {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.85
}

func extractFromJSON(content string, addLink func(string)) {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return
	}

	var sbConfig SingBoxConfig
	if err := json.Unmarshal([]byte(content), &sbConfig); err == nil && len(sbConfig.Outbounds) > 0 {
		for _, ob := range sbConfig.Outbounds {
			if ob.Type == "vless" && ob.Server != "" && ob.Server != "0.0.0.0" && ob.UUID != "" && ob.UUID != "00000000-0000-0000-0000-000000000000" {
				link := buildSingBoxVlessURL(ob)
				if link != "" {
					addLink(link)
				}
			}
		}
	}

	parseXrayJSON(content, addLink)
}

func parseXrayJSON(content string, addLink func(string)) {
	var rawItems []json.RawMessage

	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &rawItems); err != nil {
			return
		}
	} else if strings.HasPrefix(trimmed, "{") {
		rawItems = append(rawItems, json.RawMessage(trimmed))
	} else {
		return
	}

	for _, itemRaw := range rawItems {
		var itemMap map[string]interface{}
		if err := json.Unmarshal(itemRaw, &itemMap); err != nil {
			continue
		}

		remarks, _ := itemMap["remarks"].(string)

		outboundsRaw, ok := itemMap["outbounds"].([]interface{})
		if !ok {
			continue
		}

		for _, obRaw := range outboundsRaw {
			ob, ok := obRaw.(map[string]interface{})
			if !ok {
				continue
			}

			proto, _ := ob["protocol"].(string)
			if proto != "vless" {
				continue
			}

			tag, _ := ob["tag"].(string)
			nodeName := remarks
			if nodeName == "" {
				nodeName = tag
			}

			settings, _ := ob["settings"].(map[string]interface{})
			vnextList, _ := settings["vnext"].([]interface{})
			if len(vnextList) == 0 {
				continue
			}

			streamSettings, _ := ob["streamSettings"].(map[string]interface{})
			network, _ := streamSettings["network"].(string)
			if network == "" {
				network = "tcp"
			}
			security, _ := streamSettings["security"].(string)
			if security == "" {
				security = "none"
			}

			for _, vnRaw := range vnextList {
				vn, ok := vnRaw.(map[string]interface{})
				if !ok {
					continue
				}

				address, _ := vn["address"].(string)
				if address == "" || address == "0.0.0.0" {
					continue
				}

				port := 443
				if pNum, ok := vn["port"].(float64); ok && pNum > 0 {
					port = int(pNum)
				}

				usersList, _ := vn["users"].([]interface{})
				for _, uRaw := range usersList {
					u, ok := uRaw.(map[string]interface{})
					if !ok {
						continue
					}

					uuid, _ := u["id"].(string)
					if uuid == "" || uuid == "00000000-0000-0000-0000-000000000000" {
						continue
					}

					flow, _ := u["flow"].(string)
					encryption, _ := u["encryption"].(string)
					if encryption == "" {
						encryption = "none"
					}

					q := url.Values{}
					q.Set("encryption", encryption)
					if flow != "" {
						q.Set("flow", flow)
					}
					q.Set("type", network)
					q.Set("security", security)

					if security == "reality" {
						rs, _ := streamSettings["realitySettings"].(map[string]interface{})
						if sn, ok := rs["serverName"].(string); ok && sn != "" {
							q.Set("sni", sn)
						}
						if pbk, ok := rs["publicKey"].(string); ok && pbk != "" {
							q.Set("pbk", pbk)
						}
						if sid, ok := rs["shortId"].(string); ok && sid != "" {
							q.Set("sid", sid)
						}
						if fp, ok := rs["fingerprint"].(string); ok && fp != "" {
							q.Set("fp", fp)
						}
						if spx, ok := rs["spiderX"].(string); ok && spx != "" {
							q.Set("spx", spx)
						}
					} else if security == "tls" {
						ts, _ := streamSettings["tlsSettings"].(map[string]interface{})
						if sn, ok := ts["serverName"].(string); ok && sn != "" {
							q.Set("sni", sn)
						}
						if fp, ok := ts["fingerprint"].(string); ok && fp != "" {
							q.Set("fp", fp)
						}
					}

					if network == "ws" {
						ws, _ := streamSettings["wsSettings"].(map[string]interface{})
						if p, ok := ws["path"].(string); ok && p != "" {
							q.Set("path", p)
						}
						if headers, ok := ws["headers"].(map[string]interface{}); ok {
							if h, ok := headers["Host"].(string); ok && h != "" {
								q.Set("host", h)
							}
						}
					} else if network == "grpc" {
						gs, _ := streamSettings["grpcSettings"].(map[string]interface{})
						if sn, ok := gs["serviceName"].(string); ok && sn != "" {
							q.Set("serviceName", sn)
						}
					} else if network == "xhttp" || network == "splithttp" {
						xs, _ := streamSettings["xhttpSettings"].(map[string]interface{})
						if p, ok := xs["path"].(string); ok && p != "" {
							q.Set("path", p)
						}
						if h, ok := xs["host"].(string); ok && h != "" {
							q.Set("host", h)
						}
						if m, ok := xs["mode"].(string); ok && m != "" {
							q.Set("mode", m)
						}
					}

					finalTag := nodeName
					if finalTag == "" {
						finalTag = address
					}

					link := fmt.Sprintf("vless://%s@%s:%d?%s#%s", uuid, address, port, q.Encode(), url.QueryEscape(finalTag))
					addLink(link)
				}
			}
		}
	}
}

func buildSingBoxVlessURL(ob SingBoxOutbound) string {
	q := url.Values{}
	q.Set("encryption", "none")

	if ob.Flow != "" {
		q.Set("flow", ob.Flow)
	}

	netType := "tcp"
	if ob.Network != "" {
		netType = ob.Network
	}
	if ob.Transport != nil {
		if t, ok := ob.Transport["type"].(string); ok && t != "" {
			netType = t
		}
		if path, ok := ob.Transport["path"].(string); ok && path != "" {
			q.Set("path", path)
		}
		if host, ok := ob.Transport["host"].(string); ok && host != "" {
			q.Set("host", host)
		}
		if sn, ok := ob.Transport["service_name"].(string); ok && sn != "" {
			q.Set("serviceName", sn)
		}
	}
	q.Set("type", netType)

	if ob.TLS != nil && ob.TLS.Enabled {
		if ob.TLS.Reality != nil && ob.TLS.Reality.Enabled {
			q.Set("security", "reality")
			if ob.TLS.Reality.PublicKey != "" {
				q.Set("pbk", ob.TLS.Reality.PublicKey)
			}
			if ob.TLS.Reality.ShortID != "" {
				q.Set("sid", ob.TLS.Reality.ShortID)
			}
		} else {
			q.Set("security", "tls")
		}

		if ob.TLS.ServerName != "" {
			q.Set("sni", ob.TLS.ServerName)
		}
		if ob.TLS.UTLS != nil && ob.TLS.UTLS.Fingerprint != "" {
			q.Set("fp", ob.TLS.UTLS.Fingerprint)
		}
	} else {
		q.Set("security", "none")
	}

	tag := ob.Tag
	if tag == "" {
		tag = ob.Server
	}

	port := ob.ServerPort
	if port == 0 {
		port = 443
	}

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", ob.UUID, ob.Server, port, q.Encode(), url.QueryEscape(tag))
}

func extractRemark(link string) string {
	parts := strings.SplitN(link, "#", 2)
	if len(parts) == 2 {
		decoded, err := url.QueryUnescape(parts[1])
		if err == nil {
			return decoded
		}
		return parts[1]
	}
	return "No remark"
}

func decodeRemark(link string) string {
	parts := strings.SplitN(link, "#", 2)
	if len(parts) == 2 {
		decoded, err := url.QueryUnescape(parts[1])
		if err == nil {
			return parts[0] + "#" + decoded
		}
	}
	return link
}

func fileExists(path string) bool {
	if len(path) > 4096 || strings.ContainsAny(path, "\n\r\t") {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func waitIfInteractive(isInteractive bool, forcePause bool) {
	if isInteractive || forcePause || runtime.GOOS == "windows" && isInteractive {
		fmt.Print("\nPress Enter to exit...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}
}
