package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	queue = make(chan string, 1000)
	wg    sync.WaitGroup
)

type SlackRequestBody struct {
	Channel  string `json:"channel"`
	Text     string `json:"text"`
	ThreadTs string `json:"thread_ts,omitempty"`
}

type SlackResponse struct {
	Ok    bool   `json:"ok"`
	Ts    string `json:"ts"`
	Error string `json:"error,omitempty"`
}

type CloudflareResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func sendReactionMessage(reaction, threadTs string) {
	SLACK_API_URL := "https://slack.com/api/reactions.add"
	slackToken := os.Getenv("SLACK_TOKEN")

	data := map[string]string{
		"name":      reaction,
		"channel":   os.Getenv("CHANNEL_ID"),
		"timestamp": threadTs,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal JSON for reaction: %v", err)
		return
	}

	req, err := http.NewRequest("POST", SLACK_API_URL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create request for reaction: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+slackToken)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func sendSlackMessage(text, threadTs string) string {
	SLACK_API_URL := os.Getenv("SLACK_API_URL")
	data := SlackRequestBody{
		Channel: os.Getenv("CHANNEL_ID"),
		Text:    text,
	}

	if threadTs != "" {
		data.ThreadTs = threadTs
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal JSON: %v", err)
		return ""
	}

	req, err := http.NewRequest("POST", SLACK_API_URL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return ""
	}

	req.Header.Set("Authorization", "Bearer "+os.Getenv("SLACK_TOKEN"))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Request failed with status code %d", resp.StatusCode)
		return ""
	}

	var slackResp SlackResponse
	err = json.NewDecoder(resp.Body).Decode(&slackResp)
	if err != nil {
		log.Printf("Failed to decode response: %v", err)
		return ""
	}

	if slackResp.Ok {
		return slackResp.Ts
	} else {
		log.Printf("Error from Slack API: %s", slackResp.Error)
		return ""
	}
}

func checkConditionLetterChat(log string) bool {
	re := regexp.MustCompile(`[a-zA-Z]/chat/`)
	return re.MatchString(log)
}

func checkConditionLetterChatOP(log string) bool {
	re := regexp.MustCompile(`[a-zA-Z]/chat-op/`)
	return re.MatchString(log)
}

func checkConditionApiGeneralInfo(log string) bool {
	re := regexp.MustCompile(`/api/generalInfo`)
	return re.MatchString(log)
}

func checkConditionContentDotEnv(log string) bool {
	re := regexp.MustCompile(`.env`)
	return re.MatchString(log)
}

func checkConditionContentSleep(log string) bool {
	re := regexp.MustCompile(`sleep\(`)
	return re.MatchString(log)
}

func BanIP(ip string) (bool, string) {
	cfZoneID := os.Getenv("CF_ZONE_ID")
	cfEmail := os.Getenv("CF_EMAIL")
	cfApiKey := os.Getenv("CF_API_KEY")

	if cfZoneID == "" || cfEmail == "" || cfApiKey == "" {
		return false, "Cloudflare API credentials are not set in .env"
	}
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules", cfZoneID)
	headers := map[string]string{
		"X-Auth-Email": cfEmail,
		"X-Auth-Key":   cfApiKey,
		"Content-Type": "application/json",
	}
	data := map[string]interface{}{
		"mode": "block",
		"configuration": map[string]string{
			"target": "ip",
			"value":  ip,
		},
		"notes": fmt.Sprintf("Banned by Fail2Ban morannon"),
	}
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		return false, fmt.Sprintf("Error marshalling JSON payload: %v", err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return false, fmt.Sprintf("Error creating HTTP request: %v", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("Error making HTTP request: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Sprintf("Error reading response body: %v", err)
	}

	var cfResp CloudflareResponse
	err = json.Unmarshal(body, &cfResp)
	if err != nil {
		return false, fmt.Sprintf("Error parsing Cloudflare response: %v", err)
	}

	if cfResp.Success {
		return true, ""
	}

	errorMessage := "Unknown error from Cloudflare"
	if len(cfResp.Errors) > 0 {
		errorMessage = cfResp.Errors[0].Message
	}

	return false, errorMessage
}
func processLogsUnique(filteredLogs []string) string {
	logsByMinute := make(map[string][]string)

	for _, log := range filteredLogs {
		re := regexp.MustCompile(`\[(.*?)\]`)
		matches := re.FindStringSubmatch(log)
		if len(matches) > 1 {
			logTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[1])
			if err == nil {
				minute := logTime.Format("2006-01-02 15:04")
				logsByMinute[minute] = append(logsByMinute[minute], log)
			}
		}
	}

	var resultBuilder strings.Builder
	for minute, logs := range logsByMinute {
		uniqueRoutes := make(map[string]struct{})
		for _, log := range logs {
			re := regexp.MustCompile(`"(GET|POST|PUT|DELETE|HEAD|OPTIONS) (/[^ ]*)`)
			if matches := re.FindStringSubmatch(log); len(matches) > 2 {
				route := matches[2]
				uniqueRoutes[route] = struct{}{}
			}
		}

		resultBuilder.WriteString(fmt.Sprintf("Logs for %s:\n", minute))
		resultBuilder.WriteString(fmt.Sprintf("  Total requests: %d\n", len(logs)))
		resultBuilder.WriteString("  Unique routes:\n")
		for route := range uniqueRoutes {
			resultBuilder.WriteString(fmt.Sprintf("    %s\n", route))
		}
	}
	return resultBuilder.String()
}

func processLogs(ipAddress string, filePath string, maxRequests int, parentTs string) {
	fmt.Printf("%s|%s", ipAddress, parentTs)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	additionalMaxRequestsWpContentStr := os.Getenv("ADDITIONAL_MAX_REQUESTS_WPCONTENT")
	additionalMaxRequestsWpContent, err := strconv.Atoi(additionalMaxRequestsWpContentStr)

	additionalMaxRequestsWpIncludesStr := os.Getenv("ADDITIONAL_MAX_REQUESTS_WP_INCLUDES")
	additionalMaxRequestsWpIncludes, _ := strconv.Atoi(additionalMaxRequestsWpIncludesStr)

	currentTime := time.Now().UTC()
	oneHourAgo := currentTime.Add(-1 * time.Hour)

	ipRegex := regexp.MustCompile(fmt.Sprintf(`^%s -`, ipAddress))

	wpContentRegex := regexp.MustCompile(`/wp-content/`)
	wpIncludesRegex := regexp.MustCompile(`/wp-includes/`)
	lines := strings.Split(string(content), "\n")

	var filteredLogs []string
	requestsBySecond := make(map[int]int)
	wpContentSeconds := make(map[int]bool)
	wpIncludesSeconds := make(map[int]bool)
	dotEnvAlerted := false
	sleepAlerted := false
	manyRequestsAlerted := false
	for _, line := range lines {
		if ipRegex.MatchString(line) {
			re := regexp.MustCompile(`\[(.*?)\]`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				logTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[1])
				if err == nil && logTime.After(oneHourAgo) && logTime.Before(currentTime) {
					if !checkConditionLetterChat(line) && !checkConditionLetterChatOP(line) && !checkConditionApiGeneralInfo(line) {
						filteredLogs = append(filteredLogs, line)
						epochSecond := int(logTime.Unix())
						requestsBySecond[epochSecond]++

						if wpContentRegex.MatchString(line) {
							wpContentSeconds[epochSecond] = true
						} else if wpIncludesRegex.MatchString(line) {
							wpIncludesSeconds[epochSecond] = true
						}
						currentMaxRequests := maxRequests
						if wpContentSeconds[epochSecond] {
							currentMaxRequests = additionalMaxRequestsWpContent + maxRequests
						} else if wpIncludesSeconds[epochSecond] {
							currentMaxRequests = additionalMaxRequestsWpIncludes + maxRequests
						}
						if requestsBySecond[epochSecond] >= currentMaxRequests && !manyRequestsAlerted {
							manyRequestAlert := fmt.Sprintf("‼️ ‼️ ALERT for IP %s: Requests exceeded threshold. Count: %d", ipAddress, requestsBySecond[epochSecond])
							manyRequestsAlerted = true
							sendSlackMessage(manyRequestAlert, parentTs)
						}
						if checkConditionContentDotEnv(line) && !dotEnvAlerted {
							contentEnvAlert := fmt.Sprintf("‼️ ‼️ Content .env. Can be banned")
							dotEnvAlerted = true
							sendSlackMessage(contentEnvAlert, parentTs)
						}

						if checkConditionContentSleep(line) && !sleepAlerted {
							contentSleepAlert := fmt.Sprintf("‼️ ‼️ Content sleep(). Can be banned")
							sleepAlerted = true
							sendSlackMessage(contentSleepAlert, parentTs)
						}
					}
				}
			}
		}
	}
	reaction := os.Getenv("SLACK_EMOJI_BAN")
	if dotEnvAlerted || sleepAlerted || manyRequestsAlerted {
		success, errMsg := BanIP(ipAddress)
		banlogMessage := ""
		if success {
			banlogMessage = fmt.Sprintf("IP %s has been successfully blocked in Cloudflare..\n", ipAddress)
			sendSlackMessage(banlogMessage, parentTs)
		} else {
			reaction = os.Getenv("SLACK_EMOJI_FAIL_BAN")
			banlogMessage = fmt.Sprintf("Failed to block the IP %s: %s\n", ipAddress, errMsg)
		}
		sendSlackMessage(banlogMessage, parentTs)

		sendReactionMessage(reaction, parentTs)
	} else {
		reaction = os.Getenv("SLACK_EMOJI_NOT_BAN")
		sendReactionMessage(reaction, parentTs)
	}
	if len(filteredLogs) > 0 {
		logMessage := processLogsUnique(filteredLogs)
		sendSlackMessage(logMessage, parentTs)
	} else {
		logMessage := fmt.Sprintf("Нічого не знайдено")
		sendSlackMessage(logMessage, parentTs)
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	slackToken := os.Getenv("SLACK_TOKEN")
	channelID := os.Getenv("CHANNEL_ID")
	filePath := os.Getenv("FILE_PATH")
	nameSite := os.Getenv("SITE_NAME")
	maxRequestsSecond := os.Getenv("MAX_REQUESTS_SECOND")
	if slackToken == "" || channelID == "" || filePath == "" || maxRequestsSecond == "" {
		log.Fatal("Required environment variables are not set")
	}

	go worker()

	ipAddress := os.Args[2]
	mainMessageTs := sendSlackMessage(fmt.Sprintf("Site %s. Suspicious IP detected: %s", nameSite, ipAddress), "")
	wg.Add(1)
	queue <- fmt.Sprintf("%s|%s", ipAddress, mainMessageTs)

	wg.Wait()

}
func worker() {
	filePath := os.Getenv("FILE_PATH")
	maxRequestsSecond := os.Getenv("MAX_REQUESTS_SECOND")
	maxRequests, _ := strconv.Atoi(maxRequestsSecond)

	for item := range queue {
		data := parseQueueItem(item)
		ipAddress, mainMessageTs := data[0], data[1]

		go func(ip, ts string) {
			defer wg.Done()
			processLogs(ip, filePath, maxRequests, ts)
		}(ipAddress, mainMessageTs)
	}
}
func parseQueueItem(item string) []string {
	return strings.Split(item, "|")
}
