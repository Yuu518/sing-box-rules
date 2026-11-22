package lib

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	httpClient = &http.Client{
		Timeout: 60 * time.Second,
	}

	validDomainRegex      = regexp.MustCompile(`^[a-zA-Z0-9][-_a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-_a-zA-Z0-9]{0,62})*$`)
	validMultiLabelDomain = regexp.MustCompile(`^[a-zA-Z0-9][-_a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-_a-zA-Z0-9]{0,62})+$`)
)

func IsRemoteURL(uri string) bool {
	lower := strings.ToLower(strings.TrimSpace(uri))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func GetRemoteURLContent(url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		resp, err := httpClient.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("failed to get remote content -> %s: %s", url, resp.Status)
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

func ReadURIContent(uri string) ([]byte, error) {
	uri = strings.TrimSpace(uri)
	if IsS3URI(uri) {
		return ReadS3Object(uri, S3Config{})
	}
	if IsRemoteURL(uri) {
		return GetRemoteURLContent(uri)
	}
	return os.ReadFile(uri)
}

func GetIgnoreIPType(onlyIPType IPType) IgnoreIPOption {
	switch onlyIPType {
	case IPv4:
		return IgnoreIPv6
	case IPv6:
		return IgnoreIPv4
	}
	return nil
}

func IsValidDomainOrTLD(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	return validDomainRegex.MatchString(s)
}

func IsValidMultiLabelDomain(s string) bool {
	if len(s) < 3 || len(s) > 255 {
		return false
	}
	return validMultiLabelDomain.MatchString(s)
}

func FilterAndSortEntryNames(container Container, want []string, exclude []string) []string {
	excludeMap := make(map[string]bool)
	for _, ex := range exclude {
		if ex = strings.ToUpper(strings.TrimSpace(ex)); ex != "" {
			excludeMap[ex] = true
		}
	}

	hasWantedList := false
	wantList := make([]string, 0, len(want))
	seen := make(map[string]bool)
	for _, w := range want {
		if w = strings.ToUpper(strings.TrimSpace(w)); w != "" {
			hasWantedList = true
			if !excludeMap[w] && !seen[w] {
				seen[w] = true
				wantList = append(wantList, w)
			}
		}
	}

	if hasWantedList {
		if len(wantList) == 0 {
			return []string{}
		}
		slices.Sort(wantList)
		return wantList
	}

	list := make([]string, 0, container.Len())
	for entry := range container.Loop() {
		name := entry.GetName()
		if excludeMap[name] {
			continue
		}
		list = append(list, name)
	}

	slices.Sort(list)
	return list
}
