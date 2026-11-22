package lib

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type S3Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type S3Client struct {
	endpoint        string
	region          string
	bucket          string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	httpClient      *http.Client
}

type listBucketResult struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

func IsS3URI(uri string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(uri)), "s3://")
}

func ParseS3URI(uri string) (string, string, error) {
	trimmed := strings.TrimSpace(uri)
	if !IsS3URI(trimmed) {
		return "", "", fmt.Errorf("invalid s3 uri: %s", uri)
	}
	rest := trimmed[5:]
	if strings.HasPrefix(rest, "/") {
		return "", strings.TrimPrefix(rest, "/"), nil
	}
	idx := strings.IndexByte(rest, '/')
	if idx < 0 {
		return rest, "", nil
	}
	return rest[:idx], rest[idx+1:], nil
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func ResolveS3Config(cfg S3Config) S3Config {
	if cfg.AccessKeyID == "" {
		cfg.AccessKeyID = firstNonEmptyEnv("S3_ACCESS_KEY_ID", "R2_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID")
	}
	if cfg.SecretAccessKey == "" {
		cfg.SecretAccessKey = firstNonEmptyEnv("S3_SECRET_ACCESS_KEY", "R2_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY")
	}
	if cfg.SessionToken == "" {
		cfg.SessionToken = firstNonEmptyEnv("S3_SESSION_TOKEN", "AWS_SESSION_TOKEN")
	}
	if cfg.Bucket == "" {
		cfg.Bucket = firstNonEmptyEnv("S3_BUCKET", "R2_BUCKET_NAME")
	}
	if cfg.Region == "" {
		cfg.Region = firstNonEmptyEnv("S3_REGION", "AWS_REGION", "AWS_DEFAULT_REGION")
		if cfg.Region == "" {
			cfg.Region = "auto"
		}
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = firstNonEmptyEnv("S3_ENDPOINT", "AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL")
		if cfg.Endpoint == "" {
			if accountID := firstNonEmptyEnv("R2_ACCOUNT_ID"); accountID != "" {
				cfg.Endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)
			}
		}
	}
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	return cfg
}

func NewS3Client(cfg S3Config) (*S3Client, error) {
	resolved := ResolveS3Config(cfg)
	if resolved.Endpoint == "" {
		return nil, fmt.Errorf("missing S3 endpoint (set S3_ENDPOINT or R2_ACCOUNT_ID)")
	}
	if resolved.AccessKeyID == "" || resolved.SecretAccessKey == "" {
		return nil, fmt.Errorf("missing S3 credentials (set R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY or S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY)")
	}
	return &S3Client{
		endpoint:        resolved.Endpoint,
		region:          resolved.Region,
		bucket:          resolved.Bucket,
		accessKeyID:     resolved.AccessKeyID,
		secretAccessKey: resolved.SecretAccessKey,
		sessionToken:    resolved.SessionToken,
		httpClient:      httpClient,
	}, nil
}

func (c *S3Client) DefaultBucket() string {
	return c.bucket
}

func (c *S3Client) GetObject(ctx context.Context, bucket, key string) ([]byte, error) {
	if bucket == "" {
		bucket = c.bucket
	}
	if bucket == "" {
		return nil, fmt.Errorf("missing S3 bucket (set R2_BUCKET_NAME or S3_BUCKET)")
	}
	key = strings.TrimLeft(key, "/")
	if key == "" {
		return nil, fmt.Errorf("missing S3 object key")
	}

	reqPath := "/" + awsURIEncodePath(bucket+"/"+key)
	return c.doSignedGet(ctx, reqPath, nil)
}

func (c *S3Client) ListObjects(ctx context.Context, bucket, prefix string) ([]string, error) {
	if bucket == "" {
		bucket = c.bucket
	}
	if bucket == "" {
		return nil, fmt.Errorf("missing S3 bucket (set R2_BUCKET_NAME or S3_BUCKET)")
	}

	reqPath := "/" + awsURIEncodePath(bucket)
	var keys []string
	continuationToken := ""

	for {
		params := url.Values{}
		params.Set("list-type", "2")
		if prefix != "" {
			params.Set("prefix", prefix)
		}
		if continuationToken != "" {
			params.Set("continuation-token", continuationToken)
		}

		body, err := c.doSignedGet(ctx, reqPath, params)
		if err != nil {
			return nil, err
		}

		var result listBucketResult
		if err := xml.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse S3 list response: %w", err)
		}

		for _, obj := range result.Contents {
			if obj.Key != "" && !strings.HasSuffix(obj.Key, "/") {
				keys = append(keys, obj.Key)
			}
		}

		if !result.IsTruncated || result.NextContinuationToken == "" {
			break
		}
		continuationToken = result.NextContinuationToken
	}

	return keys, nil
}

func (c *S3Client) doSignedGet(ctx context.Context, canonicalPath string, query url.Values) ([]byte, error) {
	parsedEndpoint, err := url.Parse(c.endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid S3 endpoint %s: %w", c.endpoint, err)
	}

	canonicalQuery := buildCanonicalQuery(query)
	fullURL := c.endpoint + canonicalPath
	if canonicalQuery != "" {
		fullURL += "?" + canonicalQuery
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, err
		}
		req.Host = parsedEndpoint.Host
		c.signRequest(req, parsedEndpoint.Host, canonicalPath, canonicalQuery, time.Now().UTC())

		resp, err := c.httpClient.Do(req)
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
			lastErr = fmt.Errorf("S3 GET %s failed: %s (%s)", canonicalPath, resp.Status, strings.TrimSpace(string(data)))
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
				return nil, lastErr
			}
			continue
		}
		return data, nil
	}

	return nil, lastErr
}

func (c *S3Client) signRequest(req *http.Request, host, canonicalURI, canonicalQuery string, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", emptyPayloadHash)

	headers := map[string]string{
		"host":                 host,
		"x-amz-content-sha256": emptyPayloadHash,
		"x-amz-date":           amzDate,
	}
	if c.sessionToken != "" {
		req.Header.Set("x-amz-security-token", c.sessionToken)
		headers["x-amz-security-token"] = c.sessionToken
	}

	headerKeys := make([]string, 0, len(headers))
	for k := range headers {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)

	var canonicalHeaders strings.Builder
	for _, k := range headerKeys {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(headers[k]))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(headerKeys, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeaders,
		emptyPayloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+c.secretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(c.region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authHeader)
}

func ReadS3Object(uri string, cfg S3Config) ([]byte, error) {
	bucket, key, err := ParseS3URI(uri)
	if err != nil {
		return nil, err
	}
	if bucket != "" {
		cfg.Bucket = bucket
	}
	client, err := NewS3Client(cfg)
	if err != nil {
		return nil, err
	}
	return client.GetObject(context.Background(), cfg.Bucket, key)
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func awsURIEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'A' && ch <= 'Z') ||
			(ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

func awsURIEncodePath(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		segments[i] = awsURIEncode(seg)
	}
	return strings.Join(segments, "/")
}

func buildCanonicalQuery(query url.Values) string {
	if len(query) == 0 {
		return ""
	}
	type kv struct {
		k string
		v string
	}
	var pairs []kv
	for k, vals := range query {
		ek := awsURIEncode(k)
		for _, v := range vals {
			pairs = append(pairs, kv{k: ek, v: awsURIEncode(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}
	return b.String()
}
