package lib

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseS3URI(t *testing.T) {
	cases := []struct {
		uri        string
		wantBucket string
		wantKey    string
		wantErr    bool
	}{
		{"s3:///cn-only", "", "cn-only", false},
		{"s3:///", "", "", false},
		{"s3://my-bucket/path/to/file", "my-bucket", "path/to/file", false},
		{"s3://my-bucket", "my-bucket", "", false},
		{"https://example.com/a", "", "", true},
	}

	for _, tc := range cases {
		bucket, key, err := ParseS3URI(tc.uri)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseS3URI(%q) expected error", tc.uri)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseS3URI(%q) unexpected error: %v", tc.uri, err)
		}
		if bucket != tc.wantBucket || key != tc.wantKey {
			t.Fatalf("ParseS3URI(%q) = (%q, %q), want (%q, %q)", tc.uri, bucket, key, tc.wantBucket, tc.wantKey)
		}
	}
}

func TestS3ClientListAndGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=test-ak/") {
			http.Error(w, "bad auth", http.StatusForbidden)
			return
		}
		if r.Header.Get("x-amz-date") == "" || r.Header.Get("x-amz-content-sha256") != emptyPayloadHash {
			http.Error(w, "missing amz headers", http.StatusForbidden)
			return
		}

		if r.URL.Path == "/mybucket" && r.URL.Query().Get("list-type") == "2" {
			token := r.URL.Query().Get("continuation-token")
			if token == "" {
				fmt.Fprint(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>page2</NextContinuationToken><Contents><Key>cn-only</Key></Contents></ListBucketResult>`)
				return
			}
			if token == "page2" {
				fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>pcdn-cn</Key></Contents></ListBucketResult>`)
				return
			}
		}

		if r.URL.Path == "/mybucket/cn-only" {
			fmt.Fprint(w, "example.cn\n")
			return
		}
		if r.URL.Path == "/mybucket/pcdn-cn" {
			fmt.Fprint(w, "pcdn.example.cn\n")
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, err := NewS3Client(S3Config{
		Endpoint:        srv.URL,
		Region:          "auto",
		Bucket:          "mybucket",
		AccessKeyID:     "test-ak",
		SecretAccessKey: "test-sk",
	})
	if err != nil {
		t.Fatalf("NewS3Client error: %v", err)
	}

	keys, err := client.ListObjects(context.Background(), "", "")
	if err != nil {
		t.Fatalf("ListObjects error: %v", err)
	}
	if len(keys) != 2 || keys[0] != "cn-only" || keys[1] != "pcdn-cn" {
		t.Fatalf("unexpected keys: %v", keys)
	}

	data, err := client.GetObject(context.Background(), "", "cn-only")
	if err != nil {
		t.Fatalf("GetObject error: %v", err)
	}
	if string(data) != "example.cn\n" {
		t.Fatalf("unexpected body: %q", string(data))
	}
}
