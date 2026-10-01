// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/madmin-go/v3"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/pkg/v3/policy"
)

// forgedReplicationSSEHeaders returns X-Minio-Replication-* SSE headers that
// describe a sealed SSE-C key the server never issued.
func forgedReplicationSSEHeaders() map[string]string {
	return map[string]string{
		"X-Minio-Replication-Server-Side-Encryption-Sealed-Key":     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 64)),
		"X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm": "DARE-SHA256",
		"X-Minio-Replication-Server-Side-Encryption-Iv":             base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)),
	}
}

// cve34204MakeBucket creates a random bucket with a properly signed request.
func (s *TestSuiteCommon) cve34204MakeBucket(c *check) string {
	c.Helper()
	bucketName := getRandomBucketName()
	req, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	status, _ := s.cve34204Do(c, req)
	c.Assert(status, http.StatusOK)
	return bucketName
}

// cve34204Request builds a properly signed request carrying extra headers.
func (s *TestSuiteCommon) cve34204Request(c *check, method, target string, body []byte, hdrs map[string]string, accessKey, secretKey string) *http.Request {
	c.Helper()
	req, err := newTestRequest(method, target, int64(len(body)), bytes.NewReader(body))
	c.Assert(err, nil)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	if s.signer == signerV4 {
		c.Assert(signRequestV4(req, accessKey, secretKey), nil)
	} else {
		c.Assert(signRequestV2(req, accessKey, secretKey), nil)
	}
	return req
}

// cve34204Do sends a request and returns status code and body.
func (s *TestSuiteCommon) cve34204Do(c *check, req *http.Request) (int, []byte) {
	c.Helper()
	resp, err := s.client.Do(req)
	c.Assert(err, nil)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	c.Assert(err, nil)
	return resp.StatusCode, b
}

// assertReadableOrAbsent: if the write was accepted, the object must still be
// readable with plain credentials and must not carry internal SSE metadata.
func (s *TestSuiteCommon) assertReadableOrAbsent(c *check, op, bucket, object string, accepted bool, want []byte) {
	c.Helper()
	if !accepted {
		return
	}
	req := s.cve34204Request(c, http.MethodGet, getGetObjectURL(s.endPoint, bucket, object), nil,
		map[string]string{"Accept-Encoding": "identity"}, s.accessKey, s.secretKey) // no transparent gunzip
	status, body := s.cve34204Do(c, req)
	if status != http.StatusOK {
		c.Errorf("CVE-2026-34204 (%s): object made unreadable by forged replication SSE headers: GET returned %d: %s", op, status, body)
		return
	}
	if !bytes.Equal(body, want) {
		c.Errorf("CVE-2026-34204 (%s): unexpected content %q", op, body)
		return
	}
	oi, err := newObjectLayerFn().GetObjectInfo(context.Background(), bucket, object, ObjectOptions{})
	c.Assert(err, nil)
	for k := range oi.UserDefined {
		if strings.HasPrefix(k, "X-Minio-Internal-Server-Side-Encryption") {
			c.Errorf("CVE-2026-34204 (%s): internal SSE metadata %q injected", op, k)
		}
	}
}

// TestReplicationSSEHeaderInjectionCVE covers CVE-2026-34204
// (GHSA-3rh2-v3gr-35p9): X-Minio-Replication-* SSE headers on requests that are
// not genuine replication requests must not become internal SSE metadata.
func (s *TestSuiteCommon) TestReplicationSSEHeaderInjectionCVE(c *check) {
	c.Helper()
	bucket := s.cve34204MakeBucket(c)
	data := []byte("cve-2026-34204 payload\n")

	// 1. PutObject with forged headers, no source-replication marker.
	req := s.cve34204Request(c, http.MethodPut, getPutObjectURL(s.endPoint, bucket, "put"), data, forgedReplicationSSEHeaders(), s.accessKey, s.secretKey)
	status, _ := s.cve34204Do(c, req)
	s.assertReadableOrAbsent(c, "PutObject", bucket, "put", status == http.StatusOK, data)

	// 2. CopyObject with REPLACE directive and forged headers, from a clean source.
	req = s.cve34204Request(c, http.MethodPut, getPutObjectURL(s.endPoint, bucket, "src"), data, nil, s.accessKey, s.secretKey)
	status, _ = s.cve34204Do(c, req)
	c.Assert(status, http.StatusOK)
	hdrs := forgedReplicationSSEHeaders()
	hdrs[xhttp.AmzCopySource] = url.QueryEscape(SlashSeparator + bucket + SlashSeparator + "src")
	hdrs[xhttp.AmzMetadataDirective] = replaceDirective
	req = s.cve34204Request(c, http.MethodPut, getPutObjectURL(s.endPoint, bucket, "copy"), nil, hdrs, s.accessKey, s.secretKey)
	status, _ = s.cve34204Do(c, req)
	s.assertReadableOrAbsent(c, "CopyObject", bucket, "copy", status == http.StatusOK, data)

	// 3. Multipart upload with forged headers on NewMultipartUpload.
	accepted := s.cve34204Multipart(c, bucket, "multipart", data, forgedReplicationSSEHeaders(), s.accessKey, s.secretKey)
	s.assertReadableOrAbsent(c, "Multipart", bucket, "multipart", accepted, data)

	// 4. Snowball auto-extract with forged headers in PAX records.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	pax := map[string]string{}
	for k, v := range forgedReplicationSSEHeaders() {
		pax["minio.metadata."+k] = v
	}
	c.Assert(tw.WriteHeader(&tar.Header{Name: "snowball", Mode: 0o644, Size: int64(len(data)), PAXRecords: pax, Format: tar.FormatPAX}), nil)
	_, err := tw.Write(data)
	c.Assert(err, nil)
	c.Assert(tw.Close(), nil)
	req = s.cve34204Request(c, http.MethodPut, getPutObjectURL(s.endPoint, bucket, "archive.tar"), buf.Bytes(),
		map[string]string{"X-Amz-Meta-Snowball-Auto-Extract": "true"}, s.accessKey, s.secretKey)
	status, _ = s.cve34204Do(c, req)
	s.assertReadableOrAbsent(c, "Snowball", bucket, "snowball", status == http.StatusOK, data)

	// 5. PostPolicy upload with forged form fields (allowed by the uploader's own policy).
	if s.signer == signerV4 {
		t := UTCNow()
		region := "us-east-1"
		credStr := getCredentialString(s.accessKey, region, t)
		conds := []string{
			fmt.Sprintf(`["eq", "$bucket", "%s"]`, bucket),
			`["eq", "$key", "post/upload.txt"]`,
			`["eq", "$x-amz-algorithm", "AWS4-HMAC-SHA256"]`,
			fmt.Sprintf(`["eq", "$x-amz-date", "%s"]`, t.Format(iso8601DateFormat)),
			fmt.Sprintf(`["eq", "$x-amz-credential", "%s"]`, credStr),
			`["eq", "$x-amz-meta-uuid", "1234"]`,
			`["eq", "$content-encoding", "gzip"]`,
		}
		form := forgedReplicationSSEHeaders()
		for k, v := range form {
			conds = append(conds, fmt.Sprintf(`["eq", "$%s", "%s"]`, k, v))
		}
		pol := fmt.Sprintf(`{"expiration": "%s","conditions":[%s]}`, t.Add(5*time.Minute).Format(iso8601TimeFormat), strings.Join(conds, ","))
		req, err = newPostRequestV4Generic(s.endPoint, bucket, "post", data, s.accessKey, s.secretKey, region, t, []byte(pol), form, true, false, false)
		c.Assert(err, nil)
		status, body := s.cve34204Do(c, req)
		if status != http.StatusNoContent && status != http.StatusOK && status != http.StatusForbidden && status != http.StatusBadRequest {
			c.Fatalf("CVE-2026-34204 (PostPolicy): unexpected status %d: %s", status, body)
		}
		s.assertReadableOrAbsent(c, "PostPolicy", bucket, "post/upload.txt", status == http.StatusNoContent || status == http.StatusOK, data)
	}

	// 6. Source-replication marker from a caller lacking s3:ReplicateObject.
	userAK, userSK := "cve34204user", "cve34204secretkey"
	ctx := context.Background()
	_, err = globalIAMSys.CreateUser(ctx, userAK, madmin.AddOrUpdateUserReq{SecretKey: userSK, Status: madmin.AccountEnabled})
	c.Assert(err, nil)
	p, err := policy.ParseConfig(strings.NewReader(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":["arn:aws:s3:::*"]}]}`))
	c.Assert(err, nil)
	_, err = globalIAMSys.SetPolicy(ctx, "cve34204putonly", *p)
	c.Assert(err, nil)
	_, err = globalIAMSys.PolicyDBSet(ctx, userAK, "cve34204putonly", regUser, false)
	c.Assert(err, nil)

	hdrs = forgedReplicationSSEHeaders()
	hdrs[xhttp.MinIOSourceReplicationRequest] = "true"
	req = s.cve34204Request(c, http.MethodPut, getPutObjectURL(s.endPoint, bucket, "put-marker"), data, hdrs, userAK, userSK)
	status, body := s.cve34204Do(c, req)
	if status != http.StatusOK {
		c.Fatalf("PutObject by s3:PutObject-only user failed: %d %s", status, body)
	}
	s.assertReadableOrAbsent(c, "PutObject+marker,no-replicate-perm", bucket, "put-marker", true, data)

	hdrs = forgedReplicationSSEHeaders()
	hdrs[xhttp.MinIOSourceReplicationRequest] = "true"
	hdrs[xhttp.AmzBucketReplicationStatus] = "REPLICA"
	accepted = s.cve34204Multipart(c, bucket, "multipart-marker", data, hdrs, userAK, userSK)
	s.assertReadableOrAbsent(c, "Multipart+marker,no-replicate-perm", bucket, "multipart-marker", accepted, data)
}

// TestReplicationSSEHeaderLegitimateCVE is the regression check for
// CVE-2026-34204: a genuine replication request (marker present, caller holds
// s3:ReplicateObject) must still have its SSE metadata recorded, as SSE-C
// replication depends on it.
func (s *TestSuiteCommon) TestReplicationSSEHeaderLegitimateCVE(c *check) {
	c.Helper()
	bucket := s.cve34204MakeBucket(c)
	data := []byte("replicated ciphertext stand-in")
	forged := forgedReplicationSSEHeaders()

	check := func(op, object string) {
		c.Helper()
		oi, err := newObjectLayerFn().GetObjectInfo(context.Background(), bucket, object, ObjectOptions{})
		c.Assert(err, nil)
		for k, v := range forged {
			internal := replicationToInternalHeaders[k]
			if oi.UserDefined[internal] != v {
				c.Fatalf("%s: legitimate replication lost %s (got %q)", op, internal, oi.UserDefined[internal])
			}
		}
	}

	hdrs := forgedReplicationSSEHeaders()
	hdrs[xhttp.MinIOSourceReplicationRequest] = "true"
	hdrs[xhttp.AmzBucketReplicationStatus] = "REPLICA"
	req := s.cve34204Request(c, http.MethodPut, getPutObjectURL(s.endPoint, bucket, "replica"), data, hdrs, s.accessKey, s.secretKey)
	status, body := s.cve34204Do(c, req)
	if status != http.StatusOK {
		c.Fatalf("replication PutObject failed: %d %s", status, body)
	}
	check("PutObject", "replica")

	hdrs = forgedReplicationSSEHeaders()
	hdrs[xhttp.MinIOSourceReplicationRequest] = "true"
	hdrs[xhttp.AmzBucketReplicationStatus] = "REPLICA"
	req = s.cve34204Request(c, http.MethodPost, getNewMultipartURL(s.endPoint, bucket, "replica-mp"), nil, hdrs, s.accessKey, s.secretKey)
	status, body = s.cve34204Do(c, req)
	if status != http.StatusOK {
		c.Fatalf("replication NewMultipartUpload failed: %d %s", status, body)
	}
	resp := &InitiateMultipartUploadResponse{}
	c.Assert(xml.Unmarshal(body, resp), nil)
	mi, err := newObjectLayerFn().GetMultipartInfo(context.Background(), bucket, "replica-mp", resp.UploadID, ObjectOptions{})
	c.Assert(err, nil)
	for k, v := range forged {
		internal := replicationToInternalHeaders[k]
		if mi.UserDefined[internal] != v {
			c.Fatalf("NewMultipartUpload: legitimate replication lost %s (got %q)", internal, mi.UserDefined[internal])
		}
	}
}

// cve34204Multipart runs a single-part multipart upload with extra headers on
// NewMultipartUpload. It returns whether the upload completed.
func (s *TestSuiteCommon) cve34204Multipart(c *check, bucket, object string, data []byte, hdrs map[string]string, ak, sk string) bool {
	c.Helper()
	req := s.cve34204Request(c, http.MethodPost, getNewMultipartURL(s.endPoint, bucket, object), nil, hdrs, ak, sk)
	status, body := s.cve34204Do(c, req)
	if status != http.StatusOK {
		return false
	}
	resp := &InitiateMultipartUploadResponse{}
	c.Assert(xml.Unmarshal(body, resp), nil)

	// Follow-up requests carry the replication marker if the initiation did.
	var follow map[string]string
	if v, ok := hdrs[xhttp.MinIOSourceReplicationRequest]; ok {
		follow = map[string]string{xhttp.MinIOSourceReplicationRequest: v}
	}
	req = s.cve34204Request(c, http.MethodPut, getPartUploadURL(s.endPoint, bucket, object, resp.UploadID, "1"), data, follow, ak, sk)
	r, err := s.client.Do(req)
	c.Assert(err, nil)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return false
	}
	complete, err := xml.Marshal(&CompleteMultipartUpload{Parts: []CompletePart{{PartNumber: 1, ETag: r.Header.Get(xhttp.ETag)}}})
	c.Assert(err, nil)
	req = s.cve34204Request(c, http.MethodPost, getCompleteMultipartUploadURL(s.endPoint, bucket, object, resp.UploadID), complete, follow, ak, sk)
	status, _ = s.cve34204Do(c, req)
	return status == http.StatusOK
}
