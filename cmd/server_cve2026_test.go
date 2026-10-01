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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/minio/minio-go/v7/pkg/signer"
)

// makeTestBucket creates a random bucket with a properly signed request.
func (s *TestSuiteCommon) makeTestBucket(c *check) string {
	c.Helper()
	bucketName := getRandomBucketName()
	request, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)
	return bucketName
}

// assertObjectMissing verifies, with valid credentials, that the object was not written.
func (s *TestSuiteCommon) assertObjectMissing(c *check, bucketName, objectName string) {
	c.Helper()
	request, err := newTestSignedRequest(http.MethodHead, getHeadObjectURL(s.endPoint, bucketName, objectName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusNotFound)
}

// newForgedUnsignedTrailerPut builds a STREAMING-UNSIGNED-PAYLOAD-TRAILER PUT
// that carries a valid access key but no valid signature.
func (s *TestSuiteCommon) newForgedUnsignedTrailerPut(c *check, target string, body []byte) *http.Request {
	c.Helper()
	req, err := http.NewRequest(http.MethodPut, target, nil)
	c.Assert(err, nil)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.Trailer = http.Header{}
	req.Trailer.Set("x-amz-checksum-crc32", "rK0DXg==")
	req = signer.StreamingUnsignedV4(req, "", int64(len(body)), UTCNow())
	req.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
	req.Header.Set("x-amz-content-sha256", unsignedPayloadTrailer)
	return req
}

// TestUnsignedTrailerQueryCredentialCVE covers CVE-2026-41145
// (GHSA-hv4r-mvr4-25vw): credentials supplied only via the query string
// must not bypass signature verification for unsigned-trailer uploads.
func (s *TestSuiteCommon) TestUnsignedTrailerQueryCredentialCVE(c *check) {
	c.Helper()
	bucketName := s.makeTestBucket(c)
	objectName := "cve-2026-41145.txt"
	now := UTCNow()

	q := url.Values{}
	q.Set("X-Amz-Algorithm", signV4Algorithm)
	q.Set("X-Amz-Credential", fmt.Sprintf("%s/%s/us-east-1/s3/aws4_request", s.accessKey, now.Format(yyyymmdd)))
	q.Set("X-Amz-Date", now.Format(iso8601Format))
	q.Set("X-Amz-Expires", "600")
	q.Set("X-Amz-SignedHeaders", "host")
	q.Set("X-Amz-Signature", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	target := getPutObjectURL(s.endPoint, bucketName, objectName) + "?" + q.Encode()

	req := s.newForgedUnsignedTrailerPut(c, target, []byte("foobar!\n"))
	req.Header.Del("Authorization")

	response, err := s.client.Do(req)
	c.Assert(err, nil)
	if response.StatusCode == http.StatusOK {
		c.Fatalf("CVE-2026-41145: forged query-credential upload accepted")
	}
	s.assertObjectMissing(c, bucketName, objectName)
}

// TestSnowballUnsignedTrailerCVE covers CVE-2026-40344
// (GHSA-9c4q-hq6p-c237): snowball auto-extract must verify the signature
// of unsigned-trailer uploads.
func (s *TestSuiteCommon) TestSnowballUnsignedTrailerCVE(c *check) {
	c.Helper()
	bucketName := s.makeTestBucket(c)
	objectName := "cve-2026-40344.txt"

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("pwned\n")
	c.Assert(tw.WriteHeader(&tar.Header{Name: objectName, Mode: 0o644, Size: int64(len(content))}), nil)
	_, err := tw.Write(content)
	c.Assert(err, nil)
	c.Assert(tw.Close(), nil)

	// Raw tar body: the vulnerable handler never decodes aws-chunked framing
	// for this auth type, so a plain body is what an attacker would send.
	req, err := http.NewRequest(http.MethodPut, getPutObjectURL(s.endPoint, bucketName, "archive.tar"), bytes.NewReader(buf.Bytes()))
	c.Assert(err, nil)
	req.ContentLength = int64(buf.Len())
	req.Header.Set("X-Amz-Date", UTCNow().Format(iso8601Format))
	req.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(buf.Len()))
	req.Header.Set("x-amz-content-sha256", unsignedPayloadTrailer)
	req.Header.Set("X-Amz-Meta-Snowball-Auto-Extract", "true")
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", s.accessKey, UTCNow().Format(yyyymmdd)))

	response, err := s.client.Do(req)
	c.Assert(err, nil)
	if response.StatusCode == http.StatusOK {
		c.Fatalf("CVE-2026-40344: forged snowball upload accepted")
	}
	s.assertObjectMissing(c, bucketName, objectName)
}

// signedUnsignedTrailerPut builds a legitimately signed
// STREAMING-UNSIGNED-PAYLOAD-TRAILER PUT, the way minio-go does.
func (s *TestSuiteCommon) signedUnsignedTrailerPut(c *check, target string, body []byte) *http.Request {
	c.Helper()
	req, err := http.NewRequest(http.MethodPut, target, bytes.NewReader(body))
	c.Assert(err, nil)
	sum := crc32.ChecksumIEEE(body)
	var sumBytes [4]byte
	binary.BigEndian.PutUint32(sumBytes[:], sum)
	trailer := http.Header{}
	trailer.Set("x-amz-checksum-crc32", base64.StdEncoding.EncodeToString(sumBytes[:]))
	req.Header.Set("X-Amz-Content-Sha256", unsignedPayloadTrailer)
	return signer.SignV4Trailer(*req, s.accessKey, s.secretKey, "", "us-east-1", trailer)
}

// TestUnsignedTrailerLegitUploads makes sure the CVE fixes above do not
// break properly signed unsigned-trailer uploads.
func (s *TestSuiteCommon) TestUnsignedTrailerLegitUploads(c *check) {
	c.Helper()
	bucketName := s.makeTestBucket(c)

	req := s.signedUnsignedTrailerPut(c, getPutObjectURL(s.endPoint, bucketName, "legit.txt"), []byte("hello world\n"))
	response, err := s.client.Do(req)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("extracted\n")
	c.Assert(tw.WriteHeader(&tar.Header{Name: "from-tar.txt", Mode: 0o644, Size: int64(len(content))}), nil)
	_, err = tw.Write(content)
	c.Assert(err, nil)
	c.Assert(tw.Close(), nil)

	req = s.signedUnsignedTrailerPut(c, getPutObjectURL(s.endPoint, bucketName, "archive.tar"), buf.Bytes())
	req.Header.Set("X-Amz-Meta-Snowball-Auto-Extract", "true")
	// Header added after signing is fine: it is not part of SignedHeaders.
	response, err = s.client.Do(req)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	head, err := newTestSignedRequest(http.MethodHead, getHeadObjectURL(s.endPoint, bucketName, "from-tar.txt"),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	response, err = s.client.Do(head)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)
}
