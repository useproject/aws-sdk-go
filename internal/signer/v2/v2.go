package v2

import (
	"crypto/hmac"
	"crypto/sha1"
	//"encoding/hex"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/internal/protocol/rest"
)

const (
	authHeaderPrefix = "AWS"
	//timeFormat       = "20060102T150406Z"
	//timeFormat      = time.RFC1123
	timeFormat      = http.TimeFormat
	shortTimeFormat = "20060102"
)

var ignoredHeaders = map[string]bool{
	"Authorizaion":   true,
	"Content-Type":   true,
	"Content-Length": true,
	//"X-Amz-Date":     true,
	"User-Agent": true,
}

var qsaOfInterest = map[string]bool{
	"acl": true,
	"uploads": true,
	"location": true,
	"cors": true,
	"logging": true,
	"website": true,
	"lifecycle": true,
	"delete": true,
	"uploadId": true,
	"partNumber": true,
	"response-content-type": true,
	"response-content-language": true,
	"response-expires": true,
	"response-cache-control": true,
	"response-content-disposition": true,
	"response-content-encoding": true,
	"domain": true,
	"notification": true,
	"policy": true,
	"requestPayment": true,
	"torrent": true,
	"versionId": true,
	"versioning": true,
	"versions": true,
}

type signer struct {
	Request     *http.Request
	Time        time.Time
	ExpireTime  time.Duration
	ServiceName string
	Region      string
	CredValues  credentials.Value
	Credentials *credentials.Credentials
	Query       url.Values
	Body        io.ReadSeeker
	Debug       aws.LogLevelType
	Logger      aws.Logger

	isPresign          bool
	formattedTime      string
	formattedShortTime string
	expireSeconds      string

	method            string
	contentMD5        string
	contentType       string
	signedHeaders     string
	canonicalHeaders  string
	canonicalResource string
	credentialString  string
	stringToSign      string
	signature         string
	authorization     string
}

func Sign(req *request.Request) {
	if req.Service.Config.Credentials == credentials.AnonymousCredentials {
		return
	}

	region := req.Service.SigningRegion
	if region == "" {
		region = aws.StringValue(req.Service.Config.Region)
	}

	name := req.Service.SigningName
	if name == "" {
		name = req.Service.ServiceName
	}

	s := signer{
		Request:     req.HTTPRequest,
		Time:        req.Time,
		ExpireTime:  req.ExpireTime,
		Query:       req.HTTPRequest.URL.Query(),
		Body:        req.Body,
		ServiceName: name,
		Region:      region,
		Credentials: req.Service.Config.Credentials,
		Debug:       req.Service.Config.LogLevel.Value(),
		Logger:      req.Service.Config.Logger,
	}

	req.Error = s.sign()
}

func (v2 *signer) sign() error {
	if v2.ExpireTime != 0 {
		v2.isPresign = true
	}

	if v2.isRequestSigned() {
		if !v2.Credentials.IsExpired() {
			// If the request is already signed, and the credentials have not
			// expired yet ignore the signing request.
			return nil
		}

		// The credentials have expired for this request. The current signing
		// is invalid, and needs to be request because the request will fail.
		if v2.isPresign {
			v2.removePresign()
			// Update the request's query string to ensure the values stays in
			// sync in the case retrieving the new credentials fails.
			v2.Request.URL.RawQuery = v2.Query.Encode()
		}
	}

	var err error
	v2.CredValues, err = v2.Credentials.Get()
	if err != nil {
		return err
	}

	if v2.isPresign {
		if v2.CredValues.SessionToken != "" {
			v2.Query.Set("X-Amz-Security-Token", v2.CredValues.SessionToken)
		} else {
			v2.Query.Del("X-Amz-Security-Token")
		}
	} else if v2.CredValues.SessionToken != "" {
		v2.Request.Header.Set("X-Amz-Security-Token", v2.CredValues.SessionToken)
	}

	v2.build()

	if v2.Debug.Matches(aws.LogDebugWithSigning) {
		v2.logSigningInfo()
	}

	return nil
}

const logSignInfoMsg = `DEBUG: Request Signiture:
---[ METHOD ]----------------------------------------
%s
---[ CONTENT-MD5 ]-----------------------------------
%s
---[ CONTENT-TYPE ]----------------------------------
%s
---[ DATE ]------------------------------------------
%s
---[ Canonicalized Header ]--------------------------
%s
---[ Canonicalized Resource ]------------------------
%s
---[ Signed URL ]------------------------------------
%s
---[ String to Signed ]------------------------------
%s
---[ Signature ]-------------------------------------
%s
-----------------------------------------------------`
const logSignedURLMsg = `
---[ SIGNED URL ]------------------------------------
%s`

func (v2 *signer) logSigningInfo() {
	var signedURLMsg = ""
	if v2.isPresign {
		signedURLMsg = fmt.Sprintf(logSignedURLMsg, v2.Request.URL.String())
	}
	msg := fmt.Sprintf(logSignInfoMsg, v2.method, v2.contentMD5, v2.contentType, v2.formattedTime, v2.canonicalHeaders, v2.canonicalResource, signedURLMsg, v2.stringToSign, v2.signature)
	v2.Logger.Log(msg)
}

func (v2 *signer) build() {
	v2.buildMethod()
	v2.buildContentMD5()
	v2.buildContentType()
	v2.buildTime() // no depends
	if v2.isPresign {
		v2.buildQuery() // no depends
	}
	v2.buildCanonicalHeaders()  // depends on cred string
	v2.buildCanonicalResource() // depends on canon headers / signed headers
	v2.buildStringToSign()      // depends on canon string
	v2.buildSignature()         // depends on string to sign

	if v2.isPresign {
		v2.Request.URL.RawQuery += "&Signature=" + url.QueryEscape(v2.signature)
	} else {
		s := authHeaderPrefix + " " + v2.CredValues.AccessKeyID + ":" + v2.signature
		v2.Request.Header.Set("Authorization", s)
	}
}

func (v2 *signer) buildMethod() {
	v2.method = v2.Request.Method
}

func (v2 *signer) buildContentMD5() {
	v2.contentMD5 = v2.Request.Header.Get("Content-Md5")
}

func (v2 *signer) buildContentType() {
	v2.contentType = v2.Request.Header.Get("Content-type")
}

func (v2 *signer) buildTime() {
	v2.formattedTime = v2.Time.UTC().Format(timeFormat)
	v2.formattedShortTime = v2.Time.UTC().Format(shortTimeFormat)

	if v2.isPresign {
		now := time.Now().Unix()
		expire := int64(v2.ExpireTime/time.Second) + now
		v2.expireSeconds = strconv.FormatInt(expire, 10)
		v2.Query.Set("Expires", v2.expireSeconds)
	} else {
		v2.Request.Header.Set("X-Amz-Date", v2.formattedTime)
	}
}

func (v2 *signer) buildCanonicalHeaders() {
	var headers []string
	for k := range v2.Request.Header {
		if _, ok := ignoredHeaders[http.CanonicalHeaderKey(k)]; ok {
			continue // ignored header
		}
		headers = append(headers, strings.ToLower(k))
	}
	sort.Strings(headers)

	v2.signedHeaders = strings.Join(headers, ";")

	headerValues := make([]string, len(headers))
	for i, k := range headers {
		headerValues[i] = k + ":" +
			strings.Join(v2.Request.Header[http.CanonicalHeaderKey(k)], ",")
	}

	v2.canonicalHeaders = strings.Join(headerValues, "\n")
}

func (v2 *signer) buildQuery() {
	for k, h := range v2.Request.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Amz-") {
			continue // never hoist x-amz-* headers, they must be signed
		}
		if _, ok := ignoredHeaders[http.CanonicalHeaderKey(k)]; ok {
			continue // never hoist ignored headers
		}

		v2.Request.Header.Del(k)
		v2.Query.Del(k)
		for _, v := range h {
			v2.Query.Add(k, v)
		}
	}
	if v2.isPresign {
		v2.Query.Add("AWSAccessKeyId", v2.CredValues.AccessKeyID)
	}
}

func (v2 *signer) buildCanonicalResource() {
	v2.Request.URL.RawQuery = strings.Replace(v2.Query.Encode(), "+", "%20", -1)
	uri := v2.Request.URL.Opaque
	if uri != "" {
		uri = "/" + strings.Join(strings.Split(uri, "/")[3:], "/")
	} else {
		uri = v2.Request.URL.Path
	}
	if uri == "" {
		uri = "/"
	}

	if v2.ServiceName != "s3" {
		uri = rest.EscapePath(uri, false)
	}

	var sarray []string
	for k, v := range v2.Query {
		if v2.isPresign && (k == "AWSAccessKeyId" || k == "Expires") {
			continue
		} else if _, ok := qsaOfInterest[k]; !ok {
			continue
		}

		for _, vi := range v {
			if vi == "" {
				sarray = append(sarray, k)
			} else {
				// "When signing you do not encode these values."
				sarray = append(sarray, k+"="+vi)
			}
		}
	}
	var raw_query string
	if len(sarray) > 0 {
		sort.StringSlice(sarray).Sort()
		raw_query = strings.Join(sarray, "&")
	}
	fmt.Printf("raw_query=[%s]\n", raw_query)

	//if len(v2.Request.URL.RawQuery) > 0 {
	if len(raw_query) > 0 {
		//v2.canonicalResource = uri + "?" + v2.Request.URL.RawQuery
		v2.canonicalResource = uri + "?" + raw_query
	} else {
		v2.canonicalResource = uri
	}
	fmt.Printf("canonicalResource=[%s]\n", v2.canonicalResource)
}

func (v2 *signer) buildStringToSign() {
	s := []string{
		v2.Request.Method,
		v2.contentMD5,
		v2.contentType,
	}
	if v2.isPresign {
		s = append(s, v2.expireSeconds)
	} else {
		s = append(s, "")
	}
	if v2.canonicalHeaders != "" {
		s = append(s, v2.canonicalHeaders)
	}
	s = append(s, v2.canonicalResource)
	v2.stringToSign = strings.Join(s, "\n")
}

func (v2 *signer) buildSignature() {
	var b64 = base64.StdEncoding
	secret := v2.CredValues.SecretAccessKey

	hash := hmac.New(sha1.New, []byte(secret))
	hash.Write([]byte(v2.stringToSign))
	signature := make([]byte, b64.EncodedLen(hash.Size()))
	b64.Encode(signature, hash.Sum(nil))
	v2.signature = string(signature)
}

// isRequestSigned returns if the request is currently signed or presigned
func (v2 *signer) isRequestSigned() bool {
	if v2.isPresign && v2.Query.Get("X-Amz-Signature") != "" {
		return true
	}
	if v2.Request.Header.Get("Authorization") != "" {
		return true
	}

	return false
}

// unsign removes signing flags for both signed and presigned requests.
func (v2 *signer) removePresign() {
	v2.Query.Del("X-Amz-Algorithm")
	v2.Query.Del("X-Amz-Signature")
	v2.Query.Del("X-Amz-Security-Token")
	v2.Query.Del("X-Amz-Date")
	v2.Query.Del("X-Amz-Expires")
	v2.Query.Del("X-Amz-Credential")
	v2.Query.Del("X-Amz-SignedHeaders")
}

func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha1.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}
