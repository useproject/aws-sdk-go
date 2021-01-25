package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws"
)

const (
	accessKey = ""
	secretKey = ""
	host      = ""
	region    = "cn-north-1"

	bucketName = ""
)

var (
	keys = []string{
		"dir/obj1.txt",
		"dir/obj2.txt",
		"dir/obj3.txt",
		"obj1.txt",
	}
)

func NewS3Client(endpoint, region, accessKey, secretKey string) *s3.S3 {
	creds := credentials.NewStaticCredentials(accessKey, secretKey, "")
	config := &aws.Config{
		Credentials:             creds,
		Endpoint:                &endpoint,
		Region:                  &region,
		DisableSSL:              aws.Bool(false), // HTTPS
		HTTPClient:              http.DefaultClient,
		MaxRetries:              aws.Int(2),
		LogLevel:                aws.LogLevel(aws.LogDebugWithSigning),
		DisableParamValidation:  aws.Bool(true),
		DisableComputeChecksums: aws.Bool(true),
		S3ForcePathStyle:        aws.Bool(true),
	}

	svc := s3.New(config)
	return svc
}

func putObject(client *s3.S3, bucketName, objectKey string) {
	params := &s3.PutObjectInput{
		Bucket:             aws.String(bucketName), // Required
		Key:                aws.String(objectKey),  // Required
		Body:               bytes.NewReader([]byte("TEST")),
	}
	if _, err := client.PutObject(params); err != nil {
		fmt.Fprintf(os.Stderr, "put object fail, err=%v bucketName=%s objectKey=%s\n", err, bucketName, objectKey)
		os.Exit(-1)
	}
}

func putObjects(client *s3.S3) {
	for _, v := range keys {
		putObject(client, bucketName, v)
	}
}

func listObjects(client *s3.S3) {
	// get all objects belonging to the bucket
	param1 := &s3.ListObjectsInput{
		Bucket:       aws.String(bucketName), // Required
	}
	getListObjectsResp(client, param1)

	// get objects with specified prefix
	param2 := &s3.ListObjectsInput{
		Bucket:       aws.String(bucketName), // Required
		Prefix:       aws.String("dir"),
	}
	getListObjectsResp(client, param2)

	// get objects with specified prefix and delimiter
	param3 := &s3.ListObjectsInput{
		Bucket:       aws.String(bucketName), // Required
		Delimiter:    aws.String("/"),
		Prefix:       aws.String("dir"),
	}
	getListObjectsResp(client, param3)

	// get objects with maxKeys
	param4 := &s3.ListObjectsInput{
		Bucket:       aws.String(bucketName), // Required
		MaxKeys:      aws.Int64(2),
		Prefix:       aws.String("dir"),
	}
	getListObjectsResp(client, param4)

	// get objects with marker
	param5 := &s3.ListObjectsInput{
		Bucket:       aws.String(bucketName), // Required
		Marker:       aws.String("dir/obj2"),
		Prefix:       aws.String("dir"),
	}
	getListObjectsResp(client, param5)
}

func getListObjectsResp(client *s3.S3, param *s3.ListObjectsInput) {
	if resp, err := client.ListObjects(param); err != nil {
		fmt.Fprintf(os.Stderr, "ListObjects fail, err=%v param=%v\n", err, param)
		os.Exit(-1)
	} else {
		fmt.Fprintf(os.Stdout, resp.String())
	}
}

func main() {
	client := NewS3Client(
		host,
		region,
		accessKey,
		secretKey,
	)

	putObjects(client)

	listObjects(client)
}
