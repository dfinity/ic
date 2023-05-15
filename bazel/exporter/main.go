// Bazel invoked with --build_event_binary_file outputs a series of delimited build event stream protobuf messages to a file.
// This binary parse that file and output the data to Honeycomb.
// Example:
//   bazel run //bazel/exporter:exporter -- -f (git rev-parse --show-toplevel)/bazel/exporter/testdata/flaky-bep.pb
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"strconv"
	"time"

	"github.com/dfinity/ic/proto/build_event_stream"
	"github.com/golang/protobuf/proto"
	beeline "github.com/honeycombio/beeline-go"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/genproto/googleapis/bytestream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var GRPC_DIAL_TIMEOUT = 20*time.Second

// Expect multiple proto messages in uvarint delimited format.
func ReadDelimitedProtoMessage(br *bufio.Reader) ([]byte, error) {
	size, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, err
	}

	msg := make([]byte, size)
	if _, err := io.ReadFull(br, msg); err != nil {
		return nil, fmt.Errorf("error reading protobuf", err)
	}

	return msg, nil
}

func loadEnvVars() map[string]interface{} {
	want := [...]string{"CD_ENV",
		"CI_COMMIT_AUTHOR",
		"CI_COMMIT_SHA",
		"CI_COMMIT_TAG",
		"CI_COMMIT_TIMESTAMP",
		"CI_CONCURRENT_ID",
		"CI_CONCURRENT_PROJECT_ID",
		"CI_ENVIRONMENT_NAME",
		"CI_ENVIRONMENT_SLUG",
		"CI_EXTERNAL_PULL_REQUEST_IID",
		"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
		"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA",
		"CI_JOB_ID",
		"CI_JOB_IMAGE",
		"CI_JOB_MANUAL",
		"CI_JOB_NAME",
		"CI_JOB_STAGE",
		"CI_JOB_STATUS",
		"CI_JOB_URL",
		"CI_NODE_INDEX",
		"CI_NODE_TOTAL",
		"CI_PIPELINE_ID",
		"CI_PIPELINE_SOURCE",
		"CI_RUNNER_DESCRIPTION",
		"CI_RUNNER_ID",
		"CI_RUNNER_TAGS",
		"DEPLOY_FLAVOR",
		"USER_ID",
		"USER_LOGIN",
		"SCHEDULE_NAME",
		"TESTNET",
		"STEP_START",
		"PIPELINE_START_TIME",
		"job_status",
		"DISKIMG_BRANCH",
		"CI_MERGE_REQUEST_APPROVED",
		"CI_MERGE_REQUEST_ASSIGNEES",
		"CI_MERGE_REQUEST_ID",
		"CI_MERGE_REQUEST_IID",
		"CI_MERGE_REQUEST_LABELS",
		"CI_MERGE_REQUEST_MILESTONE",
		"CI_MERGE_REQUEST_PROJECT_ID",
		"CI_MERGE_REQUEST_PROJECT_PATH",
		"CI_MERGE_REQUEST_PROJECT_URL",
		"CI_MERGE_REQUEST_REF_PATH",
		"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
		"CI_MERGE_REQUEST_SOURCE_BRANCH_SHA",
		"CI_MERGE_REQUEST_SOURCE_PROJECT_ID",
		"CI_MERGE_REQUEST_SOURCE_PROJECT_PATH",
		"CI_MERGE_REQUEST_SOURCE_PROJECT_URL",
		"CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
		"CI_MERGE_REQUEST_TARGET_BRANCH_SHA",
		"CI_MERGE_REQUEST_TITLE",
		"CI_MERGE_REQUEST_EVENT_TYPE",
		"CI_MERGE_REQUEST_DIFF_ID",
		"CI_MERGE_REQUEST_DIFF_BASE_SHA",
	}

	env_vars := make(map[string]interface{})
	for _, w := range want {
		env_vars[w] = os.Getenv(w)
	}
	return env_vars
}

func envVarOrDie(name string) string {
	ans := os.Getenv(name)
	if ans == "" {
		log.Fatalln("Could not load env var ", name)
	}
	return ans
}

func main() {
	filename := flag.String("f", "", "Bazel build events log protobuff file")
	debug := flag.Bool("n", false, "Debug mode: Output all the proto in text json text form")
	flag.Parse()

	beeline.Init(beeline.Config{
		WriteKey:    envVarOrDie("HONEYCOMB_API_TOKEN"),
		Dataset:     "bazel",
		ServiceName: "exporter",
	})
	defer beeline.Close()

	pbfile, err := os.Open(*filename)
	if err != nil {
		log.Fatalln(err)
	}
	br := bufio.NewReader(pbfile)

	envVars := loadEnvVars()
	log.Println("Reading file", pbfile.Name())
	cnt := 0
	for ; ; cnt++ {
		msg, err := ReadDelimitedProtoMessage(br)
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatalln("failed to read next proto message", err)
		}

		event := &build_event_stream.BuildEvent{}
		if err := proto.Unmarshal(msg, event); err != nil {
			log.Fatalln("Failed to unmarshal", err)
		}
		if *debug {
			fmt.Println(protojson.Format(event))
		}

		// Proto message is oneof many types. Check if it's a test summary message. Otherwise skip it.
		summary := event.GetTestSummary()
		if summary == nil {
			continue
		}

		// Marhsal the protobuf to Json format. This does things like converts proto enums to their string representation.
		b, err := protojson.Marshal(event)
		if err != nil {
			log.Fatalln("failed to marshal protobuf to json:", err)
		}

		jsonMap := make(map[string]interface{})
		if err := json.Unmarshal(b, &jsonMap); err != nil {
			log.Fatalln("failed to unmarshal json bytes to map: ", err)
		}

		test_status := summary.GetOverallStatus()
		// Extract failure messages only for FLAKY or FAILED tests.
		if test_status == build_event_stream.TestStatus_FLAKY || test_status == build_event_stream.TestStatus_FAILED {
			test_target := event.GetId().GetTestSummary().GetLabel()
			if strings.Contains(test_target, "//rs/tests/") {
				// It is important for the script to NOT fail in case of errors/panics when processing system-test logs.
				// Thus, GetSystemTestFailures() recovers from panic, if one occurs.
				jsonMap["failure_messages"] = GetSystemTestFailures(summary)
			}
		}
		spanCtx, eventSpan := beeline.StartSpan(context.Background(), "export_event")
		beeline.AddField(spanCtx, "event", jsonMap)
		beeline.AddField(spanCtx, "gitlab", envVars)
		eventSpan.Send()
	}
	log.Printf("Processed %d protos", cnt)
}

func HandlePanic() {
    if err := recover(); err != nil {
        log.Printf("Recovered from panic: %v\n", err)
    }
}

func GetSystemTestFailures(summary *build_event_stream.TestSummary) string {
	defer HandlePanic()
	failures := make(map[string]string)
	failed := summary.GetFailed()
	idx := 1
	for _, file := range failed {
		failure := ""
		testLog, err := GetTestLog(file)
		if err != nil {
			log.Printf("Error when retrieving log %v\n", err)
			failure = "Failed to retrieve test log"
		} else {
			failure, err = ExtractFailuresFromTestLog(string(testLog))
			if err != nil {
				log.Printf("Error when processing log %v\n", err)
				failure = "Failed to extract errors from log"
			}
		}
		failures["failure_" + strconv.Itoa(idx)] = failure
		idx += 1
	}
	jsonBytes, _ := json.Marshal(failures)
	return string(jsonBytes)
}

func GetTestLog(file *build_event_stream.File) ([]byte, error) {
	// Uri has the form bytestream://bazel-remote.idx.dfinity.network/blobs/id1/id2
	uri := file.GetUri()
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return []byte{}, err
	}
	if parsedURI.Scheme != "bytestream" {
		err := fmt.Errorf("The expected scheme in uri is `bytestream`, actual scheme is `%v`", parsedURI.Scheme)
		log.Println(err)
		return []byte{}, err
	}
	url := parsedURI.Host
	if parsedURI.Port() == "" {
		url += ":443"
	}
	blobId := parsedURI.Path
	dialOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: false})),
	}
	// Pass a context with a timeout to tell a blocking function that it
	// should abandon its work after the timeout elapses.
	ctx, cancel := context.WithTimeout(context.Background(), GRPC_DIAL_TIMEOUT)
	defer cancel()
	conn, err := grpc.DialContext(ctx, url, dialOpts...)
	if err != nil {
		log.Printf("grpc.Dial(%v, dialOpts...) failed: %v\n", url, err)
		return []byte{}, err
	}
	defer conn.Close()
	client := bytestream.NewByteStreamClient(conn)
	ctx = context.Background()
	bstream, err := client.Read(ctx, &bytestream.ReadRequest{
		ResourceName: blobId,
	})
	if err != nil {
		log.Printf("Failed to read bytestream: %v\n", err)
		return []byte{}, err
	}
	var blob []byte
	for {
		chunk, err := bstream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Failed to receive bytes: %v\n", err)
			return []byte{}, err
		}
		blob = append(blob, chunk.Data...)
	}
	return blob, nil
}

func ExtractFailuresFromTestLog(testLog string) (string, error) {
	// First we need to find the "JSON Report" event, which contains all inner errors.
	reportIdx := strings.Index(testLog, "JSON Report")
	if reportIdx == -1 {
		return "", errors.New("Json Report was not found in the test log.")
	}
	reportStart := reportIdx + strings.Index(testLog[reportIdx:], "{")
	reportEnd := reportStart + strings.Index(testLog[reportStart:], "\n")
	report := testLog[reportStart: reportEnd]
	jsonMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(report), &jsonMap); err != nil {
		log.Printf("Failed to unmarshal json bytes to map in JSON Report: %v\n", err)
		return "", err
	}
	jsonBytes, err := json.Marshal(jsonMap["failure"])
	if err != nil {
		log.Printf("Failed to marshal map: %v\n", err)
		return "", err
	}
	return string(jsonBytes), nil
}