// Bazel invoked with --build_event_binary_file outputs a series of delimited build event stream protobuf messages to a file.
// This binary parse that file and output the data to Honeycomb.
// Example:
//   bazel run //bazel/exporter:exporter -- -f (git rev-parse --show-toplevel)/bazel/exporter/testdata/flaky-bep.pb
package main

import (
	"bufio"
	"bytes"
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
	"strconv"
	"strings"
	"time"

	"github.com/dfinity/ic/proto/build_event_stream"
	"github.com/golang/protobuf/proto"
	beeline "github.com/honeycombio/beeline-go"
	"google.golang.org/genproto/googleapis/bytestream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
)

var GRPC_DIAL_TIMEOUT = 20 * time.Second

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
	want := []string{"GITHUB_ACTION",
		"GITHUB_ACTION_PATH",
		"GITHUB_ACTION_REPOSITORY",
		"GITHUB_ACTIONS",
		"GITHUB_ACTOR",
		"GITHUB_BASE_REF",
		"GITHUB_ENV",
		"GITHUB_EVENT_NAME",
		"GITHUB_HEAD_REF",
		"GITHUB_JOB",
		"GITHUB_OUTPUT",
		"GITHUB_PATH",
		"GITHUB_REF",
		"GITHUB_REF_NAME",
		"GITHUB_REF_PROTECTED",
		"GITHUB_REF_TYPE",
		"GITHUB_REPOSITORY",
		"GITHUB_REPOSITORY_ID",
		"GITHUB_REPOSITORY_OWNER",
		"GITHUB_REPOSITORY_OWNER_ID",
		"GITHUB_RETENTION_DAYS",
		"GITHUB_RUN_ATTEMPT",
		"GITHUB_RUN_NUMBER",
		"GITHUB_SHA",
		"GITHUB_STEP_SUMMARY",
		"GITHUB_TRIGGERING_ACTOR",
		"GITHUB_WORKFLOW",
		"GITHUB_WORKFLOW_REF",
		"GITHUB_WORKFLOW_SHA",
		"GITHUB_WORKSPACE",
		"RUNNER_ARCH",
		"RUNNER_NAME",
		"RUNNER_OS",
		"RUNNER_TEMP",
		"RUNNER_TOOL_CACHE",
		"CI_JOB_URL",
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

	var dataset string = "bazel-github"
	log.Printf("Using dataset %s", dataset)

	beeline.Init(beeline.Config{
		WriteKey:    envVarOrDie("HONEYCOMB_API_TOKEN"),
		Dataset:     dataset,
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

		spanCtx, eventSpan := beeline.StartSpan(context.Background(), "export_event")
		testTarget := event.GetId().GetTestSummary().GetLabel()
		if IsSystemTestTarget(testTarget) {
			kibanaUrls, failureMessages := ExtractFailuresAndKibanaUrls(testTarget, summary)
			// By adding a string field explicitly, we circumvent the default json encoding behavior of objects (like map) containing special symbols like "&".
			// By default "problematic" HTML characters should be escaped inside JSON quoted strings. https://cs.opensource.google/go/go/+/refs/tags/go1.20.5:src/encoding/json/stream.go;l=193
			// Kibana urls do contain such special symbols (like &) and we don't want to escape them.
			beeline.AddField(spanCtx, "event.kibana_urls", kibanaUrls)
			beeline.AddField(spanCtx, "event.failure_messages", failureMessages)
		}

		beeline.AddField(spanCtx, "event", jsonMap)
		beeline.AddField(spanCtx, "github", envVars)
		eventSpan.Send()
	}
	log.Printf("Processed %d protos", cnt)
}

func ProcessTestLogFile(shouldExtractFailures bool, fileIdx int, file *build_event_stream.File, failuresMap map[string]string, kibanaUrlsMap map[string]string) {
	testLog, err := GetTestLog(file)
	if err != nil {
		errMsg := "Failed to read test log"
		kibanaUrlsMap["url_"+strconv.Itoa(fileIdx)] = errMsg
		if shouldExtractFailures {
			failuresMap["failure_"+strconv.Itoa(fileIdx)] = errMsg
		}
	} else {
		testLogStr := string(testLog)
		kibanaUrl, err := ExtractKibanaUrlFromTestLog(testLogStr)
		if err != nil {
			kibanaUrl = err.Error()
		}
		kibanaUrlsMap["url_"+strconv.Itoa(fileIdx)] = kibanaUrl
		if shouldExtractFailures {
			failureMsg, err := ExtractFailuresFromTestLog(testLogStr)
			if err != nil {
				log.Printf("Couldn't extract failures from file=%v, err: %v\n", file, err)
				failureMsg = err.Error()
			}
			failuresMap["failure_"+strconv.Itoa(fileIdx)] = failureMsg
		}
	}
}

func ConvertMapToString(m map[string]string, testTarget string) string {
	result := ""
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	// Here we change the default encoding behavior, as urls can contain special symbols like &. We don't want to escape those.
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(m)
	if err != nil {
		errMsg := "Processing error: Failed to json encode map"
		log.Printf("%s for target=%s: %v\n", errMsg, testTarget, err)
		result = errMsg
	} else {
		result = buffer.String()
		// For purely visual purposes, instead of printing an empty map (i.e. {}) in Honeycomb, let's print nothing.
		if result == "{}" {
			result = ""
		}
	}
	return result
}

func ExtractFailuresAndKibanaUrls(testTarget string, summary *build_event_stream.TestSummary) (string, string) {
	// It is important for the script to NOT fail in case of errors/panics when processing system-test logs.
	// Thus, this function recovers from panic, if one occurs.
	defer HandlePanic()
	// These could be lists instead of maps. However, in Honeycomb one can spot a particular failure message (especially verbose one) easier when an index is shown: {failure_1: "error_1", "failure_2": "error_2", ...} vs ["error_1", ... , ].
	failureMessagesMap := make(map[string]string)
	kibanaUrlsMap := make(map[string]string)
	fileIdx := 1
	for _, file := range summary.GetFailed() {
		ProcessTestLogFile(true, fileIdx, file, failureMessagesMap, kibanaUrlsMap)
		fileIdx += 1
	}
	for _, file := range summary.GetPassed() {
		ProcessTestLogFile(false, fileIdx, file, failureMessagesMap, kibanaUrlsMap)
		fileIdx += 1
	}
	kibanaUrls := ConvertMapToString(kibanaUrlsMap, testTarget)
	failureMessages := ConvertMapToString(failureMessagesMap, testTarget)
	return kibanaUrls, failureMessages
}

func HandlePanic() {
	if err := recover(); err != nil {
		log.Printf("Recovered from panic: %v\n", err)
	}
}

func IsSystemTestTarget(testTarget string) bool {
	return strings.Contains(testTarget, "//rs/tests/")
}

func GetTestLog(file *build_event_stream.File) ([]byte, error) {
	// Uri has the form bytestream://bazel-remote.idx.dfinity.network/blobs/id1/id2
	uri := file.GetUri()
	parsedURI, err := url.Parse(uri)
	if err != nil {
		log.Printf("Failed to parse uri %s, error: %v\n", uri, err)
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
	// First we need to find "json_report_created_event" event in the logs, which contains all inner errors.
	// Example of report event in the logs:
	// TIMESTAMP INFO[...] {"event_name":"json_report_created_event","body":{"success":[],"failure":[],"skipped":[]}}
	reportIdx := strings.Index(testLog, "{\"event_name\":\"json_report_created_event\"")
	if reportIdx == -1 {
		err := errors.New("json_report_created_event was not found in the test log.")
		log.Println(err)
		return "", err
	}
	reportStart := reportIdx + strings.Index(testLog[reportIdx:], "{")
	reportEnd := reportStart + strings.Index(testLog[reportStart:], "\n")
	report := testLog[reportStart:reportEnd]
	jsonMap := make(map[string]interface{})
	errMsg := "json_report_created_event from log couldn't be processed correctly"
	if err := json.Unmarshal([]byte(report), &jsonMap); err != nil {
		log.Printf("Failed to unmarshal json bytes to map in json_report_created_event: %v\n", err)
		return "", fmt.Errorf("%s: %v", errMsg, err)
	}
	jsonBytesBody, err := json.Marshal(jsonMap["body"])
	if err != nil {
		log.Printf("Failed to marshal map: %v\n", err)
		return "", fmt.Errorf("%s: %v", errMsg, err)
	}
	jsonMap = make(map[string]interface{})
	if err := json.Unmarshal([]byte(jsonBytesBody), &jsonMap); err != nil {
		log.Printf("Failed to unmarshal json bytes in the \"body\" of json_report_created_event: %v\n", err)
		return "", fmt.Errorf("%s: %v", errMsg, err)
	}
	jsonBytesFailure, err := json.Marshal(jsonMap["failure"])
	if err != nil {
		log.Printf("Failed to marshal map: %v\n", err)
		return "", fmt.Errorf("%s: %v", errMsg, err)
	}
	return string(jsonBytesFailure), nil
}

func ExtractKibanaUrlFromTestLog(testLog string) (string, error) {
	// System test log should contain this string.
	message := "Replica logs will appear in Kibana: "
	kibanaUrlIdx := strings.Index(testLog, message)
	if kibanaUrlIdx == -1 {
		return "", errors.New("Kibana url was not found in the test log.")
	}
	kibanaUrlStart := kibanaUrlIdx + len(message)
	kibanaUrlEnd := kibanaUrlStart + strings.Index(testLog[kibanaUrlStart:], "\n")
	kibanaUrl := testLog[kibanaUrlStart:kibanaUrlEnd]
	return kibanaUrl, nil
}
