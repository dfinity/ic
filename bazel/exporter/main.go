// Bazel invoked with --build_event_binary_file outputs a series of delimited build event stream protobuf messages to a file.
// This binary parse that file and output the data to Honeycomb.
// Example:
//   bazel run //bazel/exporter:exporter -- -f (git rev-parse --show-toplevel)/bazel/exporter/testdata/flaky-bep.pb
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/dfinity/ic/proto/build_event_stream"
	"github.com/golang/protobuf/proto"
	beeline "github.com/honeycombio/beeline-go"
	"google.golang.org/protobuf/encoding/protojson"
)

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

		spanCtx, eventSpan := beeline.StartSpan(context.Background(), "export_event")
		beeline.AddField(spanCtx, "event", jsonMap)
		beeline.AddField(spanCtx, "gitlab", envVars)
		eventSpan.Send()
	}

	log.Printf("Processed %d protos", cnt)
}
