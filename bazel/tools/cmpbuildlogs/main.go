package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type BuildRecord map[string]interface{}
type BuildRecords map[string]BuildRecord

const KEY = "progressMessage"
const UNIQUE_KEY = "listedOutputs"

func loadBuildRecords(fname string) BuildRecords {
	br := make(BuildRecords)

	logFile, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}

	dec := json.NewDecoder(logFile)
	for {
		buildRecord := make(BuildRecord)
		if err := dec.Decode(&buildRecord); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		key := buildRecord[KEY].(string)
		if buildRecord[UNIQUE_KEY] != nil {
			// progressMessage is not unique, need to add listedOutput to the key.
			var outs []string
			for _, v := range buildRecord[UNIQUE_KEY].([]interface{}) {
				outs = append(outs, v.(string))
			}
			key = fmt.Sprintf("%s%v", key, outs)
		}
		br[key] = buildRecord
	}
	return br
}

func ignoreBuildRecordEntries(k string, v interface{}) bool {
	return k == "walltime" || k == "remoteCacheHit" || k == "runner" || k == "digest"
}

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %v <execution-log-1.json> <execution-log-2.json>", os.Args[0])
	}
	rl1 := loadBuildRecords(os.Args[1])
	rl2 := loadBuildRecords(os.Args[2])

	cmpOpts := cmpopts.IgnoreMapEntries(ignoreBuildRecordEntries)
	for k, v1 := range rl1 {
		// TODO: optionally show when a record only exists in one of two log files
		if v2, ok := rl2[k]; ok {
			if diff := cmp.Diff(v1, v2, cmpOpts); diff != "" {
				fmt.Printf("The action \"%v\" is different:\n%v\n----------\n", k, diff)
			}
		}
	}
}
