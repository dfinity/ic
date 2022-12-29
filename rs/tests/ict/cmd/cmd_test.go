package cmd_test

import (
	"bytes"
	"testing"

	"github.com/dfinity/ic/rs/tests/ict/cmd"
	"github.com/stretchr/testify/assert"
)

func Test_RootCmdWitNoArgs(t *testing.T) {
	expected := "A simple CLI for running system_tests in Bazel"
	actual := new(bytes.Buffer)
	var command = cmd.NewRootCmd()
	command.SetOut(actual)

	err := command.Execute()

	assert.Nil(t, err)
	assert.Contains(t, actual.String(), expected)
}

func Test_RootCmdWithOneArg(t *testing.T) {
	expected := "A simple CLI for running system_tests in Bazel"
	actual := new(bytes.Buffer)
	var command = cmd.NewRootCmd()
	command.SetOut(actual)
	command.SetArgs([]string{"-h"})

	err := command.Execute()

	assert.Nil(t, err)
	assert.Contains(t, actual.String(), expected)
}

func Test_TestCmdWithNoArgs(t *testing.T) {
	expected := "Error: accepts 1 arg(s), received 0"
	actual := new(bytes.Buffer)
	var command = cmd.NewTestCmd()
	command.SetOut(actual)
	command.SetErr(actual)

	err := command.Execute()

	assert.NotNil(t, err)
	assert.Contains(t, actual.String(), expected)
}

func Test_TestCmdWithHelpArg(t *testing.T) {
	expected := "Run system_test target with Bazel"
	actual := new(bytes.Buffer)
	var command = cmd.NewTestCmd()
	command.SetArgs([]string{"-h"})
	command.SetOut(actual)

	err := command.Execute()

	assert.Nil(t, err)
	assert.Contains(t, actual.String(), expected)
}

func Test_TestCmdWithTargetAndDryRunArgs(t *testing.T) {
	expected := "bazel test my_target --config=systest --cache_test_results=yes"
	actual := new(bytes.Buffer)
	var command = cmd.NewTestCmd()
	command.SetArgs([]string{"my_target", "-c", "--dry-run"})
	command.SetOut(actual)

	err := command.Execute()

	assert.Nil(t, err)
	assert.Contains(t, actual.String(), expected)
}
