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
	expected := "requires at least 1 arg(s), only received 0"
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

func Test_ListCmdWithHelpArg(t *testing.T) {
	expected := "List all system_test targets with Bazel"
	actual := new(bytes.Buffer)
	var command = cmd.NewTestListCmd()
	command.SetArgs([]string{"-h"})
	command.SetOut(actual)

	err := command.Execute()

	assert.Nil(t, err)
	assert.Contains(t, actual.String(), expected)
}

func Test_ListCmdWithOneArg(t *testing.T) {
	expected := "Error: accepts 0 arg(s), received 1"
	actual := new(bytes.Buffer)
	var command = cmd.NewTestListCmd()
	command.SetArgs([]string{"arg"})
	command.SetOut(actual)
	command.SetErr(actual)

	err := command.Execute()

	assert.NotNil(t, err)
	assert.Contains(t, actual.String(), expected)
}
