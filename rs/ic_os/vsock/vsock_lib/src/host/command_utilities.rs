use crate::protocol::{Payload, Response};
use std::io::Error;
use std::process::Output;

pub fn handle_command_output(command_output: Result<Output, Error>) -> Response {
    command_output
        .map_err(|err| {
            let error_string = format!("Unable to read command output: {err}");
            println!("Error: {error_string}");
            error_string
        })
        .and_then(|output| {
            if output.status.success() {
                handle_output_string(String::from_utf8(output.stdout), "stdout")
            } else {
                handle_output_string(String::from_utf8(output.stderr), "stderr")
            }
        })
}

fn handle_output_string(
    output_string: Result<String, std::string::FromUtf8Error>,
    label: &str,
) -> Response {
    output_string
        .map_err(|err| {
            let error_string = format!("Unable to read command {label}: {err}");
            println!("Error: {error_string}");
            error_string
        })
        .and_then(|output| {
            if label == "stdout" {
                Ok(Payload::NoPayload)
            } else {
                Err(output)
            }
        })
}
