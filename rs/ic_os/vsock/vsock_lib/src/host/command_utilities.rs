use crate::protocol::{Payload, Response};

pub fn handle_command_output(
    command_output: Result<std::process::Output, std::io::Error>,
) -> Response {
    match command_output {
        Ok(command_output) => {
            if command_output.status.success() {
                match String::from_utf8(command_output.stdout) {
                    Ok(str) => {
                        println!("Command output: {}", str);
                        Ok(Payload::NoPayload)
                    }
                    Err(err) => {
                        let error_string = format!("Unable to read command stdout: {}", err);
                        println!("Error: {}", error_string);
                        Err(error_string)
                    }
                }
            } else {
                match String::from_utf8(command_output.stderr) {
                    Ok(str) => {
                        println!("Command stderr output: {}", str);
                        Err(str)
                    }
                    Err(err) => {
                        let error_string = format!("Unable to read command stderr: {}", err);
                        println!("Error: {}", error_string);
                        Err(error_string)
                    }
                }
            }
        }
        Err(err) => {
            let error_string = format!("Unable to read command output: {}", err);
            println!("Error: {}", error_string);
            Err(error_string)
        }
    }
}
