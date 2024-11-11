/// Utilities to manipulate a kernel command line reliably.
use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
/// A kernel command line with improperly-quoted argument values.
pub struct ImproperlyQuotedValue {
    val: String,
}
impl StdError for ImproperlyQuotedValue {}

impl fmt::Display for ImproperlyQuotedValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Unclosed quote capturing value {:?} from supplied command line",
            self.val
        )
    }
}

#[derive(Debug)]
/// A value unrepresentable as a kernel command line argument value.
pub struct UnrepresentableValue(String);

impl StdError for UnrepresentableValue {}

impl fmt::Display for UnrepresentableValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Illegal characters in supplied value {:?}", self.0)
    }
}

#[derive(Debug, Default)]
/// Represents a correctly-parsed kernel command line.
pub struct KernelCommandLine {
    tokenized_arguments: Vec<String>,
}

impl KernelCommandLine {
    fn format_argument(
        argument: &str,
        value: Option<&str>,
    ) -> Result<String, UnrepresentableValue> {
        fn escape_value(val: &str) -> Result<String, UnrepresentableValue> {
            Ok(if val.contains("\"") || val.contains("\n") {
                return Err(UnrepresentableValue(val.to_string()));
            } else if val.contains(" ") {
                format!("\"{val}\"")
            } else {
                val.to_string()
            })
        }
        if let Some(val) = value {
            Ok(format!("{}={}", argument, escape_value(val)?))
        } else {
            Ok(argument.to_owned())
        }
    }

    /// Remove an argument from a kernel command line, however many times it appears.
    /// Returns the position of the first removed argument.
    pub fn remove_argument(&mut self, argument: &str) -> Option<usize> {
        let mut firstpos: Option<usize> = None;
        self.tokenized_arguments = self
            .tokenized_arguments
            .clone()
            .into_iter()
            .enumerate()
            .filter(|(pos, arg)| {
                let res =
                    *arg != argument && !arg.starts_with((argument.to_owned() + "=").as_str());
                if !res && firstpos.is_none() {
                    firstpos.replace(*pos);
                }
                res
            })
            .map(|(_, x)| x)
            .collect();
        firstpos
    }

    /// Ensure an argument is present in a kernel command line.
    /// If the argument is in the command line, it is replaced with the supplied
    /// value in the same position, and all other mentions are removed.
    /// If the argument is not in the command line, it is appended to the end.
    pub fn ensure_single_argument(
        &mut self,
        argument: &str,
        value: Option<&str>,
    ) -> Result<(), UnrepresentableValue> {
        match self.remove_argument(argument) {
            Some(pos) => {
                // match pos >= self.tokenized_arguments.len()
                self.tokenized_arguments
                    .insert(pos, Self::format_argument(argument, value)?);
            }
            None => {
                self.add_argument(argument, value)?;
            }
        }
        Ok(())
    }

    /// Add an argument to the end of a kernel command line.
    /// This does not replace previous arguments of the same name.
    pub fn add_argument(
        &mut self,
        argument: &str,
        value: Option<&str>,
    ) -> Result<(), UnrepresentableValue> {
        let formatted_argument = Self::format_argument(argument, value)?;
        let to_add = formatted_argument;
        self.tokenized_arguments.push(to_add);
        Ok(())
    }
}

impl From<KernelCommandLine> for String {
    fn from(val: KernelCommandLine) -> Self {
        val.tokenized_arguments.join(" ")
    }
}

impl TryFrom<&str> for KernelCommandLine {
    type Error = ImproperlyQuotedValue;

    fn try_from(cmdline: &str) -> Result<Self, ImproperlyQuotedValue> {
        let mut res: Vec<String> = vec![];
        let mut curr: String = "".into();
        let mut is_quoted = false;
        for ch in cmdline.chars() {
            match ch {
                '"' => {
                    if is_quoted {
                        curr.push(ch);
                        res.push(curr.clone());
                        curr = "".into();
                        is_quoted = false;
                    } else {
                        curr.push(ch);
                        is_quoted = true;
                    }
                }
                ' ' => {
                    if is_quoted {
                        curr.push(ch);
                    } else if !curr.is_empty() {
                        res.push(curr.clone());
                        curr = "".into();
                    }
                }
                _ => {
                    curr.push(ch);
                }
            }
        }
        if curr.is_empty() {
        } else if is_quoted {
            return Err(ImproperlyQuotedValue { val: curr });
        } else {
            res.push(curr);
        }
        Ok(Self {
            tokenized_arguments: res,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::KernelCommandLine;

    #[test]
    fn test_remove_argument() {
        let table = [
            (
                "remove argument without value at the beginning of command line succeeds",
                "rd.debug rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\""
                    ,
                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\"",
            ),
            (
                "remove argument without value in the middle of command line succeeds",
                "rd.initrd=/bin/bash rd.debug rd.escaped=\"this is a multiline argument\""
                    ,
                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\"",
            ),
            (
                "remove argument without value at the end of command line succeeds",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\" rd.debug"
                    ,
                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\"",
            ),
            (
                "remove argument with value at the beginning of command line succeeds",
                "rd.debug=0 rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\""
                    ,
                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\"",
            ),
            (
                "remove argument with value in the middle of command line succeeds",
                "rd.initrd=/bin/bash rd.debug=0 rd.escaped=\"this is a multiline argument\""
                    ,
                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\"",
            ),
            (
                "remove argument with value at the end of command line succeeds",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\" rd.debug=1"
                    ,
                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\"",
            ),
            (
                "remove argument with quoted value at the beginning of command line succeeds",
                "rd.debug=\"i am quoted value\" rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\""
                    ,
                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\"",
            ),
            (
                "remove argument with quoted value in the middle of command line succeeds",
                "rd.initrd=/bin/bash rd.debug=\"i am quoted value\" rd.escaped=\"this is a multiline argument\"",
                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\"",
            ),
            (
                "remove argument with quoted value at the end of command line succeeds",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\" rd.debug=\"i am quoted value\"",                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\"",
            ),
            (
                "argument with substring does not get removed at end of string",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\" rd.debug=\"i am quoted value\"",                "rd.debu",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\" rd.debug=\"i am quoted value\""
                    ,
            ),
            (
                "argument removal chomps extra spaces after removal",
                "rd.initrd=/bin/bash  rd.escaped=\"this is a multiline argument\" rd.debug=\"i am quoted value\"",                "rd.debug",
                "rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\""
                    ,
            ),
        ];
        for (name, input, argument_to_remove, expected) in table.iter() {
            let mut cmdline = KernelCommandLine::try_from(*input).unwrap();
            cmdline.remove_argument(argument_to_remove);
            let result: String = cmdline.into();
            if result != *expected {
                panic!(
                    "During test {name}:
input:    {input:?}
argument: {argument_to_remove:?}
expected: {expected:?}
actual:   {result:?}",
                );
            }
        }
    }

    #[test]
    fn test_unquoted_argument() {
        let table = [
            (
                "misquoted argument at the beginning of command line succeeds",
                "rd.debug=\"misquoted rd.initrd=/bin/bash rd.escaped=\"this is a multiline argument\""
            ),
            (
                "misquoted argument in the middle of command line succeeds",
                "rd.initrd=/bin/bash rd.debug=\"misquoted rd.escaped=\"this is a multiline argument\""
            ),
            (
                "misquoted argument at the end of command line succeeds",
                "rd.initrd=/bin/bash misquoted=\"true it's misquoted rd.escaped=\"this is a multiline argument\" rd.debug"
            ),
        ];
        for (name, input) in table.iter() {
            if KernelCommandLine::try_from(*input).is_ok() {
                panic!(
                    "During test {name}: input {input:?} intentionally misquoted argument did not trigger error",
                )
            }
        }
    }

    #[test]
    fn test_ensure() {
        let table = [
            (
                "variable gets added when the file does not contain the variable",
                "",
                "parm",
                Some("0"),
                r"parm=0",
            ),
            (
                "changes the variable successfully when present without value",
                "parm",
                "parm",
                Some("1"),
                "parm=1",
            ),
            (
                "changes the variable value successfully when present with value",
                "parm=2",
                "parm",
                None,
                "parm",
            ),
            (
                "successfully modifies first of two parameters, removes last",
                "origparm parm=2 some=\"quoted value\" parm=4",
                "parm",
                Some("3"),
                "origparm parm=3 some=\"quoted value\"",
            ),
            (
                "successfully changes last parameter",
                "origparm some=\"quoted value\" parm=4",
                "parm",
                None,
                "origparm some=\"quoted value\" parm",
            ),
            (
                "preserves the order of the variables",
                "origparm parm=2 some=\"quoted value\" parm=4",
                "some",
                Some("another quoted value"),
                "origparm parm=2 some=\"another quoted value\" parm=4",
            ),
        ];
        for (test_name, input, argument, value, expected) in table.into_iter() {
            let mut cmdline = KernelCommandLine::try_from(input).unwrap();
            cmdline.ensure_single_argument(argument, value).unwrap();
            let result: String = cmdline.into();
            if result != *expected {
                panic!(
                    "During test {test_name}:
Input:
[[[{input}]]]

Expected:
[[[{expected}]]]

Actual:
[[[{result}]]]
"
                );
            }
        }
    }
}
