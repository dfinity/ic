use super::responses::LineDisplayPage;
use itertools::Itertools;

pub const ICRC1_TRANSFER_GENERIC_DISPLAY_MESSAGE: &str = "Transfer {AMOUNT} **{TOKEN_SYMBOL}** from the **Sender** {SENDER_ACCOUNT} to the **Receiver**: {RECEIVER_ACCOUNT}. 
The fee payed by the **Sender** is {LEDGER_FEE} **{TOKEN_SYMBOL}**.";

pub const ICRC1_TRANSFER_GENERIC_DISPLAY_MESSAGE_DETAILS: &str = "
**Request Details**
* Sender:  {SENDER_ACCOUNT}
* Receiver: {RECEIVER_ACCOUNT}
* Transferred amount of **{TOKEN_SYMBOL}**: {AMOUNT}
* Memo: {MEMO}
* The fee that was set by the **Sender**: {FEE_SET} 
* The effective fee paid by the **Sender** for the transaction: {LEDGER_FEE} **{TOKEN_SYMBOL}** e8s
* The timestamp of creation of this transaction by the user: {CREATED_AT_TIME}";

pub const ICRC1_TRANSFER_LINE_DISPLAY_MESSAGE: &str = "Transfer {AMOUNT} {TOKEN_SYMBOL} from {SENDER_ACCOUNT} to {RECEIVER_ACCOUNT}. Fee payed by {SENDER_ACCOUNT} is {LEDGER_FEE} {TOKEN_SYMBOL}. Memo is {MEMO}.";

// Maximum number of bytes that an argument to an ICRC-1 ledger function can have when passed to the ICRC-21 endpoint.
pub const MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES: u16 = 500;

/// This function was taken from the reference implementation: https://github.com/dfinity/wg-identity-authentication/blob/3ed140225b283c0a1cc88344d0cfb9912aec73cd/reference-implementations/ICRC-21/src/lib.rs#L73
pub fn consent_msg_text_pages(
    message: &str,
    characters_per_line: u16,
    lines_per_page: u16,
) -> Vec<LineDisplayPage> {
    if characters_per_line == 0 || lines_per_page == 0 {
        return vec![];
    }

    // Split text into word chunks that fit on a line (breaking long words)
    let words = message.split_whitespace().flat_map(|word| {
        word.chars()
            .chunks(characters_per_line as usize)
            .into_iter()
            .map(|chunk| chunk.collect::<String>())
            .collect::<Vec<String>>()
    });

    // Add words to lines until the line is full
    let mut lines = vec![];
    let mut current_line = "".to_string();
    for word in words {
        if current_line.is_empty() {
            // all words are guaranteed to fit on a line
            current_line = word;
            continue;
        }
        if current_line.len() + word.len() < characters_per_line as usize {
            current_line.push(' ');
            current_line.push_str(word.as_str());
        } else {
            lines.push(current_line);
            current_line = word;
        }
    }
    lines.push(current_line);

    // Group lines into pages
    lines
        .into_iter()
        .chunks(lines_per_page as usize)
        .into_iter()
        .map(|page| LineDisplayPage {
            lines: page.collect(),
        })
        .collect()
}
