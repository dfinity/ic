#!/bin/bash

# TODO migrate this and all scripts to regular quill
##: install_sns_quill
## Usage: $1 <DIR> (<VERSION>)
## Install sns-quill into DIR optionally at VERSION (defaults to 0.4.0)
install_sns_quill() {
    local DEST_FOLDER=$1
    local VERSION=${2:-0.4.0}
    log "Downloading sns-quill"

    local DEST=$DEST_FOLDER/sns-quill

    if [ $(uname -o) == "Darwin" ]; then
        curl -L -o $DEST https://github.com/dfinity/sns-quill/releases/download/v$VERSION/sns-quill-macos-x86_64
    else
        curl -L -o $DEST https://github.com/dfinity/sns-quill/releases/download/v$VERSION/sns-quill-linux-x86_64
    fi

    chmod +x $DEST
}

##: install_idl2json
## Usage: $1 <DIR> (<VERSION>)
## Install idl2json into DIR optionally at VERSION (defaults to 0.8.5)
install_idl2json() {
    local DEST_FOLDER=$1
    local VERSION=${2:-0.8.5}
    log "Downloading idl2json"

    local DEST=$DEST_FOLDER/idl2json

    if [ "$(uname -op)" == "Darwin" ]; then
        curl -L -o /tmp/idl2json.zip https://github.com/dfinity/idl2json/releases/download/v$VERSION/idl2json-macos-x86_64.zip
        unzip /tmp/idl2json.zip
    else
        curl -L -o /tmp/idl2json-linux-x86_64.tar.gz https://github.com/dfinity/idl2json/releases/download/v$VERSION/idl2json-linux-x86_64.tar.gz
        tar -zxvf /tmp/idl2json-linux-x86_64.tar.gz

    fi
    cp idl2json $DEST
    rm -f idl2json yaml2candid

    chmod +x $DEST

}
