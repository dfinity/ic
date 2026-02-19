set -ex

function make_and_copy_declarations () {
    DIR=$1
    NAME=$2

    pushd "$DIR""$NAME"
    make extract-candid
    dfx generate $NAME
    popd

    rm -r "src/declarations/$NAME"
    mv "$DIR/""$NAME""/src/declarations/""$NAME" "src/declarations/"
}

make_and_copy_declarations "../../backend/rs/canisters/" "ic_vetkeys_manager_canister"
make_and_copy_declarations "../../backend/rs/canisters/" "ic_vetkeys_encrypted_maps_canister"
