copy_component() {
  if [[ $# == 2 ]]; then
    local src_path=$1
    local dest_path=$2
  else
    local src_path=$1
    local dest_path=$1
  fi

  if [[ $dest_path != /* ]]; then
    echo "Component with not absolute deploy path: $dest_path"
    exit 1
  fi

  local src_path="/icos_build/components/$src_path"
  if [[ -d $src_path ]]; then
    mkdir -p $dest_path
    cp --remove-destination -a $src_path/* $dest_path/
  else
    mkdir -p "$(dirname $dest_path)"
    cp --remove-destination -a $src_path $dest_path
  fi
}
