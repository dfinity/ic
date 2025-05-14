# This Python script converts bazel's compact execution log (--execution_log_compact_file)
# to a CSV file that contains a row per output file for every bazel target matching the given
# --whitelist_pat regular expression and not matching the --blacklist_pat.
# Each row contains the columns: target, path, and hash.
#
# Example usage:
#
# To invoke this script first generate a compact execution log with bazel using for example:
#
#   $ bazel build //rs/replica:replica --execution_log_compact_file=compact_execlog.zst
#
# Then decompress the file:
#
#   $ zstd -d compact_execlog.zst
#
# Finally build and run this script to convert the decompressed file to a CSV:
#
#   $ bazel build //bazel:execution_log_compact_to_csv && \
#     bazel-bin/bazel/execution_log_compact_to_csv \
#       --input_execlog=compact_execlog \
#       --whitelist_pat='^//'
#
#   //rs/http_endpoints/public:build_script_,bazel-out/k8-opt-exec-ST-d57f47055a04/bin/rs/http_endpoints/public/build_script_,4463251579c194bf83a24408a184da9a7f46d5777f753e33a77afa5c2287fd1d
#   //rs/http_endpoints/public:build_script,bazel-out/k8-opt/bin/rs/http_endpoints/public/build_script.out_dir/dashboard.rs,f0ba2e4976ac312782190b6391ce945f57708b46126b741f6336b355968a8a84
#   ...
#   //rs/replica:replica_lib,bazel-out/k8-opt/bin/rs/replica/libic_replica-974340861.rlib,0d45ec60aee4472020f69d0a19ac2ad4519388216f5a21e19152539fa3d0c4ce
#   //rs/replica:replica,bazel-out/k8-opt/bin/rs/replica/replica,0ecf150fbff09dc7b92ac976827fc46179561f2e8e83487840330ce247b61b5d

import argparse
import csv
import re
import sys

import google.protobuf.internal
import spawn_pb2


def main():
    parser = argparse.ArgumentParser(
        description="Convert bazel's compact execution log to a CSV file printed to stdout."
    )
    parser.add_argument(
        "--input_execlog",
        required=True,
        help="Path to the zstd _decompressed_ input file as generated with bazel's --execution_log_compact_file option.",
    )
    parser.add_argument(
        "--whitelist_pat",
        default=None,
        help="Regex to match target labels to include in the CSV. If omitted, all targets are included.",
    )
    parser.add_argument(
        "--blacklist_pat",
        default=None,
        help="Regex to match target labels to exclude from the CSV.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Log every ExecLogEntry to stderr. This is useful for debugging.",
    )
    args = parser.parse_args()

    # We intend to log the outputs of Spawns. Spawns refer to their output by ID
    # so we need to keep track of the ID to entry mapping. Important note:
    # if an entry (like a Spawn) refers to another entry (like a File or Directory)
    # it's guaranteed the latter will precede the former.
    id_to_entry = {}

    with open(args.input_execlog, "rb") as execlog_file, sys.stdout as csv_file:
        writer = csv.writer(csv_file)
        while True:
            # The execution log is a stream of protobuf messages,
            # each preceded by a varint32 denoting its length.
            msg_len = google.protobuf.internal.decoder._DecodeVarint32(execlog_file)
            if msg_len is None:
                break

            # Parse the ExecLogEntry message. For the message definition see:
            # https://github.com/bazelbuild/bazel/blob/master/src/main/protobuf/spawn.proto.
            msg_buf = execlog_file.read(msg_len)
            exec_log_entry = spawn_pb2.ExecLogEntry()
            exec_log_entry.ParseFromString(msg_buf)

            if args.verbose:
                print(exec_log_entry, file=sys.stderr)

            entry_type = exec_log_entry.WhichOneof("type")
            if entry_type in ["file", "directory"]:
                id_to_entry[exec_log_entry.id] = exec_log_entry
            elif entry_type == "spawn":
                label = exec_log_entry.spawn.target_label
                if (args.whitelist_pat is not None and not re.match(args.whitelist_pat, label)) or (
                    args.blacklist_pat is not None and re.match(args.blacklist_pat, label)
                ):
                    continue
                for output in exec_log_entry.spawn.outputs:
                    output_type = output.WhichOneof("type")
                    if output_type != "output_id":
                        continue
                    output_entry = id_to_entry[output.output_id]
                    output_entry_type = output_entry.WhichOneof("type")
                    if output_entry_type == "file":
                        writer.writerow([label, output_entry.file.path, output_entry.file.digest.hash])
                    elif output_entry_type == "directory":
                        dir_path = output_entry.directory.path
                        for dir_file in output_entry.directory.files:
                            writer.writerow([label, dir_path + "/" + dir_file.path, dir_file.digest.hash])
                    else:
                        raise ValueError(f"Unexpected output entry type: {output_entry_type}")


if __name__ == "__main__":
    main()
