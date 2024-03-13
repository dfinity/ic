import os
import subprocess
from pathlib import Path


def join_path(*args):
    return os.path.join(*args)

# Todo: add linting and testing
def transform_yaml(input_file, output_file):
    try:
        # Explode YAML
        command = f"yq eval-all 'explode(.)' {input_file} > {output_file}"
        print("Running command:", command)
        subprocess.run(command, shell=True, check=True)

        # Remove anchors
        command = f"yq -i eval 'del(.anchors)' {output_file}"
        print("Running command:", command)
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print(f"Failed to transform {input_file} to {output_file}")
        exit(1)
    # Todo: handle additional errors


def main():
    github_dir = Path(__file__).parents[1]
    #Todo: setup config file with paths
    workflows_source = join_path(github_dir, "workflows-source")
    workflows_output = join_path(github_dir, "workflows")
    for file in os.listdir(workflows_source):
        if file.endswith(".yaml") or file.endswith(".yml"):
            input_file = join_path(workflows_source, file)
            output_file = join_path(workflows_output, file)
            transform_yaml(input_file, output_file)


if __name__ == "__main__":
    main()
