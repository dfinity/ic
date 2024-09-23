import os
import subprocess
from pathlib import Path


def run_command(command):
    print("Running command:", command)
    subprocess.run(command, shell=True, check=True)


def transform_yaml(input_file, output_file):
    try:
        # Explode YAML
        command = f"yq eval-all 'explode(.)' {input_file} > {output_file}"
        run_command(command)

        # Remove anchors
        command = f"yq -i eval 'del(.anchors)' {output_file}"
        run_command(command)
        print(f"Generating {output_file} from {input_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print(f"Failed to transform {input_file} to {output_file}")
        exit(1)
    except Exception as e:
        print(f"Failed with error: {e}")
        exit(1)


def main():
    github_dir = Path(__file__).parents[1]
    workflows_source = github_dir / "workflows-source"
    workflows_output = github_dir / "workflows"
    for file in os.listdir(workflows_source):
        if file.endswith(".yaml") or file.endswith(".yml"):
            input_file = workflows_source / file
            output_file = workflows_output /file
            transform_yaml(input_file, output_file)


if __name__ == "__main__":
    main()
