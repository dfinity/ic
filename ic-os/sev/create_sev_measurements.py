# !/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import tempfile
from pathlib import Path
import re

# Import the generated protobuf classes
# You'll need to generate these from replica_version.proto using protoc
# protoc --python_out=. replica_version.proto
try:
    from replica_version_pb2 import GuestLaunchMeasurements, GuestLaunchMeasurement, GuestLaunchMeasurementMetadata
except ImportError:
    print("Error: Could not import protobuf classes. Please generate them from replica_version.proto:")
    print("protoc --python_out=. replica_version.proto")
    sys.exit(1)


def parse_input_file(input_file_path):
    """Parse the input.txt file to extract BOOT_ARGS_A and BOOT_ARGS_B."""
    boot_args = {}

    with open(input_file_path, 'r') as f:
        content = f.read()

    # Use regex to find BOOT_ARGS_A and BOOT_ARGS_B assignments
    boot_args_a_match = re.search(r'BOOT_ARGS_A\s*=\s*"([^"]*)"', content)
    boot_args_b_match = re.search(r'BOOT_ARGS_B\s*=\s*"([^"]*)"', content)

    if not boot_args_a_match or not boot_args_b_match:
        raise ValueError("BOOT_ARGS_A or BOOT_ARGS_B not found in input file")

    boot_args['BOOT_ARGS_A'] = boot_args_a_match.group(1)
    boot_args['BOOT_ARGS_B'] = boot_args_b_match.group(1)

    return boot_args


def run_sev_snp_measure(ovmf_path, kernel_path, initrd_path, boot_args):
    """Run sev-snp-measure command and return the measurement."""
    cmd = [
        'sev-snp-measure',
        '--mode', 'snp',
        '--vcpus', '64',
        '--ovmf', ovmf_path,
        '--vcpu-type', 'EPYC-Milan',
        '--append', boot_args,
        '--initrd', initrd_path,
        '--kernel', kernel_path
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # The measurement is typically hex-encoded, we need to convert to bytes
        measurement_hex = result.stdout.strip()
        # Remove any whitespace and convert hex to bytes
        measurement_hex = re.sub(r'\s+', '', measurement_hex)
        measurement_bytes = bytes.fromhex(measurement_hex)
        return measurement_bytes
    except subprocess.CalledProcessError as e:
        print(f"Error running sev-snp-measure: {e}")
        print(f"stdout: {e.stdout}")
        print(f"stderr: {e.stderr}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error converting measurement to bytes: {e}")
        print(f"Raw output: {result.stdout}")
        sys.exit(1)


def create_guest_launch_measurements(measurements_data):
    """Create GuestLaunchMeasurements protobuf message."""
    guest_launch_measurements = GuestLaunchMeasurements()

    for boot_args, measurement_bytes in measurements_data:
        # Create measurement metadata
        metadata = GuestLaunchMeasurementMetadata()
        metadata.kernel_cmdline = boot_args

        # Create guest launch measurement
        measurement = GuestLaunchMeasurement()
        measurement.measurement = measurement_bytes
        measurement.metadata.CopyFrom(metadata)

        # Add to the list
        guest_launch_measurements.guest_launch_measurements.append(measurement)

    return guest_launch_measurements


def main():
    parser = argparse.ArgumentParser(
        description='Generate SEV-SNP measurements and create protobuf output'
    )
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Path to input.txt file containing BOOT_ARGS_A and BOOT_ARGS_B'
    )
    parser.add_argument(
        '--ovmf',
        required=True,
        help='Path to OVMF file (input_ovmf.fd)'
    )
    parser.add_argument(
        '--initrd',
        required=True,
        help='Path to initrd file (extracted_initrd.img)'
    )
    parser.add_argument(
        '--kernel',
        required=True,
        help='Path to kernel file (extracted_vmlinuz)'
    )
    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Output path for the protobuf file'
    )

    args = parser.parse_args()

    # Validate input files exist
    for file_path, name in [
        (args.input, 'input file'),
        (args.ovmf, 'OVMF file'),
        (args.initrd, 'initrd file'),
        (args.kernel, 'kernel file')
    ]:
        if not os.path.exists(file_path):
            print(f"Error: {name} '{file_path}' does not exist")
            sys.exit(1)

    # Parse input file to get boot arguments
    boot_args_dict = parse_input_file(args.input)
    print(f"Found boot arguments: {list(boot_args_dict.keys())}")

    # Generate measurements for each boot argument
    measurements_data = []

    for boot_args_name, boot_args_value in boot_args_dict.items():
        print(f"Generating measurement for {boot_args_name}...")
        measurement_bytes = run_sev_snp_measure(
            args.ovmf,
            args.kernel,
            args.initrd,
            boot_args_value
        )
        measurements_data.append((boot_args_value, measurement_bytes))
        print(f"Generated measurement for {boot_args_name}: {len(measurement_bytes)} bytes")

    # Create protobuf message
    guest_launch_measurements = create_guest_launch_measurements(measurements_data)

    # Write to output file
    try:
        with open(args.output, 'wb') as f:
            f.write(guest_launch_measurements.SerializeToString())
        print(f"Successfully wrote GuestLaunchMeasurements to {args.output}")
        print(f"Total measurements: {len(guest_launch_measurements.guest_launch_measurements)}")
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
