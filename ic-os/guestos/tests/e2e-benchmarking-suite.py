#!/usr/bin/env python3
import sys

import gflags
import ictools
import vmtools

FLAGS = gflags.FLAGS

gflags.DEFINE_string("ic_workload_generator_bin", None, "ic-workload-generator binary")
gflags.MarkFlagAsRequired("ic_workload_generator_bin")
gflags.DEFINE_string("disk_image", None, "Path to disk image to use for VMs")
gflags.MarkFlagAsRequired("disk_image")


def main(argv):
    sys.path.insert(1, ".")
    import experiment
    import run_experiment_1

    argv = FLAGS(argv)

    machines = vmtools.pool().request_machines(
        [
            {"name": "node0", "ram": "4G", "disk": "100G", "cores": 1},
            {"name": "node1", "ram": "4G", "disk": "100G", "cores": 1},
        ],
    )

    system_image = vmtools.SystemImage.open_local(FLAGS.disk_image)

    ic_config = ictools.ic_prep(
        subnets=[[machines[0].get_ipv6()], [machines[1].get_ipv6()]],
        version=ictools.get_disk_image_version(system_image),
        root_subnet=0,
    )

    machine_config_images = [
        ictools.build_ic_prep_inject_config(machines[n], ic_config, n, ictools.build_ssh_extra_config())
        for n in range(2)
    ]

    vmtools.start_machines(
        [(machine, system_image, config_image) for machine, config_image in zip(machines, machine_config_images)],
        start_ssh_log_streaming=True,
    )

    ic_url = "http://[%s]:8080" % machines[0].get_ipv6()
    ictools.wait_http_up(ic_url)
    ictools.nns_install(ic_config, ic_url)

    FLAGS.workload_generator_machines = str(machines[1].get_ipv6())
    FLAGS.targets = str(machines[0].get_ipv6())
    FLAGS.num_workload_generators = 1
    FLAGS.nns_url = ic_url
    FLAGS.no_flamegraphs = True
    FLAGS.no_prometheus = True
    FLAGS.skip_generate_report = True
    experiment.parse_command_line_args()

    exp = run_experiment_1.Experiment1()
    exp.start_experiment()
    failure_rate, t_median, _, _, _, _, num_succ, _ = exp.run_experiment(
        {
            "load_total": 10,
            "duration": 10,
        }
    )

    exp.end_experiment()

    machines[0].stop()
    machines[1].stop()


if __name__ == "__main__":
    main(sys.argv)
