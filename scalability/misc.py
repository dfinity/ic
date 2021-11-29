def get_datapoints(target_rps=500, rps_min=50, rps_max=20000, increment=50, exponent=0.5):
    """Get a distribution around target_rps from rps_min to rps_max with increasing distance between individual measurements."""
    rps = [rps_min, target_rps, rps_max]
    for inc in sorted(set([increment * round(2 ** (i * exponent)) for i in range(100)])):

        r = target_rps - inc
        if r > rps_min:
            rps.append(r)

        r = target_rps + inc
        if r < rps_max:
            rps.append(r)

    datapoints = sorted(set(rps))
    num = len(datapoints)

    print(f"Measuring {num} datapoints {datapoints}")
    return datapoints


def get_equally_distributed_datapoints(rps_min, rps_max, increment):
    """Get an equal distribution of measurements for the given configuration."""
    return range(rps_min, rps_max, increment)


def get_threshold_approaching_datapoints(threshold, num_exp_points, num_lin_points):
    """
    Use if you want to measure the behaviour when the benchmark approaches some threshold value.

    First, `num_exp_points` many measurement are taken, from `threshold / 2 ** num_exp_points` to `threshold / 2`.
    Then, `num_lin_points` many measurements are taken from `threshold / 2` to `threshold`.

    """
    datapoints = []

    for i in range(num_exp_points, 0, -1):
        datapoints.append(int(threshold / 2 ** i))

    lin_step = int(threshold / (2 * num_lin_points + 1))
    start = int(threshold / 2)

    for i in range(1, num_lin_points + 1):
        datapoints.append(start + i * lin_step)

    return datapoints
