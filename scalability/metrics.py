class Metric(object):
    """Base class for all types of metrics."""

    def __init__(self, name, target, do_instrument):
        """Init Metric."""
        self.name = name
        self.target = target
        self.do_instrument = do_instrument

    def init(self):
        """
        Init the metrics.

        Called once at the beginning of the bnechmark.
        """
        print("{} initialized".format(self.name))

    def start_iteration(self, outdir):
        """Benchmark iteration is started."""
        print("{} starting".format(self.name))

    def end_iteration(self, exp):
        """Benchmark iteration is started."""
        print("{} ending".format(self.name))
