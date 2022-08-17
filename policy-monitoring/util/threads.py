from threading import Thread


class PropagatingThread(Thread):
    """A Thread that propagates exceptions on join()"""

    def run(self):
        self.exc = None
        self.ret = None
        try:
            self.ret = self._target(*self._args, **self._kwargs)
        except BaseException as e:
            self.exc = e

    def join(self, timeout=None):
        super().join(timeout)
        if self.exc:
            raise self.exc
        return self.ret
