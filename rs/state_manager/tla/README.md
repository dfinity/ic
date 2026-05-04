# A high-level TLA+ model of the state manager <-> consensus interaction

The main file is `Abstract_Combined_SM.tla`. Analyze it against:
1. `Optimized_Abstract_Combined_SM_Safety.cfg` to check the main properties; toggle the parameters as you see fit, but note that, if divergence is enabled, it doesn't make sense to check for No_Deadlock. Note that this can be very slow to run; with divergence enabled, expect the analysis to take a couple of weeks (!) with 7 blocks and a checkpoint interval of 2.
2. `Optimization_Correctness.cfg` to check that some of the optimizations made in the model are correct

`Abstract_Replicated_SM.tla` contains an abstract model of the subnet, and Abstract_Node_SM contains the state machine bits that execute on a single replica, without interacting with the rest of the subnet.

To run the model, you can follow the [instructions](https://github.com/dfinity/formal-models/tree/master/tla) in the `formal-models` repo.
