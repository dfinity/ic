# Testing Infrastructure: `ic-fondue`

This crate is responsible for starting an IC, managing it, and providing
the infrastructure to talk to it.

A good bunch of the underlying work is done by the `fondue` crate, which currently
sits in here, but will later be extracted as an independent general-purpose library.
Don't include anything IC-specific in there!
