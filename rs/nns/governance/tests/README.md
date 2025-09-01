# NNS Testing using Fixtures

The following is a quick guide to writing NNS tests using the test fixtures
found in `fixtures.rs`.

Basically, each test has three or four basic parts:

1. If it is a `proptest`, the declaration of the test specifies which values
   will vary across different runs of the test, and the range from which those
   values are taken.

2. Each test begins by constructing an `NNSBuilder` and using it to specify
   the starting attributes of the NNS: Governance, Neurons, Ledger and
   Environment. This is completed by calling `create` to object the NNS
   fixture.

3. Write the test by performing operations against the fixture. There are
   several methods defined on the `NNS` type that are meant to offer a higher
   level interface to governance, such as `NNS::merge_maturity`. You can also
   directly manipulate the `nns.governance` object within the fixture.


## Notes

A few notes to expand upon the above:

### Builder methods

The methods to `NNSBuilder` are general designed to make it easy to
declaratively specify a starting state for the NNS. As such, they are
generally named and take arguments to allow for simpler reading of such
declarations. This means, for example, that `1` is typically used instead of
`NeuronId { id: 1}`. The same is not true for the fixture, however. Think of
this data as being used only for construction, not operation of the NNS.

### Fixture methods

Several of the methods in the `NNS` abstract command usage patterns. Rather
than repeatedly constructing `neuron_manage` arguments, for example, there is
generally a method of the same basic name as the management operation that
takes its arguments in the simplest form.

### Direct access

One can may use the `nns.governance` object within the `NNS` fixture directly,
since changes are tracked after such use. There is no harm in doing so,
although sometimes the fixture will provide a higher-level interface that
builds in certain assumptions. For example, `NNS::get_neuron` will assert if
the neuron does not exist, while `Governance::get_neuron` returns a `Result`
that must be checked for errors.

