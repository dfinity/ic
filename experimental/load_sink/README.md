# tl;dr: Workload generator is probably skewing results

This repo contains a load-sink. It accepts any URL and returns a CBOR
body with an incrementing counter. So you can use it with a regular HTTP
load tester, or you can use it with `ic-workload-generator.`

The load-sink is multi-threaded, compile it with a different value for the
`THREAD_COUNT` constant to change the number of threads it uses for
incoming requests.

I've done a couple of tests. They're quick-and-dirty (my laptop was doing
other things at the time) but they should be comparable against each other.

## Set up

In one terminal run `cargo run --release` in this directory to launch the
load-sink.

## Results using `hey`

`hey` is an HTTP load tester, see https://github.com/rakyll/hey.

On a Mac, `brew install hey`

I ran the following to get a baseline of how fast the load-sink can respond.

```
hey -z 20s -m GET http://localhost:8080
```

This will run for 20 seconds, running 50 separate worker threads to send
requests.

The results I got:

```
Summary:
  Total:	20.0037 secs
  Slowest:	0.2488 secs
  Fastest:	0.0001 secs
  Average:	0.0012 secs
  Requests/sec:	41197.7139

  Total data:	26371392 bytes
  Size/request:	32 bytes

Response time histogram:
  0.000 [1]	|
  0.025 [820206]|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.050 [3339]	|
  0.075 [404]	|
  0.100 [107]	|
  0.124 [24]	|
  0.149 [12]	|
  0.174 [7]	|
  0.199 [2]	|
  0.224 [1]	|
  0.249 [3]	|


Latency distribution:
  10% in 0.0002 secs
  25% in 0.0002 secs
  50% in 0.0004 secs
  75% in 0.0009 secs
  90% in 0.0020 secs
  95% in 0.0040 secs
  99% in 0.0172 secs

Details (average, fastest, slowest):
  DNS+dialup:	0.0000 secs, 0.0001 secs, 0.2488 secs
  DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0039 secs
  req write:	0.0000 secs, 0.0000 secs, 0.1400 secs
  resp wait:	0.0010 secs, 0.0001 secs, 0.2355 secs
  resp read:	0.0001 secs, 0.0000 secs, 0.2161 secs

Status code distribution:
  [200]	824106 responses
```

So the load-sink processed 824,106 requests, returned `200` response codes
for all of them, at a shade over 41,000 requests per second.

I had top(1) running during this period, `hey` and `load-sink` are the
top two programs running. 

## Results using the workload generator

We know the load-sink can sustain 40K+ of requests per second, so I ran
the load generator asking for the same numbers.

```
cargo run --release -- --canister-id ic:2A012B -n 20 -r 40000 http://localhost:8080
```

[Note: That was an OK canister at the time of writing, now you use `aaaaa-aa`]

There's nothing special about the canister ID, it just needs to be something
that parses as a valid canister ID.

That didn't finish in 20s, and was very slow.

I eventually had to scale back to 20s of 500 requests per second to get
meaningful data.

```
requested: 500 - achieved: 400, 🚀 Max counter value seen: 3071112 - submit failures: 0 - wait failures: 579
Summary
  Average:   439.757682 ms (std: 701.057054 ms)
  Median:    321.50819 ms
  Longest:   5663.627248 ms
  Shortest:  4.877121 ms
  Requests:  10000
  Data:      36.80 KB

Status codes:
  0: 579
  200: 9421
```

As you can see the results are very different.

I had top(1) running this period. The workload generator shows up as the 
program consuming the most CPU, but the load-sink did not, leading me to
believe that the limiting factor is how fast the workload generator can
send messages.

## Possible reasons for the difference

The workload generator is a lot more verbose about what it's doing. If you
run `hey` it doesn't print anything until it has finished. Terminal IO is
*slow*, that's probably got something to do with it.

I suspect the generator is inspecting the validity of each response during
the benchmark. That takes time. It should probably save all the responses
it's received until the benchmark is complete, and *then* process them to
determine if they were valid or not.

It may well also be constructing each message as it needs it (including
any expensive operations like crypto). Don't do that, construct all the
messages before starting the benchmark, and then send the pre-constructed
messages.

Other than that the generator will need to be instrumented to find out
where it's spending its time.

# Addenda

## What if `indicatif` is disabled?

Tried that (comment out the relevant calls in `collector.rs`) but it doesn't
appear to have a significant effect.
