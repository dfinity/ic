# The Fondue Framework

## DISCLAIMER: Currently intended for internal consumption; will be turned public in a few weeks.

The two main features of `fondue` are:

1. Separate setups from tests. In a distributed system, setting everything up is often an expensive operaton.
We want to be able to test against the same setup as much as possible.
2. Enable a composable _passive testing_ plugin. Think of it as using log analysis to enforce certain
expectations, or to monitor memory usage and detect leaks.

The `fondue` framework will be the underlying driver of our generation-two testing
framework. Please refer to the notion page for broader information:

https://www.notion.so/Gen-II-Testing-Framework-22ccf750bb8844ea9fd3af18309914bf

## Why call it `fondue`?

This project was heavily inspired and by the excellent `raclette` testing harness and we chose
`fondue` as name as tribute to `raclette` and a intuitive description of the difference between the
two projects. In a raclette, everyone's cheese is kept isolated. In a fondue, the cheese 
is mixed and everyone eats from the same pot.
