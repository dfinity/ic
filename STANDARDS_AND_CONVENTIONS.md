# Standards & Conventions

These are enforced rules for this repo.

These rules pertain to all general-purpose programming languages. Some rules
are stated in Rust terminology, but they can usually be generalized to other
programming languages.

Even if we say that X is "good", that does NOT mean over-do it!


## Basic Principles

Optimize for the reader, not the writer.

Do not assume the reader has "esoteric" knowledge, only GENERAL knowledge
with only SOME knowledge of essential/pervasive high-level concepts and terms.

> Explicit is better than implicit.
> --Zen of Python

Always be MEANINGFUL.

Lead with the lede.

Guide the eye.

Idiomatic Rust is sometimes bad.

Likely future modifications must be easy.

> Premature optimization is the root of all evil.
> --Donald Knuth

All general principles of good communication apply.

Consistency is king.

Control access on a "need to know" basis. (E.g. minimize bazel visibility.)

Data is gold.

Boring code is good.


## Naming

Use real words. Use the dictionary or encyclopedia as evidence. This includes acronyms.
Exceptions (not in the dictionary, but acceptable):
* `len`

Be as specific as possible (but not more).

Use units suffixes. (Do not abbreviate, even though there are standard abbreviations.)
Better yet, do not use raw numbers, but rather types like `std::time::Duration`.

Use plural for collections.

Use `_count` when an integer is the number of objects (or `_len`, when the
number is the cardinality of some collection). Do NOT use plural.

Use `is_` to indicate whether some property holds.


### Banned Words

Do not use the following words, because they convey little to no information
(just like the word "marklar" in _South Park_):

* Nouns:
    * data
    * info(rmation)
    * state
    * record
* Verbs:
    * do
    * run
    * execute


### Functions and Methods

Function and method names must be "verb-y".
Exceptions (not verbs, according to the dictionary, but acceptable):
* `from`
* `into`
* `new`

Use `try_` to indicate `Result` is returned.

Use `_or_panic` to indicate possible panic.


### Variables and Types

Variable and type names must be "noun-y".

(In English, adjectives come before the noun they modify, so the noun would
generally come last in a variable or type name.)

Dummy variables are good. E.g.
```
let is_name_ok =
    is_long_enough(name) &&
    is_capitalized(name) &&
    ...;
```


### Remote Procedure Calls

When fetching a collection, use `list_`, not `get_`.

One input and one output object when calling remote code (process or canister):
* `ListWidgetsRequest`
* `ListWidgetsResponse`, or `ListWidgetsResult` if it `Ok` or `Err` can be returned.

Paginate `list_` APIs. Requests must
* have `limit`
* NOT have `offset` or something like it. Instead, `exclusive_lower_bound` for efficiency.


## Formatting

Locality: Use space to indicate how closely things are related to one another.


## Abstraction

Abstractions must "pull their own weight".

To achieve many combinations of behaviors, rely on composition, not specialization.


## Control Flow

Keep the main path on the least amount of indentation.

> Flat is better than nested.
> --Zen of Python

Spinning out (i.e. turning a chunk of code that does some meaningful unit of work into
its own function or method) is good.

When a return condition is detected, return quickly.

When calling a function, if an argument is just a literal, comment what it signifies.

No multi-line `if` conditions. Ditto for `while`, `match`, and `for ... in` expressions.

Exception: when looping over a collection literal, each element can be on its own line.

Branch "on" `enum`s using `match`.

Spin out branch arms.

If a function has a `match` with four or more arms, it should have little (if any) other code.

`continue` and `break` are good.

If a return value is not used, say so explicitly. E.g. `let _maybe_replaced_element = map.insert(k, v);`.


## Problematic Rust Idioms

Do not directly call `into`.

More generally, only leave types unmentioned when they can be easily determined
from very nearby code. In particular, do `.collect::<Vec<Widget>>()`, not bare
`.collect()`.

Do not be afraid to use the `return` keyword.

Do not be afraid to use semicolons.


## Documentation

The main question that doc comments must answer is, "How do I actually USE
this thing?", or "What is the behavior here?", not "How does this achieve
the effect?".

Do NOT be vacuous.

Define terms BEFORE using them.

Code is NOT the ultimate source of truth on nominal behavior.


## Types

No `pub` fields.
Exception: Prost.

Derive as much as possible. In particular,
* `Debug` - For visibility.
* Construction:
    * `Copy`
    * `Default`
* Comparison:
    * `Eq`
    * `Ord`
    * `Hash`

When inserting an object into a collection, take ownership.


### Constructors

Supply `new`.


## Anti-Features (not just Rust)

Do not create type aliases. Re-exporting (under the exact same name) is acceptable.

To avoid name collisions when importing, use the module to disambiguate, not alias.


## Errors

Leave breadcrumbs.

List all defects in invalid data.


## Testing

Only allow EXPECTED errors to be considered passing, not just `.is_err()`.

New tests must live in separate `*_tests` (or `tests`) files.

Do not over-constrain code under test. In particular, do not assert EXACT wording
of error messages. Just look for key words and phrases.

If an assertion can be expressed as `assert_eq!(observed_value, ...)` do it that
way.
