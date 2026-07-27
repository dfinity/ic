((
# Standards & Conventions

These are enforced rules for this repo.

These rules pertain to all general-purpose programming languages. Some rules are
stated in Rust terminology, but they can usually be generalized to other
programming languages.

These rules require judgement. This does NOT imply that anything goes!
Intelligence is a FEATURE! Thanks to AI, it is now possible for machines to help
us enforce such rules. It will be a bit messy, but no rules of this kind is
worse.

Even if we say that X is "good", that does NOT mean over-do X!

## How This File Is Used

From this, two sets of Claude instructions are derived mechanically:

1. How to WRITE code.
2. How to REVIEW code.

1 is kept small to avoid overwhelming the AI. 2 is sharded out so that reviews
can be complete. To achieve 1, we put some content here between pairs of single
parentheses (for inline elisions), and pairs of double parentheses for eliding
whole swaths.

For simplicity, we require that pairs of single parentheses not be nested. This
limitation could be lifted later.

Also for simplicity, double parentheses must occur on their own line. Again,
this could be relaxed later.
))


## Basic Principles

Optimize for the reader, not the writer.

Do not assume the reader has lots of domain-specific knowledge (only GENERAL
knowledge, plus a little bit of BASIC knowledge of your domain).

> Explicit is better than implicit.
> --Zen of Python

Always be MEANINGFUL.

Lead with the lede.

(Guide the eye.)

(Idiomatic Rust is sometimes bad.)

(Likely future modifications must be easy.)

((
> Premature optimization is the root of all evil.
> --Donald Knuth
))

(All general principles of good communication apply.)

Consistency is king. This inevitably leads to a couple classes of conflicts:
1. local vs. regional or global - Local wins.
2. existing pattern vs. Standards & Conventions - Existing pattern wins. See
   "Grandfathering".

(Control access on a "need to know" basis. E.g. minimize bazel visibility.)

Data is gold. Diagnostics are diamonds.

Boring code is good.

((
Do not sweep problems under the rug.

> Errors should never pass silently.
> --Zen of Python
))


((
## Glossary

constructor - A method that returns `Self` (or `Result<Self, ...>`). In general,
    does not take `self`.

nominal behavior - What an engineered system is SUPPOSED to do. (This is not the
    same as "happy". Happy just refers to the case that you generally hope will
    occur, where there is an actual useful result.)

fixture - Same initial conditions used by multiple tests.
))


## Naming

Use real words. Use the dictionary as evidence. For example, the dictionary
knows about CPU, but it does not know that ws = white space. Exceptions (not in
the dictionary, but acceptable):
* `len`

Be as specific as possible (but not more).

Use units suffixes. (Do not abbreviate, even though there are standard
abbreviations.) Better yet, do not use raw numbers, but rather types like
`std::time::Duration`.

Use plural for collections.

Use `_count` when an integer is the number of objects (or `_len`, when the
number is the cardinality of some collection). Do NOT use plural.

Use `is_` to indicate whether some property holds.


### Banned Words

Do not use the following words (because they convey little to no information,
just like the word "marklar" in _South Park_):

* Nouns:
    * data
    * info(rmation)
    * state
    * record
* Verbs:
    * do
    * run
    * execute

Existing compound jargon (e.g. "canister state") is grandfathered in, but do not
coin new jargon from banned words.


### Functions and Methods

Function and method names must be "verb-y".
Exceptions (not verbs, according to the dictionary, but acceptable):
* `from`
* `into`
* `new`

Use `try_` to indicate `Result` is returned.

Use `${happy_behavior}_or_panic` to indicate possible panic.

Use `test_${nominal_behavior}` for tests.


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

* `ListWidgetsResponse`, or `ListWidgetsResult` if it `Ok` or `Err` can be
  returned.

Paginate `list_` APIs. (Requests must
* have `limit`
* NOT have `offset` or something like it. Instead, `exclusive_lower_bound` for
  efficiency.)


## Formatting

Locality: Use space to indicate how closely things are related to one another.

When a heading has multiple items, put a blank line after it.

When a statement spans >= 3 lines, separate it on both sides with a blank line,
unless there is a brace on the adjacent line.


## Abstraction

Abstractions must "pull their own weight".

To achieve many combinations of behaviors, rely on composition, not specialization.


## Control Flow

Keep the main path on the least amount of indentation.

> Flat is better than nested.
> --Zen of Python

Spinning out (i.e. turning a chunk of code that does some meaningful unit of
work into its own function or method) is good.

When a return condition is detected, return quickly.

When possible,
```
let Some(widget) = widget else {
    return ...
};
```
Of course, if `?` works, use that instead of this.

When calling a function, if an argument is just a literal, comment what it
signifies.

No multi-line `if` conditions. Ditto for `while`, `match`, and `for ... in`
expressions.

(Exception: when looping over a collection literal, each element can be on its
own line.)

(Branch "on" `enum`s using `match`.)

Short branch arms. (Spin out if necessary.)

(If a function has a `match` with four or more arms, it should have little if
any other code.)

(`continue` and `break` are good.)

If a return value is not used, say so explicitly. E.g.
```
let _displaced_element = map.insert(k, v);
```


## Problematic Rust Idioms

Do not directly call `into`.

More generally, leave types unmentioned only when they can be easily determined
from very nearby code. In particular, do `.collect::<Vec<Widget>>()`, not bare
`.collect()`.

Do not be afraid to use the `return` keyword.

Do not be afraid to use semicolons.

((
Do not name parameters of generics with just one letter. Instead,
```
fn f<HASHER>(hasher: HASHER)
where
    HASHER: Hasher
{ ... }
```

Do not "inline" bounds between `<...>`. Instead, use `where` (or the `formatter:
impl Formatter` shorthand if you do not need to give the type a name, and it
only needs one trait). See the previous example.
))


## Comments

The main question that doc comments MUST answer is, "How do I actually USE this
thing?". (This is usually explained by the code's behavior, not how it is
implemented.)

Define terms BEFORE using them. (E.g. the "Glossary" section above.)

More generally, in order to explain X EFFECTIVELY, you must start with things
that the reader ALREADY knows, and build up to X.

Do NOT be vacuous. (E.g. do NOT just say "validates widget". Instead, list the
properties of a "valid" widget.)

(Sometimes, the best way to explain something is by example. Sometimes, negative
examples are needed.)

(Do NOT simply transcribe code into prose. Comments ADD information that is not
"readily gleaned" from the code itself. E.g. intent.)

(Code is NOT the ultimate source of truth on nominal behavior.)


## Defining Types

No `pub` fields.
Exception: Prost, Candid.

If a basic trait makes sense, derive it, even if you are not using it yet. In
particular,
* `Debug` - For visibility.
* Construction:
    * `Default`
    * `Copy`
* Comparison:
    * `Eq`
    * `Ord`
    * `Hash`

(When inserting an object into a collection, take ownership.)


### Constructors

Avoid incomplete objects by defining constructor(s).

Supply `new` and/or `try_new`. (`new` "just assembles", and otherwise does no
"real work" besides validation.)

If you need a constructor that does "real work" (e.g. load from a file) do
NOT name the constructor `new`. (Instead, name it `from_file` or
something. The last line would generally consist of calling `new`.)


### Conversions

Implement `From`/`TryFrom` in three steps: fully disassemble, validate and
transform components, and reassemble.


## Anti-Features (not just Rust)

Do not create type aliases. (Re-exporting is acceptable.)

(To avoid name collisions when importing, use the module to disambiguate, not
alias.)


## Errors

Leave breadcrumbs. Include the offending values (not just the failure category).

List all defects in invalid data (not just the first one).


## Testing

When expecting an error, be specific.

Separate tests:
```
#[cfg(test)]
#[path = "widget_tests.rs"]
mod tests;
```

Do not assert EXACT wording of error messages. Instead, look for key words and
phrases.

If an assertion can be expressed as `assert_eq!(observed_value, ...)` do it that
way.

Explicitly have 3 top level sections (tests with <= 3 statements are exempt):
```
// Step 1: Prepare the world.
let registry = new_widgets_fixture_registry();

// Step 2: Run the code under test.
let result = insert_widget(&mut registry);

// Step 3: Verify result(s).

// Step 3.1: Inspect return value.
let widget_id = result.unwrap();

// Step 3.2: Inspect contents of registry. The widget set must be exactly the
// one we just inserted.
assert_eq!(get_widget_ids(&registry), vec![widget_id]);

// etc...
```

(Use `lazy_static!` for "constants" when you cannot define a `const` due to
limitations in `const` initialization. Do NOT define a 0-argument `fn` for this!)

((
Define your own application-specific asserts to maximize meaningfulness and
reduce tedious reading:
```
#[track_caller]
fn assert_${property}(observed, expected) { ... }
```
))


((
## Code Review Protocol

When a reviewer asks you (the author) a question, answer it via comments in the
source code itself.

Do not simply close suggestion threads. Reply. At a minimum, if you took the
suggestion, reply with "Done", or react with 👍. If you rejected, explain and
leave the thread unresolved.
))


## Grandfathering

This has been adopted without making existing code compliant. Nevertheless,
abide by "Consistency is king", as explained earlier.

You might think this would gradually lead us away from compliance. To solve
that, there will be a compliance campaign to more or less swiftly eliminate such
non-compliance.

((
Such a campaign is necessary anyway, since merely following the rules going
forward is not going to do anything about the tons of non-compliant legacy code
that we have.

Ditto for when new rules are added in the future: they will be added without
requiring that legacy code be fixed first, but there needs to be a commitment to
actually fix legacy code before adding such rules.
))
