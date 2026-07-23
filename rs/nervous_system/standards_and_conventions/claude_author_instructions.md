This file is derived mechanically from STANDARDS_AND_CONVENTIONS.md, and
tells Claude how to write code here.


## Basic Principles

Optimize for the reader, not the writer.

Do not assume the reader has lots of domain-specific knowledge.

> Explicit is better than implicit.
> --Zen of Python

Always be MEANINGFUL.

Lead with the lede.


Consistency is king. When nearby code and far away code follow different
patterns, follow the nearby code.


Data is gold. Diagnostics are diamonds.

Boring code is good.

## Naming

Use real words. Use the dictionary as evidence. For example, the dictionary
knows about CPU, but it does not know that ws = white space. Exceptions:
* `len`

Be as specific as possible.

Use units suffixes. Better yet, do not use raw numbers, but rather types like
`std::time::Duration`.

Use plural for collections.

Use `_count` when an integer is the number of objects. Do NOT use plural.

Use `is_` to indicate whether some property holds.


### Banned Words

Do not use the following words:

* Nouns:
    * data
    * info
    * state
    * record
* Verbs:
    * do
    * run
    * execute

Existing compound jargon is grandfathered in, but do not
coin new jargon from banned words.


### Functions and Methods

Function and method names must be "verb-y".
Exceptions:
* `from`
* `into`
* `new`

Use `try_` to indicate `Result` is returned.

Use `${happy_behavior}_or_panic` to indicate possible panic.

Use `test_${nominal_behavior}` for tests.


### Variables and Types

Variable and type names must be "noun-y".


Dummy variables are good. E.g.
```
let is_name_ok =
    is_long_enough(name) &&
    is_capitalized(name) &&
    ...;
```


### Remote Procedure Calls

When fetching a collection, use `list_`, not `get_`.

One input and one output object when calling remote code:

* `ListWidgetsRequest`

* `ListWidgetsResponse`, or `ListWidgetsResult` if it `Ok` or `Err` can be
  returned.

Paginate `list_` APIs.


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

Spinning out is good.

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


Short branch arms.


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

## Comments

The main question that doc comments MUST answer is, "How do I actually USE this
thing?".

Define terms BEFORE using them.

More generally, in order to explain X EFFECTIVELY, you must start with things
that the reader ALREADY knows, and build up to X.

Do NOT be vacuous.


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


### Constructors

Avoid incomplete objects by defining constructor.

Supply `new` and/or `try_new`.

If you need a constructor that does "real work" do
NOT name the constructor `new`.


### Conversions

Implement `From`/`TryFrom` in three steps: fully disassemble, validate and
transform components, and reassemble.


## Anti-Features

Do not create type aliases.


## Errors

Leave breadcrumbs. Include the offending values.

List all defects in invalid data.


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

Explicitly have 3 top level sections:
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


## Grandfathering

Making legacy code comply with these rules is its own separate effort.
