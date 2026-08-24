This file is derived mechanically from STANDARDS_AND_CONVENTIONS.md, and
tells Claude how to write code here.

Since it is difficult to keep all these rules in mind while writing,
after a first draft, review for compliance of newly drafted code against
these rules.

## Basic Principles

Optimize for the reader, not the writer. Correct behavior is NOT enough. The
compiler accepts it is NOT enough.

Do not assume the reader has lots of domain-specific knowledge.

> Explicit is better than implicit.
> --Zen of Python

Always be MEANINGFUL.


Lead with the lede. Do not bury the lede with secondary facts.


Consistency is king. This inevitably leads to a couple classes of conflicts:
1. local vs. regional or global - Local wins.
2. existing pattern vs. Standards & Conventions - Existing pattern wins. See
   "Grandfathering".


Data is gold. Diagnostics are diamonds.

Boring code is good.

Do not sweep problems under the rug.

> Errors should never pass silently.
> --Zen of Python

Do not optimize uncommon cases. Here, "optimize" more refers to making code more
concise. To know how common something is, you need to MEASURE it.
Support future evolution.
## About Your Audience

To write well, you must understand your audience. You have two audiences:

1. The compiler.
2. Software engineers.

This document is focused on the second audience. What makes the second audience
special is intelligence. The important thing to remember about intelligence is
that it is absolutely NOT omniscience! Sure, an intelligent software engineer
knows how to program well, but they do NOT know all the intricacies of your
domain. They know `match`, for example, but they do NOT COMPREHENSIVELY know the
standard library, only the frequently used parts.

## Naming

This is where "Always be MEANINGFUL" really really happens. Name things after
WHAT they represent, not HOW they are being represented. For example, if you are
talking about the amount of time before giving up, call it `timeout`, not `duration`.

Use real words. Use the dictionary as evidence. For example, the dictionary
knows about CPU, but it does not know that ws = white space. Exceptions:
* `len`
* `new` as a verb.

Be as specific as possible, but not more.
When a type is generic, do not
name things after their type. See the earlier example with `timeout` vs.
`duration`.

When a type is specific, it is usually named after a concept in your domain. In
this case, it might make sense to name variables after their type. However, if
there are multiple variables of the same type, then it is very often the case
that they play distinct roles in the calculation, meaning that you couldn't just
swap them and still get an acceptable result. In that case, their names must
reflect their distinct roles.
Use units suffixes. Do not abbreviate. Better yet, do not use raw numbers, but rather types like
`std::time::Duration`. In Candid and Protocol Buffers, this is not possible
.

Use plural for non-map collections.

Use `_count` when an integer is the number of objects, or `_len`, when the
number is the cardinality of some collection. Do NOT use plural.

Use `parent_to_child_names` for maps like `BTreeMap<String, String>`. Notice
that the name is NOT necessarily of the form `${key_type}_to_${value_type}`. See
earlier rules about not naming things after their type.

Use `is_` to indicate whether some property holds.

### Banned Words

Do not use the following words:

* Nouns:
    * data
    * information
    * state
    * record
* Verbs:
    * do
    * run
    * execute
    * calculate

Existing compound jargon is grandfathered in, but do not
coin new jargon from banned words.


### Functions, Methods, and Commands

Function and method names must be "verb-y".
Exceptions:
* `from`
* `into`
* `new`

Use `try_` to indicate `Result` is returned.

Use `${happy_behavior}_or_panic` to indicate possible panic.

Use `test_${nominal_behavior}` for tests.

When a verb can easily be applied to other things, include the direct object in
the name. For example, do not name a method `get`. This can be applied to
literally anything! Instead, name it `get_inner`. Ditto for
`${VERB}er` nouns: do not name something `coordinator`. Coordinator OF WHAT? All
sorts of things can be coordinated, and you do not support most of them.
Instead, `cansiter_migration_coordinator`. Yes, that is a mouthful, but much
more time will be wasted by later readers trying to figure out, "ok, but WHAT is
being coordinated here?". They cannot recover that from your silence, except at
great cost. Elision is generally an optimization for the writer, not the reader.


### Variables and Types

Variable and type names must be "noun-y".


Dummy variables are good. E.g.
```
let is_name_ok =
    is_long_enough(name) &&
    is_capitalized(name) &&
    ...;
```

When converting, recycle the name. Do not name the result after the new type.
```
// 🙅 BAD
let pb_widget = pb::Widget::from(widget);
```
Instead,
```
// 👍 GOOD
let widget = pb::Widget::from(widget);
```
Exception: you need both the original type and the new type, but this is rare,
and suggests that you are doing something wrong.


### Remote Procedure Calls

When fetching a collection, use `list_`, not `get_`.

One input and one output object when calling remote code:

* `ListWidgetsRequest`

* `ListWidgetsResponse`, or `ListWidgetsResult` if it `Ok` or `Err` can be
  returned.

Paginate `list_` APIs.


## Formatting

Obey the principle of locality: Closely related things must be close together
AND unrelated things must be farther away from each other. Use space to create separation. Blank lines != gold bars. We have large screens
now!

When a heading has multiple items, put a blank line after it.

When a statement spans >= 3 lines, separate it on both sides with a blank line,
unless there is a brace on the adjacent line.

Do not be stingy with vertical space.

Use parentheses to indicate order of operations, unless the order of operations
is "well-known". E.g. it is fine to omit parenthes `y == m * x + b`, because it
has been beaten into us since childhood that `*` is stronger than/takes
precedence over `+`.
### Front Matter

Import things at the top of the file.

At least in Rust, do NOT refer to things from other crates/modules via qualified
names.

Exception to the previous rule: if the unqualified name is easily confused, then
DO qualify using one or more of its parent module.
```
use food::fruit::{
    self, // This lets us refer to food::fruit using just fruit.
    use_of_this_is_not_shown,
};

fn send_request() {
    // Here, instead of bare Request, we qualify it with fruit.
    let fruit_request = fruit::Request::new(...);
    ...
}
```
For example, if the name is a common word, or if the name is used by other
crates, then qualifying is helpful to the reader. Do NOT
give things alternative names!

Consolidate `use`s. rustfmt does NOT enforce this.

Do not use blank lines to group `use`s. rustfmt does NOT enforce this.


## Abstraction

Abstractions must "pull their own weight". If it is not frequently used, and
saves very little code, do not use it. This ALSO applies to the standard
library.
To achieve many combinations of behaviors, composition primitives, do not not
invent new specializations.


## Control Flow

Keep the main path on the least amount of indentation.

> Flat is better than nested.
> --Zen of Python

It is good to spinning out. Do not inline.

When a return condition is detected, return quickly. This is where `return` and
`?` become highly effective. In particular, avoid continuing the dot chain. Also in particular, do not do
```
// 🙅 BAD
if ok {
    next_step()
    next_next_step()
    ...
    Ok(result)
} else {
    // This is far away from where it was detected that we can return!
    Err(blah)
}
```
Instead,
```
// 👍 GOOD
if !ok {
    // This goes STRAIGHT from detection to returning!
    return Err(blah);
}

next_step();
next_next_step();
...

Ok(result)
```
Notice how this results in following the first rule in this section, i.e. "Keep
the main path on the least amount of indentation.".
`?` must appear at the end of a line, not in the
middle. It is fine if comments appear after `?`.
When calling a function, if an argument is just a literal, comment what it
signifies.

No multi-line `if` conditions. Ditto for `while`, `match`, and `for ... in`
expressions.


In a boolean expression, strongly avoid mixing `!`, `&&`, and `||`. Use only one
of these within the same expression. This can usually be accomplished using a
combination of De Morgan's Law and dummy variables.
Splitting a big boolean expression tends to work well when validating data,
because you often have many requirements.


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

When defining a trait do NOT name it after its one method.


## Comments

The main question that doc comments MUST answer is, "How do I actually USE this
thing?". This is usually explained by the code's behavior, what actually
happens. In particular, do NOT explain how it is implemented.

Define terms BEFORE using them.

More generally, in order to explain X EFFECTIVELY, you must start with things
that the reader ALREADY knows, and build up to X.

Do NOT be vacuous.


## Defining Types

No `pub` fields. Grandfathered exception: Prost, Candid.

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

If many pieces are required to assemble an object, since Rust is not yet
civilized enough to have named arguments, ou might have to grudgingly use the
builder pattern.
Supply `new` and/or `try_new`. These just assembles, and otherwise does no "real
work" such as reading a file other than validation.

If you need a constructor that does "real work" do NOT
name the constructor `new`. Instead, name it `load_from_file` or something. The
last line would generally consist of calling `new`.


### Conversions

Convert in three steps:
1. Fully disassemble.
2. Validate and transform components.
3. Reassemble.
Step 2 is where the "real work" happens.
Match the call tree to the type definition tree. Do not inline conversion of
composite members.
This also applies to validation.


## Anti-Features

Do not create type aliases.


## Errors

Leave breadcrumbs. Include the offending values.

List ALL defects in invalid data, not just the first one.
```
impl Plane {
    fn validate(&self) -> Result<(), InvalidPlane> {
        let mut defects = vec![];

        ... populate_defects ...

        if !defects.is_empty() {
            return Err(InvalidPlane(defects))
        }

        Ok(())
    }
}
```
In general, assume that more ways to fail will be added later. That should not
be a breaking change.
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

Use `lazy_static!` for "constants" when you cannot define a `const` due to
limitations in `const` initialization. Do NOT define a 0-argument `fn` for this!

## Code Review Protocol

When a reviewer asks you a question about the code you wrote,
answer it via comments in the source code itself.

Do not simply close suggestion threads. Reply. At a minimum, if you took the
suggestion, reply with "Done", or react with 👍. If you rejected, explain and
leave the thread unresolved.


## Grandfathering

This has been adopted without making existing code compliant. Nevertheless,
abide by "Consistency is king", as explained earlier.

You might think this would gradually lead us away from compliance. To solve
that, there will be a compliance campaign to more or less swiftly eliminate such
non-compliance.
