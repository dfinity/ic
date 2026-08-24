((
# Standards & Conventions

These rules are enforced by AI.

These rules pertain to all general-purpose programming languages. Some rules are
stated in Rust terminology, but they can usually be generalized to other
programming languages.

These rules require judgement. This does NOT imply that anything goes!
Intelligence is a FEATURE! Thanks to AI, it is now possible for machines to help
us enforce such rules. It will be a bit messy, but this is better than no rules.
What this really means is, if a rule seems to inevitably lead to "hideous"
contortions, then, you might have to break the rule. However, this is rare. Do
not chop the baby with a sword.


## How This File Is Used

From this, two sets of Claude instructions are derived mechanically:

1. How to WRITE code.
2. How to REVIEW code.

1 is kept small to avoid overwhelming the Claude. 2 is sharded out so that
reviews can be complete.

### What is up with all these parentheses??

To achieve 1, we put some content here between pairs of single parentheses (for
inline elisions), and pairs of double parentheses for eliding whole swaths.

For simplicity, we require that pairs of single parentheses not be nested. This
limitation could be lifted later.

Also for simplicity, double parentheses must occur on their own line. Again,
this could be relaxed later.
))


## Basic Principles

Optimize for the reader, not the writer. Correct behavior is NOT enough. The
compiler accepts it is NOT enough.

Do not assume the reader has lots of domain-specific knowledge (only GENERAL
knowledge, plus a little bit of BASIC domain knowledge).

> Explicit is better than implicit.
> --Zen of Python

Always be MEANINGFUL.


Lead with the lede. Do not bury the lede with secondary facts.
((
Do not give equal air time to supporting characters. Rather, identify the MAIN
idea(s), and make them SHINE, and relegate the rest to less prominent positions.
))

(Guide the eye.)

(Idiomatic Rust is sometimes bad.)

(Likely future modifications must be easy.)

(All general principles of good communication apply.)

Consistency is king. This inevitably leads to a couple classes of conflicts:
1. local vs. regional or global - Local wins.
2. existing pattern vs. Standards & Conventions - Existing pattern wins. See
   "Grandfathering".

(Control access on a "need to know" basis. E.g. minimize bazel visibility.)

Data is gold. Diagnostics are diamonds.

Boring code is good.

Do not sweep problems under the rug.

> Errors should never pass silently.
> --Zen of Python

Do not optimize uncommon cases. Here, "optimize" more refers to making code more
concise (of course, reducing CPU and RAM load is still included in what not to
optimize). To know how common something is, you need to MEASURE it.
((    
[Sourcegraph] is a good tool for measuring frequency, because you can share URLs
as evidence.

[Sourcegraph]: https://sourcegraph.com/search?q=repo:%5Egithub%5C.com/dfinity/ic%24&patternType=regexp&case=yes&sm=0

> Premature optimization is the root of all evil.
> --Donald Knuth
))

Support future evolution.
((
E.g. old code must still be able to decode new data. In particular, support
deleting fields (often, replaced with a new one). Support new errors.
))


## About Your Audience

To write well, you must understand your audience. You have two audiences:

1. The compiler.
2. Software engineers (and AI).

This document is focused on the second audience. What makes the second audience
special is intelligence. The important thing to remember about intelligence is
that it is absolutely NOT omniscience! Sure, an intelligent software engineer
knows how to program well, but they do NOT know all the intricacies of your
domain. They know `match`, for example, but they do NOT COMPREHENSIVELY know the
standard library, only the frequently used parts.

((
Here is a concrete image of what "intelligent software engineer" looks like:
summer intern who joined a couple weeks ago, and has gone through basic
training. In general, they have done well in their Computer Science courses (or
have equivalent experience), passed the interviews, been introduced to what the
company does, what your team does, but that's it. They haven't read all your
code. They maybe just taught themselves Rust. If they are REALLY smart, they are
no longer wrestling with the borrow checker every 5 minutes. But that's it. They
don't know WTF a "private neuron" is, even though it is a publicly documented
feature. They don't know that `.ok()` does NOT return `Ok`, even though it is in
the standard library. Lack of such knowledge != lack of intelligence!
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

This is where "Always be MEANINGFUL" really really happens. Name things after
WHAT they represent, not HOW they are being represented. For example, if you are
talking about the amount of time before giving up, call it `timeout` (this is
the WHAT), not `duration` (this tells us HOW you are implementing it, to wit,
`std::time::Duration`).

((
<!-- TODO: Transplant to rationale file(s) -->
Names are where languages allows us to specify the intended/nominal behavior. If
something is named `x` or whatever, it is vacuously not incorrect, but that is
an exceedingly low bar. What we are shooting for is code that is self-evidently
correct. For example,
```
fn calculate_stuff(a: f64, b: f64) -> {
    a + b
}
```
is just as correct as
```
fn calculate_stuff(a: f64, b: f64) -> {
    sqrt(
        a * a
          +
        b * b
    )
}
```
even though the behaviors are completely different. They are equally correct,
because the names promise absolutely NOTHING. Without promises, there is NO
value. Correct naming prevents this. The original sin here is that the names are
devoid of MEANING. By contrast, there is a big CORRECTNESS difference between
```
fn hypotenuse_length_m(leg_a_length_m: f64, leg_b_length_m: f64) -> {
    // THIS INCURS EUCLID'S WRATH! YOU SHALL BURN IN THE FIERY DEPTHS OF
    // HADES FOR ALL ETERNITY TO ATONE FOR THIS OUTRAGEOUS SIN AGAINST
    // ALMIGHTY GEOMETRY!
    leg_a_length + leg_b_length
}
```
vs.
```
fn hypotenuse_length_m(leg_a_length_m: f64, leg_b_length_m: f64) -> {
    // Euclid is appeased by this.
    sqrt(
        leg_a_length_m * leg_a_length_m
            +
        leg_b_length_m * leg_b_length_m
    )
}
```
The latter is correct, because the behavior _lives up to the name_. Names are
not just "helpful" to weak human brains. To the contrary, they are assertions
that only intelligent beings can evaluate. By contrast, a compiler cannot
evaluate such assertions precisely because compilers are free of intelligence.
))

Use real words. Use the dictionary as evidence. For example, the dictionary
knows about CPU, but it does not know that ws = white space. Exceptions (not in
the dictionary, but acceptable):
* `len`
* `new` as a verb (in standard English, it's an adjective).

Be as specific as possible, but not more.
((
E.g.
```
// 🙅 BAD
let vehicle = Rocket::new(...);
vehicle.launch();

// Also 🙅 BAD, but in the opposite way.
fn repair(rocket: impl Vehicle) { ... }
```
))

When a type is generic (in the dictionary sense, not the Rust sense), do not
name things after their type. See the earlier example with `timeout` vs.
`duration`.

When a type is specific, it is usually named after a concept in your domain. In
this case, it might make sense to name variables after their type. However, if
there are multiple variables of the same type, then it is very often the case
that they play distinct roles in the calculation, meaning that you couldn't just
swap them and still get an acceptable result. In that case, their names must
reflect their distinct roles.
((
```
// 🙅 BAD
let employee = Employee::new("pointy haired boss");
let other_employee = Employee::new("Dilbert");

// You cannot swap the two employees here. Dilbert doesn't order the point
// haired boss around! They cannot be swapped because the two `Employee`s
// play different ROLES in this "calculation".
employee.give_orders(other_employee);
```
```
// 👍 GOOD
let boss = Employee::new("pointy haired boss");
let subordinate = Employee::new("Dilbert");

// Because the variable names reflect the roles of the two Employees,
// this code not only behaves as intended, it looks correct, and relatedly,
// is easy for the reader to verify.
boss.give_orders(subordinate);
```
Notice how these names identify the ROLE that the two `Employee`s play, their
relationship to one another. Of course, in this case, no need for the variable
names to mention `employee`, since `boss` and `subordinate` are just special
cases of the more general concept.
))

Use units suffixes. Do not abbreviate (even though there are standard
abbreviations). Better yet, do not use raw numbers, but rather types like
`std::time::Duration`. In Candid and Protocol Buffers, this is not possible
(which is deeply unfortunate).

Use plural for non-map collections.

Use `_count` when an integer is the number of objects, or `_len`, when the
number is the cardinality of some collection. Do NOT use plural.

Use `parent_to_child_names` for maps like `BTreeMap<String, String>`. Notice
that the name is NOT necessarily of the form `${key_type}_to_${value_type}`. See
earlier rules about not naming things after their type.

Use `is_` to indicate whether some property holds.

### Banned Words

Do not use the following words when naming things, because they convey little to
no information, just like the word "marklar" in _South Park_:

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
    * process

((
These words are like "stuff" in English: unless you mean literally ANYTHING,
there is a much more specific word than "stuff" for what you ACTUALLY meant.
E.g. "I am eating stuff." vs. "I am eating desert." is the actually meaningful
way of answering, "What phase of the meal are you in?"
))

Existing compound jargon (e.g. "canister state") is grandfathered in, but do not
coin new jargon from banned words.


### Functions, Methods, and Commands

Function and method names must be "verb-y".
Exceptions (not verbs, according to the dictionary, but acceptable):
* `from`
* `into`
* `new`

Use `try_` to indicate `Result` is returned.

Use `${happy_behavior}_or_panic` to indicate possible panic.

Use `test_${nominal_behavior}` for tests.

((
`get_` means it is cheap, like reading a `struct` field. It does NOT construct
a new thing. That's what `new_` is for. Meanwhile, `fetch_` means it's more
expensive, like accessing something over the Internet.

Names of getters can elide the `get_` prefix entirely.
<!-- TODO: Ok, but let's have a consistent rule on naming getters: either Java style, or Google style. -->
))

When a verb can easily be applied to other things, include the direct object in
the name. For example, do not name a method `get`. This can be applied to
literally anything! Instead, name it `get_inner` (or just `inner`). Ditto for
`${VERB}er` nouns: do not name something `coordinator`. Coordinator OF WHAT? All
sorts of things can be coordinated, and you do not support most of them.
Instead, `cansiter_migration_coordinator`. Yes, that is a mouthful, but much
more time will be wasted by later readers trying to figure out, "ok, but WHAT is
being coordinated here?". They cannot recover that from your silence, except at
great cost. Elision is generally an optimization for the writer, not the reader.


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

One input and one output object when calling remote code (process or canister):

* `ListWidgetsRequest`

* `ListWidgetsResponse`, or `ListWidgetsResult` if it `Ok` or `Err` can be
  returned.

Paginate `list_` APIs. (Requests must
* have `limit`
* NOT have `offset` or something like it. Instead, `exclusive_lower_bound` for
  efficiency.)


## Formatting

Obey the principle of locality: Closely related things must be close together
AND unrelated things must be farther away from each other.
((
E.g. if a comment refers to one line within a multi-line statement, put the
comment directly above the line it is talking about, not before the entire
statement.
))

Blank lines are a good way to create separation. Do not be stingy with blank
lines.

When a heading has multiple items, put a blank line after it.

When a statement spans >= 3 lines, separate it on both sides with a blank line,
unless there is a brace on the adjacent line.

Use parentheses to indicate order of operations, unless an elementary school
student can determine the order of operations. E.g. `y == m * x + b` is fine.
((
This is because it has been beaten into us since childhood that `*` is stronger
than/takes precedence over `+`. Other than that, just because the compiler
considers such parentheses superfluous does NOT mean they are superfluous to
intelligent beings.
))


### Front Matter

Import things (via `use`) at the top of the file.

At least in Rust, do NOT refer to things from other crates/modules via qualified
names.

Exception to the previous rule: if the unqualified name is easily confused, then
DO qualify using one or more of its parent module(s).
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
crates (including this one), then qualifying is helpful to the reader. Do NOT
give things alternative names!

Consolidate `use`s. rustfmt does NOT enforce this.

Do not use blank lines to group `use`s. rustfmt does NOT enforce this.


## Abstraction

Abstractions must "pull their own weight". If it is not frequently used, and
saves very little code, do not use it. This ALSO applies to the standard
library.
((
For example, do not do `some_bool.then(...)`; instead, just use `if`. This rule
is not just saying to avoid CREATING things; it's also saying that you might
even need to avoid USING EXISTING things.
))

To achieve many combinations of behaviors, composition primitives, do not not
invent new specializations.


## Control Flow

Keep the main path on the least amount of indentation.

> Flat is better than nested.
> --Zen of Python

It is good to spinning out (i.e. turning a chunk of code that does some
meaningful unit of work into its own function or method). Do not (over-)inline.

When a return condition is detected, return quickly. This is where `return` and
`?` become highly effective. In particular, avoid continuing the dot chain (if
you are on one). Also in particular, do not do
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
((
When possible,
```
let Some(widget) = widget else {
    return ...
};
```
Of course, if `?` works, use that instead of this.
))

`?` must appear at the end of a line (possibly with a semicolon), not in the
middle. It is fine if comments appear after `?`.
((
E.g.
```
// 🙅 BAD
let result = f(g()?);
```
Instead,
```
// 👍 GOOD
let result = g()?;
let result = f(result)
```
`?` appearing in the middle of a multi-line dot chain does not violate this,
because the rule specifically says end of LINE, not STATEMENT.
```
order_new_airplane()
    .await
    // This is fine, even though the `?` is in the middle of a
    // statement, because it is at the end of a LINE.
    .map_err()?
    .inspect();
```
))

When calling a function, if an argument is just a literal, comment what it
signifies.

No multi-line `if` conditions. Ditto for `while`, `match`, and `for ... in`
expressions.

(Exception: when looping over a collection literal, each element can be on its
own line.)

In a boolean expression, strongly avoid mixing `!`, `&&`, and `||`. Use only one
of these within the same expression. This can usually be accomplished using a
combination of De Morgan's Law and dummy variables.
((
E.g. instead of
```
// 🙅 BAD: This mixes `&&` and `!`.
let can_edit = is_admin && !is_read_only;
```
do this
```
// 👍 GOOD: We got rid of the `!` by flipping `is_readonly` to `is_writable`.
let can_edit = is_admin && is_writable;
```
Another way that is often effective is to split the expression.
E.g.
```
fn can_edit(...) {
    ...

    if !is_admin {
        // No need to consider read-only mode; we already know that the
        // answer to "Can we edit?" is false, so just return that now.
        return false;
    }

    if is_read_only {
        // Similarly, this requirement is orthogonal to the other.
        return false;
    }

    // All requirements met -> we can finally return true.
    true
}
```
))
Splitting a big boolean expression tends to work well when validating data,
because you often have many requirements (e.g. one per field).
((
Split can even be applied to `while` condition expression. E.g.
```
while has_x && !has_y { ...
```
can be expressed as
```
loop {
    if !has_x {
        break;
    }

    if has_y {
        break;
    }
}
```
Do not worry about packing everything into one expression.

Splitting lends itself well to commenting; you can certainly comment
subexpressions, but it often "feels wrong". This rule is based on the
observation that what generally happens in practice is you have a list of
requirements, or a list of sufficient conditions. In these cases, you would use
either only `&&` or only `||` (not both). The `can_edit` example falls under the
"list of requirements" case. Then, to avoid mixing in `!`, you just need to
state all the conditions in the positive. As silly as it sounds, humans are not
that good at grasping `&&` where one (or more) of the subexpressions is a `!`
expression. You really have to sit down and stare very hard at such code, maybe
whip out pencil and a used envelope. Sad, but true. Here's a simple test if you
don't believe me: Does `||` distribute over `&&`? How about the other way: Does
`&&` distribute over `||`? These simple examples use only 2 (mixed) operators!
Spoiler alert! Of course, this test is not valid if you memorized these
identities. I really had to sit down with pencil and paper on this one, and my
guess is, for everyone who didn't memorize these identities, you had to also
whip out pen and paper. Don't force your reader to do that!

))

(Branch "on" `enum`s using `match`.)

Short branch arms. (Spin out if necessary.)

(If a function has a `match` with four or more arms, it should have little if
any other code.)

((
Do not do
```
match fruit {
    Fruit::Banana(banana) if banana.mass_kilograms > 3.14 => {
        ...
    }
}
```
Instead,
```
match fruit {
    Fruit::Banana(banana) => {
        if banana.mass_kilograms > 3.14 {
            ...
        }
    }
}
```
))

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

When defining a trait do NOT name it after its one method.


## Comments

The main question that doc comments MUST answer is, "How do I actually USE this
thing?". This is usually explained by the code's behavior, what actually
happens. In particular, do NOT explain how it is implemented.

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

(When inserting an object into a collection, take ownership.)


### Constructors

Avoid incomplete objects by defining constructor(s).

If many pieces are required to assemble an object, since Rust is not yet
civilized enough to have named arguments, ou might have to grudgingly use the
builder pattern.
((
Just remember: when you invent a new builder, you are creating "esoteric"
knowledge and forcing people to learn it. It's an abstraction that is really
prone to violating "Abstractions must pull their own weight".
))

Supply `new` and/or `try_new`. These just assembles, and otherwise does no "real
work" such as reading a file other than validation.

If you need a constructor that does "real work" (e.g. load from a file) do NOT
name the constructor `new`. Instead, name it `load_from_file` or something. The
last line would generally consist of calling `new`.


### Conversions

Convert (such as `impl From...`) in three steps:
1. Fully disassemble.
2. Validate and transform (sub-)components.
3. Reassemble.
Step 2 is where the "real work" happens.
((
Step 0 of Lego is ALWAYS to dump out the box. You do not pull out the one piece
that you need from the box as you need it while assembling! Also, for complex
models, you generally assemble one subcomponent at a time, before assembling
many subcomponents together. This is exactly how you should construct objects.
))

Match the call tree to the type definition tree. Do not inline conversion of
composite members.
((
```
impl From<Plane> for Aircraft {
    fn from(plane: Plane) -> Self {
        // Disassemble.
        let Plane {
            left_wing,
            mass_kg
        }

        // Transform components. (Validation would also go here.)
        let left_wing = aircraft::LeftWing::from(left_wing);

        // Reassemble.
        Aircraft {
            left_wing,
            mass_kg,
        }
    }
}
```
This is just a special case of spinning out.
))
This also applies to validation.


## Anti-Features (not just Rust)

Do not create type aliases. (Re-exporting is acceptable, because uses the same
name, just in a different place.)

(To avoid name collisions when importing, use the module to disambiguate, not
alias.)


## Errors

Leave breadcrumbs. This means including the specific offending value(s), not
just a general description of the failure.
((
We call such data "diagnostics". They are our black box. A general description
of the problem is not actually that valuable, because Rust automatically
includes file and line number. Rust cannot include diagnostics, because that
requires intelligence. It is only capable of purely mechanical things. You are
valuable because you are intelligent. Use it! Diagnostics are diamonds.
))

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
((
This way, the user does not have to make N attempts to figure out all the things
that they need to correct in their request.
))

In general, assume that more ways to fail will be added later. That should not
be a breaking change.
((
E.g.
```
// 🙅 BAD
type ErrorType = variant {
    NotFound,
    NotAuthorized,
};
```
Later, you will add back pressure to your service. Then, you will want to add
`Unavailable` or `Overloaded` to `ErrorType`. But that is NOT a compatible
change! One way to partially work around this is `opt`:
```
type Error = record {
    type_ :
        opt // <- Partial save.
        ErrorType;

    // other fields elided...
};
```
That does allow you to add `Unavailable`. The problem is, a caller cannot tell
the difference between you sending `Unavailable`, vs. you simply didn't populate
`type_`. This is a general problem with Candid `variant`s, but it is especially
a problem for error types, because our core principle here is "Assume more ways
to fail will be added later".
))


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

Use `lazy_static!` for "constants" when you cannot define a `const` due to
limitations in `const` initialization. Do NOT define a 0-argument `fn` for this!

((
Define your own application-specific asserts to maximize meaningfulness and
reduce tedious reading:
```
#[track_caller]
fn assert_${property}(observed, expected) { ... }
```
))


((
## Bash

Use `--long` flags (when available). E.g. `--force` not `-f`.

Use `\` to spread long commands onto multiple lines. E.g.
```
bazel build \
    --test_output=streamed \
    //path/to:my_binary
```

As illustrated above, use lines to group each flag with its argument. Do not put
tangential things on the same line.
))


## Code Review Protocol

When a reviewer asks you (the author) a question about the code you wrote,
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

((
Such a campaign is necessary anyway, since merely following the rules going
forward is not going to do anything about the tons of non-compliant legacy code
that we have.

Ditto for when new rules are added in the future: they will be added without
requiring that legacy code be fixed first, but there needs to be a commitment to
actually fix legacy code before adding such rules.
))
