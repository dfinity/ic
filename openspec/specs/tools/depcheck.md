# Depcheck Specification

This specification covers the `depcheck` crate (`rs/depcheck/`), which enforces dependency policy rules across the IC workspace. It detects undesirable transitive dependencies by performing BFS over the Cargo dependency graph and reports violations with shortest-path evidence.

---

## Requirements

### Requirement: PackageSpec Matching

A `PackageSpec` determines which packages a rule targets or forbids.

#### Scenario: Wildcard matches any package
- **WHEN** a `PackageSpec::Wildcard` is evaluated against any package
- **THEN** it matches regardless of the package name

#### Scenario: Named spec matches only the named package
- **WHEN** a `PackageSpec::Name("foo")` is evaluated against a package
- **AND** the package name is `"foo"`
- **THEN** it matches

#### Scenario: Named spec does not match a different package
- **WHEN** a `PackageSpec::Name("foo")` is evaluated against a package
- **AND** the package name is not `"foo"`
- **THEN** it does not match

#### Scenario: Display format for Wildcard
- **WHEN** a `PackageSpec::Wildcard` is displayed
- **THEN** it renders as `*`

#### Scenario: Display format for Name
- **WHEN** a `PackageSpec::Name("foo")` is displayed
- **THEN** it renders as `foo`

---

### Requirement: DepKind Matching

A `DepKind` determines which dependency kinds (normal, dev, build) a rule applies to.

#### Scenario: Wildcard matches any dependency kind
- **WHEN** a `DepKind::Wildcard` is evaluated against any `DependencyKind`
- **THEN** it matches

#### Scenario: Normal-only matches normal dependencies
- **WHEN** a `DepKind::normal()` is evaluated against `DependencyKind::Normal`
- **THEN** it matches

#### Scenario: Normal-only does not match dev dependencies
- **WHEN** a `DepKind::normal()` is evaluated against `DependencyKind::Development`
- **THEN** it does not match

#### Scenario: Normal-only does not match build dependencies
- **WHEN** a `DepKind::normal()` is evaluated against `DependencyKind::Build`
- **THEN** it does not match

#### Scenario: OneOf matches any listed kind
- **WHEN** a `DepKind::OneOf(vec![Normal, Build])` is evaluated against `DependencyKind::Build`
- **THEN** it matches

---

### Requirement: Rule Definition

A `Rule` combines a source package pattern, a forbidden dependency pattern, a justification, a dependency kind filter, and the file where it is defined.

#### Scenario: Rule display format
- **WHEN** a `Rule` is displayed
- **THEN** it renders as `'<package>' must not depend on '<should_not_depend_on>': <justification>`

#### Scenario: Rule with Wildcard package applies to all workspace members
- **WHEN** a `Rule` has `package: PackageSpec::Wildcard`
- **THEN** during violation detection it is evaluated against every workspace member

#### Scenario: Rule with named package applies to matching packages only
- **WHEN** a `Rule` has `package: PackageSpec::Name("ic-replica")`
- **THEN** during violation detection it is evaluated only against packages named `"ic-replica"`

---

### Requirement: Current Policy Rules

The `main.rs` binary defines the set of dependency policy rules enforced in the IC workspace.

#### Scenario: No workspace member may depend on git2
- **WHEN** any workspace member is checked
- **THEN** it must not depend on the `git2` crate (any dependency kind)
- **AND** the justification states that `git` should be invoked as a subprocess instead to avoid native library overhead and ~10s compile time increase

#### Scenario: ic-replica must not depend on dfn_core
- **WHEN** the `ic-replica` crate is checked
- **THEN** it must not have a normal dependency on `dfn_core`
- **AND** the justification states that the replica must not depend on the Rust CDK

#### Scenario: ic-replica must not depend on orchestrator
- **WHEN** the `ic-replica` crate is checked
- **THEN** it must not have a normal dependency on `orchestrator`
- **AND** the justification states that the replica must not depend on the orchestrator binary

#### Scenario: ic-replica must not depend on ic-workload-generator
- **WHEN** the `ic-replica` crate is checked
- **THEN** it must not have a normal dependency on `ic-workload-generator`
- **AND** the justification states that the replica must not depend on the workload generator binary

#### Scenario: ic-replica must not depend on ic-canister-client
- **WHEN** the `ic-replica` crate is checked
- **THEN** it must not have a normal dependency on `ic-canister-client`
- **AND** the justification states that the replica must not depend on the ic-canister-client library

#### Scenario: ic-types must not depend on bitcoin
- **WHEN** the `ic-types` crate is checked
- **THEN** it must not have a normal dependency on `bitcoin`
- **AND** the justification states that bitcoin is a large package and only a few type definitions should be copied

#### Scenario: ic-constants must not depend on anything
- **WHEN** the `ic-constants` crate is checked
- **THEN** it must not have a normal dependency on any package (`should_not_depend_on: Wildcard`)
- **AND** the justification states that constants do not need dependencies and dependent constants should live in a separate package

---

### Requirement: Violation Detection Algorithm

The `search_for_violation` function uses BFS to find the shortest path in the dependency graph from a source package to a forbidden dependency.

#### Scenario: No path to forbidden dependency
- **WHEN** BFS is performed from a source package
- **AND** no transitive dependency matches the `should_not_depend_on` pattern
- **THEN** no violation is found (returns `None`)

#### Scenario: Direct forbidden dependency
- **WHEN** BFS is performed from a source package
- **AND** the source has a direct dependency matching `should_not_depend_on`
- **AND** the dependency kind matches the rule's `dependency_kind`
- **THEN** a violation is found with a path of length 2 (source and the forbidden dependency)

#### Scenario: Transitive forbidden dependency
- **WHEN** BFS is performed from a source package
- **AND** a transitive (indirect) dependency matches `should_not_depend_on`
- **THEN** a violation is found with the shortest path from the source to the forbidden dependency

#### Scenario: Dependency kind filtering during BFS
- **WHEN** BFS traverses an edge in the dependency graph
- **AND** the edge's dependency kind does not match the rule's `dependency_kind`
- **THEN** that edge is skipped and not traversed

#### Scenario: Cycle avoidance during BFS
- **WHEN** BFS encounters a package that has already been visited
- **THEN** it skips that package to avoid infinite traversal

#### Scenario: Violation path contains package names and versions
- **WHEN** a violation is found
- **THEN** the `dependency_path` contains tuples of `(name, version)` for each package in the shortest path from the source to the forbidden dependency

---

### Requirement: Run Function Behavior

The `run()` function evaluates all rules against workspace metadata and collects violations.

#### Scenario: No violations found
- **WHEN** `run()` is called with metadata and a set of rules
- **AND** no rule is violated
- **THEN** it returns an empty `Vec<Violation>`

#### Scenario: Single violation found
- **WHEN** `run()` is called with metadata and a set of rules
- **AND** exactly one rule is violated by one package
- **THEN** it returns a `Vec` containing one `Violation` with the correct `rule_idx` and `dependency_path`

#### Scenario: Multiple violations from a Wildcard rule
- **WHEN** `run()` is called with a rule whose `package` is `PackageSpec::Wildcard`
- **AND** multiple workspace members violate the rule
- **THEN** a separate `Violation` is returned for each violating workspace member

#### Scenario: Named package rule checks all matching resolved nodes
- **WHEN** `run()` is called with a rule whose `package` is `PackageSpec::Name("foo")`
- **THEN** it iterates over all resolved nodes and checks each one whose package name matches `"foo"`

#### Scenario: Metadata must include resolve graph
- **WHEN** `run()` is called with metadata that has no `resolve` field
- **THEN** it panics with the message `"missing Metadata.resolve"`

---

### Requirement: Error Reporting Format

The `main` function reports violations to stderr with a structured format.

#### Scenario: No violations exits successfully
- **WHEN** no violations are found
- **THEN** the message `"No dependency policy violations found."` is printed to stdout
- **AND** the process exits with code 0

#### Scenario: Single violation count message
- **WHEN** exactly one violation is found
- **THEN** `"Found one dependency policy violation."` is printed to stderr

#### Scenario: Multiple violations count message
- **WHEN** `n` violations are found (where `n > 1`)
- **THEN** `"Found <n> dependency policy violations."` is printed to stderr

#### Scenario: Violation detail block
- **WHEN** a violation is reported
- **THEN** a separator line of 80 `=` characters is printed
- **AND** `"Found a violation of rule #<idx> defined in <file>:"` is printed (where idx is 1-based)
- **AND** another separator line is printed
- **AND** `"'<package>' should not depend on '<forbidden>'."` is printed
- **AND** the rule's justification is printed
- **AND** the shortest dependency path is printed as a tree

#### Scenario: Dependency path tree format
- **WHEN** a violation's dependency path is rendered
- **THEN** the first entry is printed as `<name>:<version>` with no indentation
- **AND** each subsequent entry is printed as `<indent>└── <name>:<version>` where the indent increases by 4 spaces per depth level

#### Scenario: Non-zero exit on violations
- **WHEN** one or more violations are found
- **THEN** the process exits with code 1
