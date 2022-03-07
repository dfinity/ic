use cargo_metadata::{DependencyKind, Metadata, Node, Package, PackageId, Version};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

/// A pattern for matching package names in a [Rule].
pub enum PackageSpec {
    /// Match all packages.
    Wildcard,
    /// Match packages with the specified name.
    Name(String),
}

impl fmt::Display for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wildcard => write!(f, "*"),
            Self::Name(name) => write!(f, "{}", name),
        }
    }
}

impl PackageSpec {
    fn applies_to(&self, pkg: &Package) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Name(name) => &pkg.name == name,
        }
    }
}

/// A pattern for matching dependency kinds in a [Rule].
pub enum DepKind {
    /// Match all dependency kinds.
    Wildcard,
    /// Match dependency kinds from the list.
    OneOf(Vec<DependencyKind>),
}

impl DepKind {
    /// Returns a dependency kind pattern that applies only to dependencies from
    /// '[dependencies]' section in Cargo.toml.
    pub fn normal() -> DepKind {
        Self::OneOf(vec![DependencyKind::Normal])
    }
}

/// A rule for detecting undesirable dependencies.
pub struct Rule {
    /// The pattern for the package to which the policy applies.
    /// If equals to "Wildcard", the rule applies to all workspace members.
    pub package: PackageSpec,
    /// The pattern for the package that should not appear in the dependency
    /// closure of the "package" above.
    pub should_not_depend_on: PackageSpec,
    /// Explanation for the policy.
    /// Why is it important to apply this rule?
    pub justification: String,
    /// Kind of dependencies this rule applies to.
    pub dependency_kind: DepKind,
    /// The file where the rule is defined.
    /// Use `std::file!()` macro at the rule construction site.
    pub defined_in: &'static str,
}

impl Rule {
    fn applies_to_kind(&self, k: DependencyKind) -> bool {
        match &self.dependency_kind {
            DepKind::Wildcard => true,
            DepKind::OneOf(kinds) => kinds.contains(&k),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' must not depend on '{}': {}",
            self.package, self.should_not_depend_on, self.justification
        )
    }
}

pub struct Violation {
    /// Index of the rule that was violated.
    pub rule_idx: usize,
    /// The shortest path in the dependency graph that demonstrates the
    /// violation of the rule.
    pub dependency_path: Vec<(String, Version)>,
}

/// Tries to find the shortest path in the dependency graph that demonstrates a
/// violation of the given `rule`.
fn search_for_violation(
    metadata: &Metadata,
    node_by_id: &HashMap<&PackageId, &Node>,
    node: &Node,
    rule: &Rule,
) -> Option<Vec<(String, Version)>> {
    let mut paths = VecDeque::new();
    paths.push_back(vec![&node]);

    let mut visited = HashSet::new();
    visited.insert(&node.id);

    while let Some(path) = paths.pop_front() {
        let head = path.last().unwrap();
        for dep in head.deps.iter() {
            if !dep.dep_kinds.iter().any(|e| rule.applies_to_kind(e.kind)) {
                continue;
            }

            if !visited.insert(&dep.pkg) {
                continue;
            }

            let extended_path = {
                let mut path = path.clone();
                path.push(node_by_id.get(&dep.pkg).unwrap());
                path
            };

            if rule.should_not_depend_on.applies_to(&metadata[&dep.pkg]) {
                let dependency_path = extended_path
                    .iter()
                    .map(|n| {
                        let p = &metadata[&n.id];
                        (p.name.clone(), p.version.clone())
                    })
                    .collect();
                return Some(dependency_path);
            }

            paths.push_back(extended_path)
        }
    }
    None
}

/// Runs the given rule set on workspace metadata and returns the list of rule
/// violations.
pub fn run(metadata: &Metadata, rules: &[Rule]) -> Vec<Violation> {
    let mut violations = Vec::new();

    let resolve = metadata.resolve.as_ref().expect("missing Metadata.resolve");

    let node_by_id: HashMap<_, _> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();

    for (rule_idx, rule) in rules.iter().enumerate() {
        match &rule.package {
            PackageSpec::Wildcard => {
                for pkg in metadata.workspace_members.iter() {
                    let node = node_by_id.get(pkg).unwrap();
                    if let Some(dependency_path) =
                        search_for_violation(metadata, &node_by_id, node, rule)
                    {
                        violations.push(Violation {
                            rule_idx,
                            dependency_path,
                        });
                    }
                }
            }
            PackageSpec::Name(n) => {
                for node in resolve.nodes.iter() {
                    let package = &metadata[&node.id];
                    if n != &package.name {
                        continue;
                    }
                    if let Some(dependency_path) =
                        search_for_violation(metadata, &node_by_id, node, rule)
                    {
                        violations.push(Violation {
                            rule_idx,
                            dependency_path,
                        });
                    }
                }
            }
        }
    }
    violations
}
