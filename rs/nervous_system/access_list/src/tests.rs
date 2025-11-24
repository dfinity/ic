#![cfg(test)]
use ic_nervous_system_access_list::FeatureAccessPolicy;

#[test]
fn allow_all_works() {
    let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::allow_all();

    assert!(policy.is_allowed(&1));
    assert!(policy.is_allowed(&42));
}

#[test]
fn deny_all_works() {
    let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::deny_all();

    assert!(!policy.is_allowed(&1));
    assert!(!policy.is_allowed(&42));
}

#[test]
fn allow_works() {
    // Allowing no one should be `DenyAll`
    let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::allow([]);

    assert!(!policy.is_allowed(&1));
    assert!(!policy.is_allowed(&42));

    // Allowing some should be `AllowOnly`
    let policy = FeatureAccessPolicy::allow([1, 42]);

    assert!(policy.is_allowed(&42));
    assert!(!policy.is_allowed(&999));
}

#[test]
fn deny_works() {
    // Denying no one should be `AllowAll`
    let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::deny([]);

    assert!(policy.is_allowed(&1));
    assert!(policy.is_allowed(&42));

    // Denying some should be `DenyOnly`
    let policy = FeatureAccessPolicy::deny([1, 42]);

    assert!(!policy.is_allowed(&42));
    assert!(policy.is_allowed(&999));
}

#[test]
fn is_all_allowed_works() {
    let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::allow_all();

    assert!(policy.is_all_allowed());
    assert!(!policy.is_all_denied());

    let policy = FeatureAccessPolicy::allow([1, 42]);
    assert!(!policy.is_all_allowed());
    assert!(!policy.is_all_denied());
}

#[test]
fn is_all_denied_works() {
    let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::deny_all();
    assert!(policy.is_all_denied());
    assert!(!policy.is_all_allowed());

    let policy = FeatureAccessPolicy::deny([1, 42]);
    assert!(!policy.is_all_allowed());
    assert!(!policy.is_all_denied());
}
