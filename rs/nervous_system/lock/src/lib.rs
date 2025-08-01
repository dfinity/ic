//! This makes it easy to implement "fail if another async call is in progress".
//!
//! See tests.rs for an example of how to use this.
use std::{cell::RefCell, fmt::Debug, thread::LocalKey};

/// If current_resource_flag is None (the happy case), this does a few things:
///
///     1. Sets current_resource_flag to Some(new_resource_flag).
///
///     2. Returns Ok.
///
///     3. Returns an object that when dropped sets current_resource_flag (back) to None.
///
/// In the sad case (i.e. current_resource_flag is Some(...)), returns Err(current_resource_flag).
///
/// Returns immediately; does not wait for others to release.
pub fn acquire<ResourceFlag: Debug + Copy + 'static>(
    current_resource_flag: &'static LocalKey<RefCell<Option<ResourceFlag>>>,
    new_resource_flag: ResourceFlag,
) -> Result<ResourceGuard<ResourceFlag>, ResourceFlag> {
    ResourceGuard::new(current_resource_flag, new_resource_flag)
}

#[derive(Debug)]
pub struct ResourceGuard<ResourceFlag: Debug + Copy + 'static> {
    resource_flag: Option<&'static LocalKey<RefCell<Option<ResourceFlag>>>>,
}

impl<ResourceFlag: Debug + Copy + 'static> ResourceGuard<ResourceFlag> {
    fn new(
        current_resource_flag: &'static LocalKey<RefCell<Option<ResourceFlag>>>,
        new_resource_flag: ResourceFlag,
    ) -> Result<
        Self,
        ResourceFlag, // Original value.
    > {
        current_resource_flag.with(|current_resource_flag| {
            let mut current_resource_flag = current_resource_flag.borrow_mut();
            let original_value = *current_resource_flag;

            if let Some(original_value) = original_value {
                return Err(original_value);
            }

            *current_resource_flag = Some(new_resource_flag);
            Ok(())
        })?;

        let resource_flag = Some(current_resource_flag);
        Ok(ResourceGuard { resource_flag })
    }
}

impl<ResourceFlag: Debug + Copy + 'static> Drop for ResourceGuard<ResourceFlag> {
    fn drop(&mut self) {
        if let Some(resource_flag) = self.resource_flag {
            resource_flag.with(|resource_flag| {
                let mut resource_flag = resource_flag.borrow_mut();
                *resource_flag = None;
            })
        }
    }
}

#[cfg(test)]
mod tests;
