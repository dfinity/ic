use candid::Principal;

use crate::{LocalRef, StableSet, StorablePrincipal};

#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Authorize {
    fn authorize(&self, principal: &Principal) -> Result<(), AuthorizeError>;
}

pub struct Authorizer {
    authorized_principals: LocalRef<StableSet<StorablePrincipal>>,
}

impl Authorizer {
    pub fn new(authorized_principals: LocalRef<StableSet<StorablePrincipal>>) -> Self {
        Self {
            authorized_principals,
        }
    }
}

impl Authorize for Authorizer {
    fn authorize(&self, principal: &Principal) -> Result<(), AuthorizeError> {
        if !self
            .authorized_principals
            .with(|ps| ps.borrow().contains_key(&principal.to_text().into()))
        {
            return Err(AuthorizeError::Unauthorized);
        }

        Ok(())
    }
}

impl<T: Authorize> Authorize for LocalRef<T> {
    fn authorize(&self, principal: &Principal) -> Result<(), AuthorizeError> {
        self.with(|a| a.borrow().authorize(principal))
    }
}

impl Authorize for Box<dyn Authorize> {
    fn authorize(&self, principal: &Principal) -> Result<(), AuthorizeError> {
        (**self).authorize(principal)
    }
}

pub struct WithAuthorize<T, A>(pub T, pub A);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ROOT_PRINCIPALS, acl::AuthorizeError};
    use candid::Principal;

    #[test]
    fn authorizer_empty() {
        let p = &Principal::from_text("llx5h-dqaaa-aaaag-abckq-cai").unwrap();

        let result = Authorizer::new(&ROOT_PRINCIPALS).authorize(p);

        match result {
            Err(AuthorizeError::Unauthorized) => {}
            _ => panic!("expected unauthorized error, got {result:?}"),
        }
    }

    #[test]
    fn authorizer_authorized() {
        let p = &Principal::from_text("llx5h-dqaaa-aaaag-abckq-cai").unwrap();

        ROOT_PRINCIPALS.with(|m| m.borrow_mut().insert(p.to_text().into(), ()));

        let result = Authorizer::new(&ROOT_PRINCIPALS).authorize(p);

        match result {
            Ok(()) => {}
            _ => panic!("expected unauthorized error, got {result:?}"),
        }
    }

    #[test]
    fn authorizer_unauthorized() {
        let p1 = &Principal::from_text("llx5h-dqaaa-aaaag-abckq-cai").unwrap();
        let p2 = &Principal::from_text("bb7pg-paaaa-aaaap-aav3q-cai").unwrap();

        ROOT_PRINCIPALS.with(|m| m.borrow_mut().insert(p1.to_text().into(), ()));

        let result = Authorizer::new(&ROOT_PRINCIPALS).authorize(p2);

        match result {
            Err(AuthorizeError::Unauthorized) => {}
            _ => panic!("expected unauthorized error, got {result:?}"),
        }
    }
}
