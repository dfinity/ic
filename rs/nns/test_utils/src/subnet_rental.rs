/// The Subnet Rental canister does not actually have an init argument.
/// Therefore, it might seem strange that we have a builder for it. The reason
/// this exists is that Subnet Rental canister is optional. You have to call
/// with_subnet_rental_canister in order for it to be created during NNS
/// creation.
#[derive(Default, Clone, Debug)]
pub struct SubnetRentalCanisterInitPayloadBuilder {
    enabled: bool,
}

impl SubnetRentalCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable(&mut self) -> &mut Self {
        self.enabled = true;
        self
    }

    pub fn build(&mut self) -> Option<()> {
        if self.enabled { Some(()) } else { None }
    }
}
