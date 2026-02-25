use super::{MAX_SUSTAINED_SUBNET_ADMINS_PER_DAY, UpdateSubnetAdminsError};
use ic_base_types::SubnetId;
use ic_nervous_system_rate_limits::{
    InMemoryRateLimiter, RateLimiterConfig, RateLimiterError, Reservation,
};
use std::time::{Duration, SystemTime};

const MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE: u64 =
    (24 * 3600) / MAX_SUSTAINED_SUBNET_ADMINS_PER_DAY;

pub(super) struct UpdateSubnetAdminsRateLimiter {
    subnet_limiter: InMemoryRateLimiter<SubnetId>,
}

#[derive(Debug)]
pub(super) struct UpdateSubnetAdminsReservation {
    subnet_reservation: Reservation<SubnetId>,
}

impl UpdateSubnetAdminsRateLimiter {
    pub(super) fn new() -> Self {
        Self {
            subnet_limiter: InMemoryRateLimiter::new_in_memory(RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: Duration::from_secs(
                    MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE,
                ),
                max_capacity: MAX_SUSTAINED_SUBNET_ADMINS_PER_DAY,
                max_reservations: MAX_SUSTAINED_SUBNET_ADMINS_PER_DAY + 1,
            }),
        }
    }

    pub(super) fn try_reserve(
        &mut self,
        subnet_id: SubnetId,
        now: SystemTime,
    ) -> Result<UpdateSubnetAdminsReservation, UpdateSubnetAdminsError> {
        let subnet_reservation =
            self.subnet_limiter
                .try_reserve(now, subnet_id, 1)
                .map_err(|e| match e {
                    RateLimiterError::NotEnoughCapacity => {
                        UpdateSubnetAdminsError::SubnetRateLimited { subnet_id }
                    }
                    re => panic!("Unexpected error from subnet rate limiter: {re:?}"),
                })?;

        Ok(UpdateSubnetAdminsReservation { subnet_reservation })
    }

    pub(super) fn commit(&mut self, reservation: UpdateSubnetAdminsReservation, now: SystemTime) {
        // This call cannot fail as the whole execution is performed in a single update context
        self.subnet_limiter
            .commit(now, reservation.subnet_reservation)
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutations::do_update_subnet_admins::UpdateSubnetAdminsRateLimiter;

    use ic_base_types::PrincipalId;
    use ic_nervous_system_time_helpers::now_system_time;

    #[test]
    fn rate_limit_prevents_too_many_updates_for_single_subnet() {
        let mut rate_limiter = UpdateSubnetAdminsRateLimiter::new();
        let now = now_system_time();
        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));

        // The first `MAX_SUSTAINED_SUBNET_ADMINS_PER_DAY` calls should succeed.
        for _ in 0..MAX_SUSTAINED_SUBNET_ADMINS_PER_DAY {
            let reservation = rate_limiter.try_reserve(subnet_id, now).unwrap();
            rate_limiter.commit(reservation, now);
        }

        // The (`MAX_SUSTAINED_SUBNET_ADMINS_PER_DAY` + 1)-th call should fail.
        let expected_err = UpdateSubnetAdminsError::SubnetRateLimited { subnet_id };
        let response = rate_limiter
            .try_reserve(subnet_id, now)
            .expect_err("Should error out");
        assert_eq!(response, expected_err);

        // But a call to update subnet admins for another subnet succeeds.
        let another_subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(2));
        let reservation = rate_limiter.try_reserve(another_subnet_id, now).unwrap();
        rate_limiter.commit(reservation, now);

        // After `MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE` another call to
        // update admins of the first subnet should succeed.
        let after_duration_elapsed = now
            .checked_add(Duration::from_secs(
                MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE,
            ))
            .unwrap();
        rate_limiter
            .try_reserve(subnet_id, after_duration_elapsed)
            .unwrap();
    }
}
