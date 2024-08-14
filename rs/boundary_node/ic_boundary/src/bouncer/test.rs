use std::str::FromStr;

use dashmap::DashSet;

use super::*;

struct MockFirewall(DashSet<IpAddr>);

#[async_trait]
impl Firewall for MockFirewall {
    async fn apply(&self, decisions: Vec<Decision>) -> Result<(), Error> {
        self.0.clear();
        decisions.into_iter().for_each(|x| {
            self.0.insert(x.ip);
        });
        Ok(())
    }
}

#[tokio::test]
async fn test_bouncer() {
    let fw = Arc::new(MockFirewall(DashSet::new()));

    let bouncer = Bouncer::new(
        10,
        15,
        Duration::from_secs(100),
        100,
        Duration::from_secs(10),
        fw.clone(),
        &Registry::new(),
    )
    .unwrap();

    let ip1 = IpAddr::from_str("1.1.1.1").unwrap();
    let ip2 = IpAddr::from_str("2.2.2.2").unwrap();

    // Check that first 15 reqs for ip1 are allowed (burst)
    for _ in 0..15 {
        assert!(bouncer.acquire_token(ip1));
    }

    // Check that next one is denied
    assert!(!bouncer.acquire_token(ip1));

    // Make sure it's added to firewall
    assert!(bouncer.apply().await.is_ok());
    assert!(fw.0.contains(&ip1));

    // Check that first 15 reqs for ip2 are allowed even if ip1 is blocked
    for _ in 0..15 {
        assert!(bouncer.acquire_token(ip2));
    }

    // Check that next one is denied
    assert!(!bouncer.acquire_token(ip2));

    // Make sure it's added to firewall and we still have ip1 there
    assert!(bouncer.apply().await.is_ok());
    assert!(fw.0.contains(&ip1));
    assert!(fw.0.contains(&ip2));

    // Jump 150s into the future and check that both IPs are expired
    let now = Instant::now()
        .checked_add(Duration::from_secs(150))
        .unwrap();
    bouncer.process_releases(now);
    assert!(bouncer.apply().await.is_ok());
    assert!(fw.0.is_empty());
}
