use prometheus_parse::{Sample, Scrape, Value};

pub fn get_counter(scrape: &Scrape, name: &str) -> f64 {
    match get_sample(scrape, name).value {
        Value::Counter(value) => value,
        value => panic!("Metric found, but not a counter: {:?}", value),
    }
}

pub fn get_gauge(scrape: &Scrape, name: &str) -> f64 {
    match get_sample(scrape, name).value {
        Value::Gauge(value) => value,
        value => panic!("Metric found, but not a gauge: {:?}", value),
    }
}

pub fn get_sample(scrape: &Scrape, name: &str) -> Sample {
    for sample in &scrape.samples {
        if sample.metric == name {
            assert!(sample.labels.is_empty(), "Sample has labels: {:#?}", sample);
            return sample.clone();
        }
    }
    panic!("Metric not found: {} in {:#?}", name, scrape);
}

pub fn get_samples(scrape: &Scrape, name: &str) -> Vec<Sample> {
    let result = scrape
        .samples
        .iter()
        .filter_map(|sample| {
            if sample.metric != name {
                return None;
            }

            assert!(
                !sample.labels.is_empty(),
                "Sample has no labels: {:#?}",
                sample
            );
            Some(sample.clone())
        })
        .collect::<Vec<Sample>>();

    assert!(
        !result.is_empty(),
        "Unable to find a metric named {}: {:#?}",
        name,
        scrape
    );

    result
}
