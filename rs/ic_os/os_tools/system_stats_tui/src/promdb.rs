use chrono::TimeDelta;
use prometheus_parse::{Sample, Scrape, Value};
use regex::Regex;
use std::{
    cmp::min,
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    ops::{BitAnd, BitOr},
};

pub enum ValueQuery {
    Equals(String),
    DoesNotEqual(String),
    Matches(Regex),
    DoesNotMatch(Regex),
}

impl ValueQuery {
    pub fn equals(value: &str) -> Self {
        Self::Equals(value.to_string())
    }

    pub fn does_not_equal(value: &str) -> Self {
        Self::DoesNotEqual(value.to_string())
    }

    pub fn matches(regex: &Regex) -> Self {
        let anchored = "^".to_owned() + regex.as_str() + "$";
        let proper_re = Regex::new(&anchored).unwrap();
        Self::Matches(proper_re)
    }

    pub fn does_not_match(regex: &Regex) -> Self {
        let anchored = "^".to_owned() + regex.as_str() + "$";
        let proper_re = Regex::new(&anchored).unwrap();
        Self::DoesNotMatch(proper_re)
    }
}

struct IndexedScrapeLabelValueQuery<'a> {
    value: ValueQuery,
    label_query: IndexedScrapeLabelQuery<'a>,
    indexes: HashSet<usize>,
}

impl<'a> IndexedScrapeLabelValueQuery<'a> {
    fn new(label_query: IndexedScrapeLabelQuery<'a>, value: ValueQuery) -> Self {
        let indexes_for_label_name = match label_query.scrape.index.get(&label_query.label) {
            Some(s) => s,
            None => &HashMap::new(),
        };
        Self {
            indexes: match &value {
                ValueQuery::Equals(val) => match indexes_for_label_name.get(val) {
                    Some(ss) => ss.clone(),
                    None => HashSet::new(),
                },
                ValueQuery::DoesNotEqual(val) => {
                    let hashset: HashSet<usize> = HashSet::from_iter(
                        label_query
                            .scrape
                            .index
                            .values()
                            .flat_map(|x| x.values())
                            .flat_map(|x| x.iter())
                            .copied(),
                    );
                    match indexes_for_label_name.get(val) {
                        // Both label name and label value were found in the map.
                        Some(ss) => hashset.difference(ss).copied().collect(),
                        None => hashset,
                    }
                }
                ValueQuery::Matches(rex) => {
                    let hashsets: Vec<&HashSet<usize>> = indexes_for_label_name
                        .iter()
                        .filter_map(|(v, n)| match rex.is_match(v) {
                            true => Some(n),
                            false => None,
                        })
                        .collect();
                    match hashsets.len() {
                        0 => HashSet::new(),
                        _ => hashsets[1..]
                            .iter()
                            .fold(hashsets[0].clone(), |acc, set| acc.bitor(set)),
                    }
                }
                ValueQuery::DoesNotMatch(rex) => {
                    let hashsets: Vec<&HashSet<usize>> = label_query
                        .scrape
                        .index
                        .values()
                        .flat_map(|x| x.values())
                        .collect();
                    let hashset = match hashsets.len() {
                        0 => HashSet::new(),
                        _ => hashsets[1..]
                            .iter()
                            .fold(hashsets[0].clone(), |acc, set| acc.bitor(set)),
                    };
                    let exclude_these: Vec<&HashSet<usize>> = indexes_for_label_name
                        .iter()
                        .filter_map(|(v, n)| match rex.is_match(v) {
                            true => Some(n),
                            false => None,
                        })
                        .collect();
                    let exclude_these_indexes = match exclude_these.len() {
                        0 => HashSet::new(),
                        _ => exclude_these[1..]
                            .iter()
                            .fold(exclude_these[0].clone(), |acc, set| acc.bitor(set)),
                    };
                    hashset
                        .difference(&exclude_these_indexes)
                        .copied()
                        .collect()
                }
            },
            value,
            label_query,
        }
    }

    fn equals(label_query: IndexedScrapeLabelQuery<'a>, value: &str) -> Self {
        Self::new(label_query, ValueQuery::equals(value))
    }

    fn matches(label_query: IndexedScrapeLabelQuery<'a>, value: &Regex) -> Self {
        Self::new(label_query, ValueQuery::matches(value))
    }

    fn does_not_equal(label_query: IndexedScrapeLabelQuery<'a>, value: &str) -> Self {
        Self::new(label_query, ValueQuery::does_not_equal(value))
    }

    fn does_not_match(label_query: IndexedScrapeLabelQuery<'a>, value: &Regex) -> Self {
        Self::new(label_query, ValueQuery::does_not_match(value))
    }
}

impl<'a> BitOr for IndexedScrapeLabelValueQuery<'a> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        let mine_indexes = self.indexes.clone();
        let other_indexes = rhs.indexes.clone();
        Self {
            value: self.value,
            label_query: self.label_query,
            indexes: &mine_indexes | &other_indexes,
        }
    }
}

impl<'a> BitAnd for IndexedScrapeLabelValueQuery<'a> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        let mine_indexes = self.indexes.clone();
        let other_indexes = rhs.indexes.clone();
        Self {
            value: self.value,
            label_query: self.label_query,
            indexes: &mine_indexes & &other_indexes,
        }
    }
}

struct IndexedScrapeLabelQuery<'a> {
    label: String,
    scrape: &'a IndexedScrape,
}

impl<'a> IndexedScrapeLabelQuery<'a> {
    fn equals(self, value: &str) -> IndexedScrapeLabelValueQuery<'a> {
        IndexedScrapeLabelValueQuery::equals(self, value)
    }

    fn does_not_equal(self, value: &str) -> IndexedScrapeLabelValueQuery<'a> {
        IndexedScrapeLabelValueQuery::does_not_equal(self, value)
    }

    fn matches(self, regex: &Regex) -> IndexedScrapeLabelValueQuery<'a> {
        IndexedScrapeLabelValueQuery::matches(self, regex)
    }

    fn does_not_match(self, regex: &Regex) -> IndexedScrapeLabelValueQuery<'a> {
        IndexedScrapeLabelValueQuery::does_not_match(self, regex)
    }
}

#[derive(Debug)]
pub struct IndexedScrape {
    pub samples: Vec<Sample>,
    index: HashMap<String, HashMap<String, HashSet<usize>>>,
}

impl IndexedScrape {
    fn label(&self, label: &str) -> IndexedScrapeLabelQuery<'_> {
        IndexedScrapeLabelQuery {
            label: label.to_string(),
            scrape: self,
        }
    }

    pub fn search<'a>(
        &self,
        labelsets: impl IntoIterator<Item = (&'a str, &'a ValueQuery)>,
    ) -> Vec<&Sample> {
        let hashsets: Vec<_> = labelsets
            .into_iter()
            .map(|(label, value)| match value {
                ValueQuery::Equals(val) => self.label(label).equals(val).indexes.clone(),
                ValueQuery::Matches(regex) => self.label(label).matches(regex).indexes.clone(),
                ValueQuery::DoesNotEqual(val) => {
                    self.label(label).does_not_equal(val).indexes.clone()
                }
                ValueQuery::DoesNotMatch(regex) => {
                    self.label(label).does_not_match(regex).indexes.clone()
                }
            })
            .collect();
        let indexes = match hashsets.len() {
            0 => HashSet::new(),
            _ => hashsets[1..]
                .iter()
                .fold(hashsets[0].clone(), |mut acc, set| {
                    acc.retain(|item| set.contains(item));
                    acc
                }),
        };
        indexes.iter().map(|idx| &self.samples[*idx]).collect()
    }

    /// Finds a sample in this scrape that exactly matches the metric name and labelset
    /// of the provided sample. Returns None if no match or multiple matches are found.
    fn find_matching_sample(&self, other_sample: &Sample) -> Option<&Sample> {
        let mut labelset: Vec<(&str, ValueQuery)> =
            vec![("__name__", ValueQuery::equals(other_sample.metric.as_str()))];
        labelset.extend(
            other_sample
                .labels
                .iter()
                .map(|(k, v)| (k.as_str(), ValueQuery::equals(v))),
        );
        let res = self.search(labelset.iter().map(|(k, v)| (*k, v)));

        // Filter to only samples with exactly the same label count to ensure exact match
        let exact_matches: Vec<_> = res
            .into_iter()
            .filter(|s| s.labels.len() == other_sample.labels.len())
            .collect();

        match exact_matches.len() {
            1 => Some(exact_matches[0]),
            _ => None, // Return None for 0 matches or ambiguous multiple matches
        }
    }

    pub fn sum_by<'a>(&self, labels: impl IntoIterator<Item = &'a str>) -> Self {
        let label_names: Vec<String> = labels.into_iter().map(|v| v.to_string()).collect();
        let mut buckets: HashMap<Vec<Option<&str>>, Sample> = HashMap::new();
        for sample in self.samples.iter() {
            let label_values: Vec<_> = label_names.iter().map(|ln| sample.labels.get(ln)).collect();
            match buckets.entry(label_values) {
                Entry::Vacant(v) => {
                    v.insert({
                        let without = sample.labels.clone();
                        Sample {
                            metric: sample.metric.clone(),
                            value: sample.value.clone(),
                            timestamp: sample.timestamp,
                            labels: without,
                        }
                    });
                }
                Entry::Occupied(mut o) => {
                    let new_value = match (&sample.value, &o.get().value) {
                        (Value::Gauge(s), Value::Gauge(b)) => Value::Gauge(s + b),
                        (Value::Untyped(s), Value::Untyped(b)) => Value::Untyped(s + b),
                        (Value::Counter(s), Value::Counter(b)) => Value::Counter(s + b),
                        (Value::Histogram(_), _) | (_, Value::Histogram(_)) => {
                            panic!("sample type changed between scrapes")
                        }
                        (Value::Summary(_), _) | (_, Value::Summary(_)) => {
                            panic!("sample type changed between scrapes")
                        }
                        _ => panic!("sample type changed between scrapes"),
                    };
                    o.get_mut().value = new_value;
                }
            };
        }
        Self::from(buckets.values().cloned().collect::<Vec<_>>())
    }
}

impl From<Vec<Sample>> for IndexedScrape {
    fn from(samples: Vec<Sample>) -> Self {
        let mut index: HashMap<String, HashMap<String, HashSet<usize>>> = HashMap::new();
        for (uidx, sample) in samples.iter().enumerate() {
            index
                .entry("__name__".to_string())
                .or_default()
                .entry(sample.metric.clone())
                .or_default()
                .insert(uidx);
            for (labelname, labelvalue) in sample.labels.iter() {
                index
                    .entry(labelname.to_string())
                    .or_default()
                    .entry(labelvalue.clone())
                    .or_default()
                    .insert(uidx);
            }
        }
        Self { samples, index }
    }
}

impl From<Scrape> for IndexedScrape {
    fn from(value: Scrape) -> Self {
        IndexedScrape::from(value.samples)
    }
}

#[derive(Debug)]
pub struct IndexedSeries(usize, VecDeque<IndexedScrape>);

impl<'a> IndexedSeries {
    pub fn new(capacity: usize) -> Self {
        Self(capacity, VecDeque::with_capacity(capacity))
    }

    pub fn push(&mut self, scrape: IndexedScrape) {
        if self.1.len() == self.0 {
            self.1.truncate(self.0 - 1)
        }
        self.1.push_front(scrape)
    }

    pub fn len(&self) -> usize {
        self.1.len()
    }

    pub fn is_empty(&self) -> bool {
        self.1.is_empty()
    }

    pub fn search(
        &'a self,
        labelsets: impl IntoIterator<Item = (&'a str, &'a ValueQuery)> + 'a,
    ) -> IndexedSeriesSubset<'a> {
        IndexedSeriesSubset {
            series: self,
            labelsets: labelsets.into_iter().collect(),
        }
    }
}

pub struct IndexedSeriesSubset<'a> {
    series: &'a IndexedSeries,
    labelsets: Vec<(&'a str, &'a ValueQuery)>,
}

impl<'a> IndexedSeriesSubset<'a> {
    fn _delta_with_timestamps(
        &self,
        start_sample: usize,
        sample_count: usize,
    ) -> Vec<(Sample, TimeDelta)> {
        // FIXME maybe we should not be clamping, but just returning empty stuff.
        let start = min(start_sample, self.series.1.len() - 1);
        let end = min(start_sample + sample_count, self.series.1.len() - 1);
        if start == end {
            return vec![];
        };

        let first_scrape = &self.series.1[start];
        let last_scrape = &self.series.1[end];

        let mut new_samples: Vec<(Sample, TimeDelta)> = vec![];
        for sample in first_scrape.search(self.labelsets.clone().into_iter()) {
            let sample_before = last_scrape.find_matching_sample(sample);
            //println!("{:?}", sample_before);
            //println!("{:?}\n", sample);
            if let Some(sample_before) = sample_before {
                let delta = match (&sample_before.value, &sample.value) {
                    (Value::Gauge(b), Value::Gauge(n)) => Some(Value::Gauge(n - b)),
                    (Value::Untyped(b), Value::Untyped(n)) => Some(Value::Untyped(n - b)),
                    (Value::Counter(b), Value::Counter(n)) => Some(Value::Counter(n - b)),
                    (Value::Histogram(_), Value::Histogram(_)) => None, // "don't know how to deal with histograms".to_string(),
                    (Value::Summary(_), Value::Summary(_)) => None, // "don't know how to deal with summaries".to_string(),
                    (_, _) => None, //format!("mismatch between types of {:?} and {:?}", otherbefore, otherafter),
                };
                if let Some(delta) = delta {
                    let mut new_sample = Sample::clone(sample);
                    new_sample.value = delta;
                    new_samples.push((new_sample, sample.timestamp - sample_before.timestamp));
                }
            }
        }

        new_samples
    }

    pub fn delta(&self, start_sample: usize, sample_count: usize) -> IndexedScrape {
        IndexedScrape::from(
            self._delta_with_timestamps(start_sample, sample_count)
                .into_iter()
                .map(|(s, _d)| s)
                .collect::<Vec<_>>(),
        )
    }

    pub fn rate(&self, start_sample: usize, sample_count: usize) -> IndexedScrape {
        IndexedScrape::from(
            self._delta_with_timestamps(start_sample, sample_count)
                .iter()
                .map(|(s, d)| {
                    let mut s = s.clone();
                    s.value = match s.value {
                        Value::Gauge(b) => Value::Gauge(b / d.as_seconds_f64()),
                        Value::Untyped(b) => Value::Untyped(b / d.as_seconds_f64()),
                        Value::Counter(b) => Value::Counter(b / d.as_seconds_f64()),
                        Value::Histogram(_) => panic!("no support for histograms"),
                        Value::Summary(_) => panic!("no support for summaries"),
                    };
                    s
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn at(&self, start_sample: usize) -> IndexedScrape {
        // FIXME maybe we should not be clamping, but just returning empty stuff.
        let start = min(start_sample, self.series.1.len() - 1);
        let scrape = &self.series.1[start];
        let samples = scrape.search(self.labelsets.clone());
        samples.into_iter().cloned().collect::<Vec<_>>().into()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use prometheus_parse::Value::Untyped;

    use super::*;

    #[test]
    fn test_sum() {
        let mut series = IndexedSeries::new(12);
        let first_scrape = r#"node_cpu_seconds_total{cpu="1",mode="idle"} 10000
node_cpu_seconds_total{cpu="1",mode="iowait"} 1
node_cpu_seconds_total{cpu="1",mode="irq"} 1
node_cpu_seconds_total{cpu="1",mode="nice"} 1
node_cpu_seconds_total{cpu="1",mode="softirq"} 1
node_cpu_seconds_total{cpu="1",mode="steal"} 1
node_cpu_seconds_total{cpu="1",mode="system"} 1
node_cpu_seconds_total{cpu="1",mode="user"} 1
node_cpu_seconds_total{cpu="10",mode="idle"} 10000
node_cpu_seconds_total{cpu="10",mode="iowait"} 2
node_cpu_seconds_total{cpu="10",mode="irq"} 2
node_cpu_seconds_total{cpu="10",mode="nice"} 2
node_cpu_seconds_total{cpu="10",mode="softirq"} 2
node_cpu_seconds_total{cpu="10",mode="steal"} 2
node_cpu_seconds_total{cpu="10",mode="system"} 2
node_cpu_seconds_total{cpu="10",mode="user"} 2
"#;
        let second_scrape = r#"node_cpu_seconds_total{cpu="1",mode="idle"} 10001
node_cpu_seconds_total{cpu="1",mode="iowait"} 2
node_cpu_seconds_total{cpu="1",mode="irq"} 2
node_cpu_seconds_total{cpu="1",mode="nice"} 2
node_cpu_seconds_total{cpu="1",mode="softirq"} 2
node_cpu_seconds_total{cpu="1",mode="steal"} 2
node_cpu_seconds_total{cpu="1",mode="system"} 2
node_cpu_seconds_total{cpu="1",mode="user"} 2
node_cpu_seconds_total{cpu="10",mode="idle"} 10001
node_cpu_seconds_total{cpu="10",mode="iowait"} 3
node_cpu_seconds_total{cpu="10",mode="irq"} 3
node_cpu_seconds_total{cpu="10",mode="nice"} 3
node_cpu_seconds_total{cpu="10",mode="softirq"} 3
node_cpu_seconds_total{cpu="10",mode="steal"} 3
node_cpu_seconds_total{cpu="10",mode="system"} 3
node_cpu_seconds_total{cpu="10",mode="user"} 3
"#;
        let time = Utc::now();
        for (n, scrape) in [first_scrape, second_scrape].iter().enumerate() {
            let t = time + TimeDelta::seconds(n.try_into().unwrap());
            series.push(
                prometheus_parse::Scrape::parse_at(scrape.lines().map(|l| Ok(l.to_owned())), t)
                    .expect("scrape succeeded")
                    .into(),
            );
        }

        let found = series
            .search([(
                "__name__",
                &ValueQuery::Equals("node_cpu_seconds_total".into()),
            )])
            .delta(0, 1);

        for s in found.samples.iter() {
            if s.value != Untyped(1.0) {
                panic!("Sample value not 1.0: {:?}", s.value)
            }
        }

        let summed = found.sum_by(["cpu"]);
        for s in summed.samples.iter() {
            if s.value != Untyped(8.0) {
                panic!("Sample value not 8.0: {:?}", s.value)
            }
        }
    }

    #[test]
    fn test_searches() {
        let scrape_text = r#"label_1{cpu="1",mode="idle"} 10001
label_1{cpu="2",mode="iowait"} 2
label_2{cpu="1",mode="irq"} 2
label_2{cpu="2",mode="nice"} 2
label_3{cpu="1",mode="irq"} 2
label_3{cpu="2",mode="nice"} 2
"#;
        let scrape: IndexedScrape =
            prometheus_parse::Scrape::parse(scrape_text.lines().map(|l| Ok(l.to_owned())))
                .unwrap()
                .into();

        let subscrape = scrape.search([("__name__", &ValueQuery::equals("label_1"))]);
        assert_eq!(
            subscrape
                .iter()
                .map(|s| s.metric.as_str())
                .collect::<Vec<_>>(),
            vec!["label_1", "label_1"]
        );

        let subscrape = scrape.search([("__name__", &ValueQuery::does_not_equal("label_1"))]);
        let metrics = subscrape
            .iter()
            .map(|s| s.metric.as_str())
            .collect::<Vec<_>>();
        assert!(metrics.contains(&"label_2"));
        assert!(metrics.contains(&"label_3"));
        assert!(!metrics.contains(&"label_1"));

        let subscrape = scrape.search([
            ("__name__", &ValueQuery::does_not_equal("label_1")),
            (
                "__name__",
                &ValueQuery::matches(&Regex::new("label.*").unwrap()),
            ),
        ]);
        let metrics = subscrape
            .iter()
            .map(|s| s.metric.as_str())
            .collect::<Vec<_>>();
        assert!(metrics.contains(&"label_2"));
        assert!(metrics.contains(&"label_3"));
        assert!(!metrics.contains(&"label_1"));
    }

    /// Helper to parse a single sample from prometheus text format
    fn parse_sample(text: &str) -> Sample {
        let scrape: IndexedScrape =
            prometheus_parse::Scrape::parse(text.lines().map(|l| Ok(l.to_owned())))
                .unwrap()
                .into();
        scrape.samples.into_iter().next().unwrap()
    }

    #[test]
    fn test_find_matching_sample_exact_match() {
        let scrape_text = r#"metric_a{device="sda",mode="read"} 100
metric_a{device="sda",mode="write"} 200
metric_a{device="sdb",mode="read"} 300
"#;
        let scrape: IndexedScrape =
            prometheus_parse::Scrape::parse(scrape_text.lines().map(|l| Ok(l.to_owned())))
                .unwrap()
                .into();

        // Create a sample to search for (same as first sample in scrape)
        let target = parse_sample(r#"metric_a{device="sda",mode="read"} 999"#);

        let found = scrape.find_matching_sample(&target);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.metric, "metric_a");
        assert_eq!(found.labels.get("device"), Some("sda"));
        assert_eq!(found.labels.get("mode"), Some("read"));
    }

    #[test]
    fn test_find_matching_sample_rejects_different_label_count() {
        // This test verifies the fix: samples with different label counts should NOT match
        let scrape_text = r#"metric_a{device="sda",mode="read"} 100
metric_a{device="sda"} 200
"#;
        let scrape: IndexedScrape =
            prometheus_parse::Scrape::parse(scrape_text.lines().map(|l| Ok(l.to_owned())))
                .unwrap()
                .into();

        // Search for sample with 2 labels - should match only the 2-label sample
        let target_two_labels = parse_sample(r#"metric_a{device="sda",mode="read"} 0"#);

        let found = scrape.find_matching_sample(&target_two_labels);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.labels.len(), 2);
        assert_eq!(found.labels.get("mode"), Some("read"));

        // Search for sample with 1 label - should match only the 1-label sample
        let target_one_label = parse_sample(r#"metric_a{device="sda"} 0"#);

        let found_single = scrape.find_matching_sample(&target_one_label);
        assert!(found_single.is_some());
        let found_single = found_single.unwrap();
        assert_eq!(found_single.labels.len(), 1);
        assert!(found_single.labels.get("mode").is_none());
    }
}
