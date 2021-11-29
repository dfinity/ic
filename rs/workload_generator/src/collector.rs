use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::{message::Message, plan::Plan};
use std::{
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::{Duration, SystemTime},
};

/// Kicks off the collector which is a background thread. The collector will
/// capture all data sent to the sender and then will return on the handle the
/// entire dataset.
///
/// The plan is essential to pre-allocating the array.
pub fn start<T>(
    plan: Plan,
    periodic_output: bool,
) -> (Sender<Message<T>>, thread::JoinHandle<Vec<T>>)
where
    T: 'static + Send + RequestInfo,
{
    let (sender, receiver) = channel::<Message<T>>();
    (
        sender,
        thread::spawn(move || collect(&receiver, plan, periodic_output)),
    )
}

pub trait RequestInfo {
    fn is_succ(&self) -> bool;
}

fn collect<T>(receiver: &Receiver<Message<T>>, plan: Plan, periodic_output: bool) -> Vec<T>
where
    T: 'static + Send + RequestInfo,
{
    let num_expected = plan.requests;
    let mut eof_received = false;
    let mut messages: Vec<T> = Vec::with_capacity(plan.requests);

    let m = MultiProgress::new();

    let pb_success = if !periodic_output {
        let pb_success = m.add(ProgressBar::new(num_expected as u64));
        pb_success.set_style(
            ProgressStyle::default_bar()
                .template("{msg} {percent:>3}% {per_sec:>20} {bar:40.green} {pos:5}/{len:7}"),
        );
        pb_success.set_message("Completed successfully");
        pb_success.set_position(0);
        Some(pb_success)
    } else {
        None
    };

    let pb_fail = if !periodic_output {
        let pb_fail = m.add(ProgressBar::new(num_expected as u64));
        pb_fail.set_style(
            ProgressStyle::default_bar()
                .template("{msg} {percent:>3}% {per_sec:>20} {bar:40.red} {pos:5}/{len:7}"),
        );
        pb_fail.set_message("Completed with failure");
        pb_fail.set_position(0);
        Some(pb_fail)
    } else {
        None
    };

    std::thread::spawn(move || {
        m.join().unwrap();
    });

    let mut num_succ = 0;
    let mut last_num_succ = 0;
    let mut num_fail = 0;

    let mut last_print = SystemTime::now();
    let time_start = SystemTime::now();

    while !eof_received {
        match receiver
            .recv()
            .unwrap_or_else(|_| panic!("Cannot receive from receiver in collect()"))
        {
            Message::Body(message) => {
                if message.is_succ() {
                    if let Some(pb_success) = pb_success.as_ref() {
                        pb_success.inc(1);
                    }
                    num_succ += 1;
                } else {
                    if let Some(pb_fail) = pb_fail.as_ref() {
                        pb_fail.inc(1);
                    }
                    num_fail += 1;
                }

                if periodic_output {
                    let last_print_elapsed = last_print.elapsed().unwrap();
                    if last_print_elapsed > Duration::from_secs(10) {
                        let total_elapsed = time_start.elapsed().unwrap();
                        let delta_succ = num_succ - last_num_succ;
                        println!(
                            "Progress {:?}: success = {}, failed = {}, current RPS = {}, effective RPS = {}",
                            total_elapsed,
                            num_succ,
                            num_fail,
                            (delta_succ as f32) / last_print_elapsed.as_secs_f32(),
                            (num_succ as f32) / total_elapsed.as_secs_f32(),
                        );
                        last_print = SystemTime::now();
                        last_num_succ = num_succ;
                    }
                }

                messages.push(message);
            }
            Message::Log(s) => {
                if let Some(pb_success) = pb_success.as_ref() {
                    pb_success.println(s);
                }
            }
            Message::Eof => {
                if let Some(pb_success) = pb_success.as_ref() {
                    pb_success.finish_and_clear();
                }
                eof_received = true;
            }
        }
    }

    if periodic_output {
        let elapsed = time_start.elapsed().unwrap();
        println!(
            "Summary {:?}: success = {}, failed = {}, effective RPS = {}",
            elapsed,
            num_succ,
            num_fail,
            (num_succ as f32) / elapsed.as_secs_f32(),
        );
    }
    messages
}
