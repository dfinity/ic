pub(crate) trait PayloadSize<T> {
    fn payload_size(t: T) -> usize;
}
