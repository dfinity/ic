/// Represents a message that can be sent along the channel from a runner
/// to a collector. It needs to be returning via a join handle so the data
/// is static.
pub enum Message<T>
where
    T: 'static + Send,
{
    Body(T),
    Log(String),
    Eof,
}
