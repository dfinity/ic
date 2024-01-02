pub mod sns;
pub mod target;

pub trait DataContract {
    fn get_name(&self) -> String;
    fn get_id(&self) -> String;
}
