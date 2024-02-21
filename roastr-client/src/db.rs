use strum_macros::EnumIter;

#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
