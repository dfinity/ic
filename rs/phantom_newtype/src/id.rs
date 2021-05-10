use crate::displayer::{DisplayProxy, DisplayerOf};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

#[cfg(not(target_arch = "wasm32"))]
use proptest::prelude::Arbitrary;
#[cfg(not(target_arch = "wasm32"))]
use proptest::strategy::{MapInto, Strategy};

/// `Id<Entity, Repr>` provides a type-safe way to keep ids of
/// entities. Note that there's no default for `Repr` type, the type
/// of the identifier should be always provided explicitly.
///
/// Example:
///
/// ```
/// use phantom_newtype::Id;
///
/// struct User {
///   id: Id<User, u64>,
///   name: String,
///   posts: Vec<Id<Post, u64>>,
/// }
///
/// struct Post {
///   id: Id<Post, u64>,
///   title: String,
/// }
/// ```
///
/// `Entity` doesn't have to be a struct, any type will do. It's just a
/// tag that differentiate incompatible ids.
///
/// ```compile_fail
/// use phantom_newtype::Id;
///
/// struct Recepient {}
/// struct Message {}
///
/// type RecepientId = Id<Recepient, u64>;
/// type MessageId = Id<Message, u64>;
///
/// assert_eq!(RecepientId::from(15), MessageId::from(15));
/// ```
///
/// `Id` is cheap to copy if `Repr` is:
///
/// ```
/// use phantom_newtype::Id;
///
/// struct Message {}
/// type MessageId = Id<Message, u64>;
///
/// let x = MessageId::from(5);
/// let y = x;
/// assert_eq!(x, y);
/// ```
///
/// `Id` can be used as a key in a hash map as long as `Repr` has
/// this property:
///
/// ```
/// use phantom_newtype::Id;
/// use std::collections::HashMap;
///
/// #[derive(PartialEq, Debug)]
/// struct User {}
/// type UserId = Id<User, String>;
///
/// let mut users_by_id = HashMap::new();
/// let id = UserId::from("john".to_string());
/// users_by_id.insert(id.clone(), User {});
///
/// assert!(users_by_id.get(&id).is_some());
/// ```
///
/// Ids are ordered if the `Repr` is. Note that this is mostly useful
/// e.g. for storing Ids in a `BTreeMap`, there is usually little
/// semantic value in comparing ids.
///
/// ```
/// use std::collections::BTreeMap;
/// use phantom_newtype::Id;
///
/// #[derive(PartialEq, Debug)]
/// struct User {}
/// type UserId = Id<User, u64>;
///
/// let mut map = BTreeMap::new();
/// let id = UserId::from(5);
/// map.insert(id.clone(), User {});
///
/// assert!(map.get(&id).is_some());
/// ```
///
///
/// Ids can be serialized and deserialized with `serde`. Serialized
/// forms of `Id<Entity, Repr>` and `Repr` are identical.
///
/// ```
/// use phantom_newtype::Id;
/// use serde::{Serialize, Deserialize};
/// use serde_json;
/// struct User {}
///
/// let repr: u64 = 10;
/// let user_id = Id::<User, u64>::from(repr);
/// assert_eq!(serde_json::to_string(&user_id).unwrap(), serde_json::to_string(&repr).unwrap());
/// ```
pub struct Id<Entity, Repr>(Repr, PhantomData<Entity>);

impl<Entity, Repr> Id<Entity, Repr> {
    /// `get` returns the underlying representation of the identifier.
    ///
    /// ```
    /// use phantom_newtype::Id;
    ///
    /// struct User {}
    /// type UserId = Id<User, u64>;
    ///
    /// assert_eq!(UserId::from(15).get(), 15);
    /// ```
    pub fn get(self) -> Repr {
        self.0
    }

    /// `get_ref` returns a reference to the underlying representation of the
    /// identifier.
    ///
    /// ```
    /// use phantom_newtype::Id;
    ///
    /// struct User {}
    /// type UserId = Id<User, u64>;
    ///
    /// assert_eq!(*UserId::from(15).get_ref(), 15);
    /// ```
    pub const fn get_ref(&self) -> &Repr {
        &self.0
    }

    /// `new` is a synonym for `from` that can be evaluated in
    /// compile time. The main use-case of this functions is defining
    /// constants:
    ///
    /// ```
    /// use phantom_newtype::Id;
    /// struct User {}
    /// type UserId = Id<User, u64>;
    ///
    /// const ADMIN_ID: UserId = UserId::new(42);
    ///
    /// assert_eq!(ADMIN_ID.get(), 42);
    /// ```
    pub const fn new(repr: Repr) -> Id<Entity, Repr> {
        Id(repr, PhantomData)
    }
}

impl<Entity, Repr> Id<Entity, Repr>
where
    Entity: DisplayerOf<Id<Entity, Repr>>,
{
    /// `display` provides a machanism to implement a custom display
    /// for phantom types.
    ///
    /// ```
    /// use phantom_newtype::{Id, DisplayerOf};
    /// use std::fmt;
    ///
    /// struct Message {}
    /// type MessageId = Id<Message, [u8; 32]>;
    ///
    /// impl DisplayerOf<MessageId> for Message {
    ///   fn display(id: &MessageId, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    ///     id.get().iter().try_for_each(|b| write!(f, "{:02x}", b))
    ///   }
    /// }
    ///
    /// let vec: Vec<_> = (0u8..32u8).collect();
    /// let mut arr: [u8; 32] = [0u8; 32];
    /// (&mut arr[..]).copy_from_slice(&vec[..]);
    ///
    /// assert_eq!(format!("{}", MessageId::from(arr).display()),
    ///            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    /// ```
    pub fn display(&self) -> DisplayProxy<'_, Self, Entity> {
        DisplayProxy::new(self)
    }
}

impl<Entity, Repr> AsRef<Repr> for Id<Entity, Repr> {
    fn as_ref(&self) -> &Repr {
        self.get_ref()
    }
}

impl<Entity, Repr: Clone> Clone for Id<Entity, Repr> {
    fn clone(&self) -> Self {
        Self::from(self.0.clone())
    }
}

impl<Entity, Repr: Copy> Copy for Id<Entity, Repr> {}

impl<Entity, Repr: PartialEq> PartialEq for Id<Entity, Repr> {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.eq(&rhs.0)
    }
}

impl<Entity, Repr: PartialOrd> PartialOrd for Id<Entity, Repr> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&rhs.0)
    }
}

impl<Entity, Repr: Ord> Ord for Id<Entity, Repr> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.0.cmp(&rhs.0)
    }
}

impl<Entity, Repr: Hash> Hash for Id<Entity, Repr> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<Entity, Repr> From<Repr> for Id<Entity, Repr> {
    fn from(repr: Repr) -> Self {
        Self::new(repr)
    }
}

impl<Entity, Repr: Eq> Eq for Id<Entity, Repr> {}

impl<Entity, Repr: fmt::Debug> fmt::Debug for Id<Entity, Repr> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<Entity, Repr: fmt::Display> fmt::Display for Id<Entity, Repr> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<Entity, Repr> Serialize for Id<Entity, Repr>
where
    Repr: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, Entity, Repr> Deserialize<'de> for Id<Entity, Repr>
where
    Repr: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Repr::deserialize(deserializer).map(Id::<Entity, Repr>::from)
    }
}

/// ```
/// use phantom_newtype::Id;
/// use candid::{Decode, Encode};
///
/// enum User {}
/// type UserId = Id<User, u64>;
///
/// let id = UserId::from(3);
/// let bytes = Encode!(&id).unwrap();
/// let decoded = Decode!(&bytes, UserId).unwrap();
/// assert_eq!(id, decoded);
/// ```
impl<Entity, Repr> candid::CandidType for Id<Entity, Repr>
where
    Repr: candid::CandidType,
{
    fn id() -> candid::types::TypeId {
        Repr::id()
    }
    fn _ty() -> candid::types::Type {
        Repr::_ty()
    }
    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        self.0.idl_serialize(serializer)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<Entity, Repr: fmt::Debug + Arbitrary> Arbitrary for Id<Entity, Repr> {
    type Parameters = Repr::Parameters;
    type Strategy = MapInto<Repr::Strategy, Id<Entity, Repr>>;

    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        Repr::arbitrary_with(args).prop_map_into()
    }
}

impl<Entity, Repr: slog::Value> slog::Value for Id<Entity, Repr> {
    fn serialize(
        &self,
        record: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        self.0.serialize(record, key, serializer)
    }
}
