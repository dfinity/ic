# Phantom Newtype

## Requirements

### Requirement: AmountOf Type-Safe Quantities
AmountOf<Unit, Repr> provides a type-safe wrapper for quantities, preventing accidental mixing of incomparable amounts (e.g., Apples vs Oranges).

#### Scenario: Type incompatibility at compile time
- **WHEN** AmountOf<Apples, u64> and AmountOf<Oranges, u64> are compared
- **THEN** the code MUST NOT compile because different Unit types are incompatible

#### Scenario: Comparison operations
- **WHEN** two AmountOf values of the same type are compared
- **THEN** standard comparison operators (<, >, <=, >=, ==, !=) work correctly
- **AND** Ord is implemented for use in BTreeMap and sorting

#### Scenario: Arithmetic operations
- **WHEN** two AmountOf values of the same type are added or subtracted
- **THEN** the result is an AmountOf of the same type
- **AND** add, sub, add_assign, sub_assign, increment, decrement are all supported

#### Scenario: Scalar multiplication and division
- **WHEN** an AmountOf is multiplied by a scalar
- **THEN** the result is an AmountOf (scaled amount)
- **WHEN** two AmountOf values are divided
- **THEN** the result is a scalar (ratio, not an amount)
- **WHEN** an AmountOf is divided by a scalar
- **THEN** the result is an AmountOf (integer division for integer Repr)

#### Scenario: Sum iterator
- **WHEN** an iterator of AmountOf values is summed
- **THEN** the result is an AmountOf of the same type

#### Scenario: Serialization transparency
- **WHEN** an AmountOf is serialized/deserialized via serde
- **THEN** the serialized form is identical to that of the underlying Repr

#### Scenario: Display customization
- **WHEN** the Unit type implements DisplayerOf<AmountOf<Unit, Repr>>
- **THEN** the custom display format is used (e.g., NumBytesTag formats as "123.45 MiB")

### Requirement: Id Type-Safe Identifiers
Id<Entity, Repr> provides type-safe identifiers where different entity types cannot be confused.

#### Scenario: Type incompatibility at compile time
- **WHEN** Id<User, u64> and Id<Post, u64> are compared
- **THEN** the code MUST NOT compile because they are different types

#### Scenario: Copy semantics for Copy Repr
- **WHEN** Id is used with a Copy Repr (like u64)
- **THEN** Id is also Copy, allowing cheap duplication

#### Scenario: Hash map compatibility
- **WHEN** Id<Entity, String> is used as a HashMap key
- **THEN** standard hash map operations (insert, get) work correctly

#### Scenario: BTreeMap compatibility
- **WHEN** Id<Entity, u64> is used as a BTreeMap key
- **THEN** ordering is based on the underlying Repr

#### Scenario: Serialization transparency
- **WHEN** an Id is serialized/deserialized via serde
- **THEN** the serialized form is identical to that of the underlying Repr
- **AND** Id<Entity, u64> serializes the same as a bare u64

#### Scenario: get() accessor
- **WHEN** id.get() is called
- **THEN** it returns the underlying Repr value

### Requirement: BitMask Type-Safe Bit Manipulation
BitMask provides type-safe bit mask operations.

#### Scenario: BitMask operations
- **WHEN** BitMask operations are performed
- **THEN** standard bitwise operations (AND, OR, XOR, NOT) are supported with type safety

### Requirement: DisplayProxy Custom Display Delegation
DisplayProxy and DisplayerOf allow custom Display implementations for phantom-typed wrappers.

#### Scenario: DisplayerOf override
- **WHEN** a Unit type implements DisplayerOf for AmountOf or Id
- **THEN** the Display trait uses the custom implementation
- **WHEN** no DisplayerOf is implemented
- **THEN** the default Debug or standard display of Repr is used
