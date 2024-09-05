------------------------------- MODULE Variants -------------------------------
(**
 * Operators on variants. Variants are a common programming pattern that allows
 * one to mix records of various shapes into a single set, sequence,
 * or a function.
 *
 * This module provides the default untyped implementation of the operators.
 * Apalache treats these operators as typed, so it enforces type safety of
 * variants.
 *
 * Igor Konnov, Informal Systems, 2021-2022
 *)

(**
 * A representation of the unit type.
 *
 * Useful for defining variants that don't need to wrap any values. E.g., to
 * define a type of primary colors `Red(UNIT) | Blue(UNIT) | Green(UNIT)`
 *
 * @type: UNIT;
 *)
UNIT == "U_OF_UNIT"

(**
 * Wrap a value with a variant.
 *
 * @param rec a value
 * @return the record wrapped in the variant type
 *
 * The type looks like follows, when __tagName == "Tag":
 *
 *   (Str, a) => Tag(a) | b
 *)
Variant(__tagName, __value) ==
    \* default untyped implementation
    [ tag |-> __tagName, value |-> __value ]

(**
 * Filter a set of variants with the provided tag value.
 *
 * @param `S` a set of variants that are constructed with `Variant(...)`
 * @param `tagValue` a constant string that is used to filter the set elements
 * @return the set of elements of S that are tagged with `tagValue`.
 *
 * The type looks like follows, when __tagName == "Tag":
 *
 *   (Str, Set(Tag(a) | b)) => Set(a)
 *)
VariantFilter(__tagName, __S) ==
    \* default untyped implementation
    { __d.value : __d \in { __e \in __S: __e.tag = __tagName } }

(**
 * Get the tag name that is associated with a variant.
 *
 * @param `variant` a variant that is constructed with `Variant(...)`
 * @return the tag name associated with a variant
 *
 * Its type is as follows:
 *
 *   Variant(a) => Str
 *)
VariantTag(__variant) ==
    \* default untyped implementation
    __variant.tag

(**
 * Return the value associated with the tag, when the tag equals to __tagName.
 * Otherwise, return __elseValue.
 *
 * @param `__tagName` the tag attached to the variant
 * @param `__variant` a variant that is constructed with `Variant(...)`
 * @param `__defaultValue` the default value to return, if not tagged with __tagName
 * @return the value extracted from the variant, or the __defaultValue
 *
 * Its type could look like follows:
 *
 *   (Str, Tag(a) | b, a) => a
 *)
VariantGetOrElse(__tagName, __variant, __defaultValue) ==
    \* default untyped implementation
    IF __variant.tag = __tagName
    THEN __variant.value
    ELSE __defaultValue


(**
 * Unsafely return a value of the type associated with __tagName.
 * If the variant is tagged with __tagName, then return the associated value.
 * Otherwise, return some value of the type associated with __tagName.
 *
 * @param `tagValue` the tag attached to the variant
 * @param `variant` a variant that is constructed with `Variant(...)`
 * @return the value extracted from the variant, when tagged __tagName;
 *         otherwise, return some value
 *
 * Its type could look like follows:
 *
 *   (Str, Tag(a) | b) => a
 *)
VariantGetUnsafe(__tagName, __variant) ==
    \* the default untyped implementation
    __variant.value

===============================================================================