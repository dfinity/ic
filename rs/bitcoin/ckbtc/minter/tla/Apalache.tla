--------------------------- MODULE Apalache -----------------------------------
(*
 * This is a standard module for use with the Apalache model checker.
 * The meaning of the operators is explained in the comments.
 * Many of the operators serve as additional annotations of their arguments.
 * As we like to preserve compatibility with TLC and TLAPS, we define the
 * operator bodies by erasure. The actual interpretation of the operators is
 * encoded inside Apalache. For the moment, these operators are mirrored in
 * the class at.forsyte.apalache.tla.lir.oper.ApalacheOper.
 *                                                                          
 * Igor Konnov, Jure Kukovec, Informal Systems 2020-2022                    
 *)

(**
 * An assignment of an expression e to a state variable x. Typically, one
 * uses the non-primed version of x in the initializing predicate Init and
 * the primed version of x (that is, x') in the transition predicate Next.
 * Although TLA+ does not have a concept of a variable assignment, we find
 * this concept extremely useful for symbolic model checking. In pure TLA+,
 * one would simply write x = e, or x \in {e}.
 *
 * Apalache automatically converts some expressions of the form
 * x = e or x \in {e} into assignments. However, if you like to annotate
 * assignments by hand, you can use this operator.
 *
 * For a further discussion on that matter, see:
 * https://github.com/apalache-mc/apalache/blob/main/docs/src/idiomatic/001assignments.md
 *)
__x := __e == __x = __e

(**
 * A generator of a data structure. Given a positive integer `bound`, and
 * assuming that the type of the operator application is known, we
 * recursively generate a TLA+ data structure as a tree, whose width is
 * bound by the number `bound`.
 *
 * The body of this operator is redefined by Apalache.
 *)
Gen(__size) == {}

(**
 * Non-deterministically pick a value out of the set `S`, if `S` is non-empty.
 * If `S` is empty, return some value of the proper type.  This can be
 * understood as a non-deterministic version of CHOOSE x \in S: TRUE.
 *
 * @type: Set(a) => a;
 *)
Guess(__S) ==
    \* Since this is not supported by TLC,
    \* we fall back to the deterministic version for TLC.
    \* Apalache redefines the operator `Guess` as explained above.
    CHOOSE __x \in __S: TRUE

(**
 * Convert a set of pairs S to a function F. Note that if S contains at least
 * two pairs <<x, y>> and <<u, v>> such that x = u and y /= v,
 * then F is not uniquely defined. We use CHOOSE to resolve this ambiguity.
 * Apalache implements a more efficient encoding of this operator
 * than the default one.
 *
 * @type: Set(<<a, b>>) => (a -> b);
 *)
SetAsFun(__S) ==
    LET __Dom == { __x: <<__x, __y>> \in __S }
        __Rng == { __y: <<__x, __y>> \in __S }
    IN
    [ __x \in __Dom |-> CHOOSE __y \in __Rng: <<__x, __y>> \in __S ]

(**
 * A sequence constructor that avoids using a function constructor.
 * Since Apalache is typed, this operator is more efficient than
 * FunAsSeq([ i \in 1..N |-> F(i) ]). Apalache requires N to be
 * a constant expression.
 *
 * @type: (Int, (Int -> a)) => Seq(a);
 *)
LOCAL INSTANCE Integers
MkSeq(__N, __F(_)) ==
    \* This is the TLC implementation. Apalache does it differently.
    [ __i \in (1..__N) |-> __F(__i) ]

\* required by our default definition of FoldSeq and FunAsSeq
LOCAL INSTANCE Sequences

(**
 * As TLA+ is untyped, one can use function- and sequence-specific operators
 * interchangeably. However, to maintain correctness w.r.t. our type-system,
 * an explicit cast is needed when using functions as sequences.
 * FunAsSeq reinterprets a function over integers as a sequence.
 *
 * The parameters have the following meaning:
 *
 *  - fn is the function from 1..len that should be interpreted as a sequence.
 *  - len is the length of the sequence, len = Cardinality(DOMAIN fn),
 *    len may be a variable, a computable expression, etc.
 *  - capacity is a static upper bound on the length, that is, len <= capacity.
 *
 * @type: ((Int -> a), Int, Int) => Seq(a);
 *)
FunAsSeq(__fn, __len, __capacity) ==
    LET __FunAsSeq_elem_ctor(__i) == __fn[__i] IN
    SubSeq(MkSeq(__capacity, __FunAsSeq_elem_ctor), 1, __len)

(**
 * Annotating an expression \E x \in S: P as Skolemizable. That is, it can
 * be replaced with an expression c \in S /\ P(c) for a fresh constant c.
 * Not every exisential can be replaced with a constant, this should be done
 * with care. Apalache detects Skolemizable expressions by static analysis.
 *)
Skolem(__e) == __e

(**
 * A hint to the model checker to expand a set S, instead of dealing
 * with it symbolically. Apalache finds out which sets have to be expanded
 * by static analysis.
 *)
Expand(__S) == __S

(**
 * A hint to the model checker to replace its argument Cardinality(S) >= k
 * with a series of existential quantifiers for a constant k.
 * Similar to Skolem, this has to be done carefully. Apalache automatically
 * places this hint by static analysis.
 *)
ConstCardinality(__cardExpr) == __cardExpr

(**
 * The folding operator, used to implement computation over a set.
 * Apalache implements a more efficient encoding than the one below.
 * (from the community modules).
 *
 * @type: ((a, b) => a, a, Set(b)) => a;
 *)
RECURSIVE ApaFoldSet(_, _, _)
ApaFoldSet(__Op(_,_), __v, __S) ==
    IF __S = {}
    THEN __v
    ELSE LET __w == CHOOSE __x \in __S: TRUE IN
         LET __T == __S \ {__w} IN
         ApaFoldSet(__Op, __Op(__v,__w), __T)

(**
 * The folding operator, used to implement computation over a sequence.
 * Apalache implements a more efficient encoding than the one below.
 * (from the community modules).
 *
 * @type: ((a, b) => a, a, Seq(b)) => a;
 *)
RECURSIVE ApaFoldSeqLeft(_, _, _)
ApaFoldSeqLeft(__Op(_,_), __v, __seq) ==
    IF __seq = <<>>
    THEN __v
    ELSE ApaFoldSeqLeft(__Op, __Op(__v, Head(__seq)), Tail(__seq))

(**
 * The repetition operator, used to consecutively apply an operator, starting from
 * an initial value.
 *
 * @type: ((a, Int) => a, Int, a) => a;
 *)
RECURSIVE Repeat(_,_,_)
Repeat(__F(_,_), __N, __x) ==
        \* This is the TLC implementation. Apalache does it differently.
        IF __N <= 0
        THEN __x
        ELSE __F(Repeat(__F, __N - 1, __x), __N)

===============================================================================
