---- MODULE Consensus ----------------------------------------------------------

EXTENDS Sequences, Naturals

CONSTANT Blocks (* The set of all possible blocks *)

VARIABLES blockOffset, blockChain

vars == <<blockOffset, blockChain>>

TypeOk == /\ blockOffset \in Nat
          /\ blockChain \in Seq(Blocks)

MakeBlock == /\ \E b \in Blocks : blockChain' = Append(blockChain, b)
             /\ UNCHANGED blockOffset

lastBlockIndex == blockOffset + Len(blockChain)

Init == /\ blockOffset = 0
        /\ blockChain = <<>>

Next == MakeBlock

Spec == Init /\ [][Next]_vars

SmallChainConstraint == lastBlockIndex <= 5

================================================================================
