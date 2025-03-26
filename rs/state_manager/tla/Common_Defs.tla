---- MODULE Common_Defs ----
EXTENDS TLC, Naturals

\* TODO: TLC doesn't evaluate CHOOSE properly here; it sticks with the same evaluation for all
\* traces. Which means the whole model gets evaluated only for a single function, instead of
\* all functions between the two sets.
\* Execute_Block(s, b) == (CHOOSE f \in [STATES \X BLOCK_PAYLOADS -> STATES] : TRUE)[<<s, b>>]
VARIABLE 
    genesis_state,
    exec_f

CONSTANT
    CHECKPOINT_INTERVAL,
    STATES,
    BLOCK_PAYLOADS,
    MAX_HEIGHT

GENESIS_HEIGHT == 0
HEIGHTS == 0..MAX_HEIGHT
HASHES == STATES

IS_CHECKPOINT_HEIGHT(h) == h % CHECKPOINT_INTERVAL = 0
All_Checkpoint_Heights == {h \in HEIGHTS : IS_CHECKPOINT_HEIGHT(h)}
Previous_Checkpoint_Height(h) == h - (h % CHECKPOINT_INTERVAL)
Execute_Block(s, b) == exec_f[<<s, b>>]

Init_Common ==
    exec_f \in [STATES \X BLOCK_PAYLOADS -> STATES]

\* The "correct" manifest hash function. In the model, we just need an arbitrary injective function, since we
\* want the function to be collision-resistant. The identity function will do.
\* We can model divergence by letting the node a different manifest hash function.
correct_m_hash == [s \in STATES |-> s]


====