---- MODULE Util ----
EXTENDS TLC

Restrict(f, S) == [ x \in DOMAIN f \cap S |-> f[x] ]
Remove_Arguments(f, S) == [ x \in DOMAIN f \ S |-> f[x] ]

\* Function intersections, when functions are viewed as sets of pairs
Intersect_Funs(f, g) == [ x \in {y \in DOMAIN f \cap DOMAIN g: f[y] = g[y] } |-> f[x] ]

Range(f) == {f[x] : x \in DOMAIN f}


====