(module
  (global $g1 (import "foo" "bar") i32)
  (global $g2 i32 (i32.const 5))
  (global $g3 (mut i64) (i64.const 100))
)