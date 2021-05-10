(module
  ;; good. already exported. keep it as it is
  (global (export "_g_0") (mut i32) (i32.const 0))
  ;; good. already exported. keep it as it is
  (global (export "_g_1") i32 (i32.const 1))
  ;; good. immutable, doesn't need exporting
  (global i32 (i32.const 2))
  ;; bad. needs exporting
  (global (mut i32) (i32.const 3))
)
