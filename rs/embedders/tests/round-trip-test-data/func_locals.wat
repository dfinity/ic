(module
  (func (param i32) (result i64) (local i32 i64) 
	local.get 0
	local.get 1
	i32.add
	i64.extend_i32_s
  )
)