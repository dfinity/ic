(module
  (type $a (func(param i32 i32) (result i32)))   
  (type $b (func (result i32)))
  (import "ic0" "msg_arg_data_size" (func (type $b)))
  (func $addTwo (type $a)
    (i32.add
      (get_local 0)
      (get_local 1)))
  (export "addTwo" (func $addTwo)))
