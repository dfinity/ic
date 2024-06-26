Wasm Instructions Benchmark Results
===================================

This file is autogenerated by the `run_wasm_benchmarks.sh`

| INSTRUCTION                           | BENCHMARK RESULT, NS | COST | COMMENT          |
| ------------------------------------- | -------------------- | ---- | ---------------- |
| overhead                              | 139062               | 0    | OVERHEAD (0)     |
| const/i32.const                       | 2294117              | 1    |
| const/i64.const                       | 2288495              | 1    |
| const/f32.const                       | 2548363              | 1    |
| const/f64.const                       | 3238092              | 1    |
| iunop/i32.clz                         | 2277650              | 1    |
| iunop/i32.ctz                         | 2287004              | 1    |
| iunop/i32.popcnt                      | 2282780              | 1    |
| iunop/i64.clz                         | 2306009              | 1    |
| iunop/i64.ctz                         | 2285120              | 1    |
| iunop/i64.popcnt                      | 2281801              | 1    |
| funop/f32.abs                         | 3089266              | 1    |
| funop/f32.neg                         | 3080070              | 1    |
| funop/f64.abs                         | 3801166              | 1    |
| funop/f64.neg                         | 3761747              | 1    |
| funop/f32.ceil                        | 4832989              | 2    |
| funop/f32.floor                       | 4824093              | 2    |
| funop/f32.trunc                       | 4839689              | 2    |
| funop/f32.nearest                     | 4832886              | 2    |
| funop/f64.ceil                        | 5512046              | 2    |
| funop/f64.floor                       | 5518989              | 2    |
| funop/f64.trunc                       | 5537904              | 2    |
| funop/f64.nearest                     | 5531477              | 2    |
| funop/f32.sqrt                        | 11905466             | 5    |
| funop/f64.sqrt                        | 18814340             | 8    |
| ibinop/i32.add                        | 2282094              | 1    |
| ibinop/i32.sub                        | 2284108              | 1    |
| ibinop/i32.mul                        | 2289414              | 1    |
| ibinop/i32.and                        | 2283086              | 1    |
| ibinop/i32.or                         | 2277048              | 1    |
| ibinop/i32.xor                        | 2281910              | 1    |
| ibinop/i32.shl                        | 2280947              | 1    |
| ibinop/i32.shr_s                      | 2284374              | 1    |
| ibinop/i32.shr_u                      | 2270135              | 1    | BASELINE (1)     |
| ibinop/i32.rotl                       | 2287721              | 1    |
| ibinop/i32.rotr                       | 2295530              | 1    |
| ibinop/i64.add                        | 2291685              | 1    |
| ibinop/i64.sub                        | 2282409              | 1    |
| ibinop/i64.mul                        | 2281051              | 1    |
| ibinop/i64.and                        | 2286730              | 1    |
| ibinop/i64.or                         | 2276735              | 1    |
| ibinop/i64.xor                        | 2277718              | 1    |
| ibinop/i64.shl                        | 2282608              | 1    |
| ibinop/i64.shr_s                      | 2277050              | 1    |
| ibinop/i64.shr_u                      | 2276375              | 1    |
| ibinop/i64.rotl                       | 2276415              | 1    |
| ibinop/i64.rotr                       | 2283454              | 1    |
| ibinop/i32.div_s                      | 49079257             | 22   |
| ibinop/i32.div_u                      | 49114277             | 22   |
| ibinop/i32.rem_s                      | 49116383             | 22   |
| ibinop/i32.rem_u                      | 49086217             | 22   |
| ibinop/i64.div_s                      | 49082560             | 22   |
| ibinop/i64.div_u                      | 49059522             | 22   |
| ibinop/i64.rem_s                      | 49109282             | 22   |
| ibinop/i64.rem_u                      | 49087455             | 22   |
| fbinop/f32.add                        | 4818889              | 2    |
| fbinop/f32.sub                        | 4819607              | 2    |
| fbinop/f32.mul                        | 4845702              | 2    |
| fbinop/f64.add                        | 5531045              | 2    |
| fbinop/f64.sub                        | 5520096              | 2    |
| fbinop/f64.mul                        | 5520481              | 2    |
| fbinop/f32.div                        | 7737994              | 3    |
| fbinop/f64.div                        | 10830097             | 5    |
| fbinop/f32.min                        | 38854283             | 18   |
| fbinop/f32.max                        | 39750419             | 18   |
| fbinop/f64.min                        | 38766942             | 18   |
| fbinop/f64.max                        | 38081549             | 17   |
| fbinop/f32.copysign                   | 4496968              | 2    |
| fbinop/f64.copysign                   | 6585903              | 3    |
| itestop/i32.eqz                       | 2502424              | 1    |
| itestop/i64.eqz                       | 2649138              | 1    |
| irelop/i32.eq                         | 2640778              | 1    |
| irelop/i32.ne                         | 2652871              | 1    |
| irelop/i32.lt_s                       | 2643597              | 1    |
| irelop/i32.lt_u                       | 2658234              | 1    |
| irelop/i32.gt_s                       | 2655809              | 1    |
| irelop/i32.gt_u                       | 2642484              | 1    |
| irelop/i32.le_s                       | 2634246              | 1    |
| irelop/i32.le_u                       | 2649994              | 1    |
| irelop/i32.ge_s                       | 2647284              | 1    |
| irelop/i32.ge_u                       | 2639199              | 1    |
| irelop/i64.eq                         | 2512905              | 1    |
| irelop/i64.ne                         | 2513447              | 1    |
| irelop/i64.lt_s                       | 2507571              | 1    |
| irelop/i64.lt_u                       | 2506327              | 1    |
| irelop/i64.gt_s                       | 2512829              | 1    |
| irelop/i64.gt_u                       | 2522030              | 1    |
| irelop/i64.le_s                       | 2507221              | 1    |
| irelop/i64.le_u                       | 2513102              | 1    |
| irelop/i64.ge_s                       | 2499291              | 1    |
| irelop/i64.ge_u                       | 2500342              | 1    |
| frelop/f32.eq                         | 4784951              | 2    |
| frelop/f32.ne                         | 4790252              | 2    |
| frelop/f64.eq                         | 4808634              | 2    |
| frelop/f64.ne                         | 4788326              | 2    |
| frelop/f32.lt                         | 3160986              | 1    |
| frelop/f32.gt                         | 3158917              | 1    |
| frelop/f32.le                         | 3170030              | 1    |
| frelop/f32.ge                         | 3163137              | 1    |
| frelop/f64.lt                         | 3150350              | 1    |
| frelop/f64.gt                         | 3161521              | 1    |
| frelop/f64.le                         | 3164264              | 1    |
| frelop/f64.ge                         | 3143046              | 1    |
| cvtop/i32.extend8_s                   | 2276868              | 1    |
| cvtop/i32.extend16_s                  | 2276122              | 1    |
| cvtop/i64.extend8_s                   | 2275913              | 1    |
| cvtop/i64.extend16_s                  | 2273014              | 1    |
| cvtop/f32.convert_i32_s               | 2548897              | 1    |
| cvtop/f32.convert_i64_s               | 2700594              | 1    |
| cvtop/f64.convert_i32_s               | 2549144              | 1    |
| cvtop/f64.convert_i64_s               | 2683211              | 1    |
| cvtop/i64.extend32_s                  | 2277016              | 1    |
| cvtop/i32.wrap_i64                    | 2278694              | 1    |
| cvtop/i64.extend_i32_s                | 2280388              | 1    |
| cvtop/i64.extend_i32_u                | 2276396              | 1    |
| cvtop/f32.demote_f64                  | 5389941              | 2    |
| cvtop/f64.promote_f32                 | 6052759              | 2    |
| cvtop/f32.reinterpret_i32             | 2281607              | 1    |
| cvtop/f64.reinterpret_i64             | 2276087              | 1    |
| cvtop/f32.convert_i32_u               | 3022190              | 1    |
| cvtop/f64.convert_i32_u               | 3004076              | 1    |
| cvtop/i32.reinterpret_f32             | 2820940              | 1    |
| cvtop/i64.reinterpret_f64             | 2828228              | 1    |
| cvtop/i32.trunc_f32_s                 | 52892010             | 24   |
| cvtop/i32.trunc_f32_u                 | 49845526             | 23   |
| cvtop/i32.trunc_f64_s                 | 46183460             | 21   |
| cvtop/i32.trunc_f64_u                 | 50388025             | 23   |
| cvtop/i64.trunc_f32_s                 | 52552609             | 24   |
| cvtop/i64.trunc_f32_u                 | 52345262             | 24   |
| cvtop/i64.trunc_f64_s                 | 51541639             | 24   |
| cvtop/i64.trunc_f64_u                 | 56765422             | 26   |
| cvtop/i64.trunc_sat_f32_s             | 37700044             | 17   |
| cvtop/i64.trunc_sat_f64_s             | 34891964             | 16   |
| cvtop/i32.trunc_sat_f32_u             | 108094177            | 50   |
| cvtop/i32.trunc_sat_f64_u             | 109814516            | 51   |
| cvtop/i64.trunc_sat_f32_u             | 107494462            | 50   |
| cvtop/i64.trunc_sat_f64_u             | 108863509            | 51   |
| cvtop/i32.trunc_sat_f32_s             | 36494463             | 17   |
| cvtop/i32.trunc_sat_f64_s             | 39264541             | 18   |
| cvtop/f32.convert_i64_u               | 30166727             | 14   |
| cvtop/f64.convert_i64_u               | 29952019             | 13   |
| refop/ref.func                        | 222388050            | 104  |
| refop/ref.is_null                     | 232583054            | 4    | = 109 - ref.func |
| varop/local.get                       | 2281205              | 1    |
| varop/global.get                      | 2292583              | 1    |
| varop/global.set                      | 2281682              | 1    |
| varop/local.tee                       | 2275606              | 1    |
| tabop/table.get                       | 6774094              | 3    |
| tabop/table.size                      | 2285588              | 1    |
| memop/i32.load                        | 3139286              | 1    |
| memop/i64.load                        | 3179548              | 1    |
| memop/f32.load                        | 3650386              | 1    |
| memop/f64.load                        | 3644321              | 1    |
| memop/i32.store                       | 3070695              | 1    |
| memop/i64.store                       | 3080833              | 1    |
| memop/f32.store                       | 3004619              | 1    |
| memop/f64.store                       | 2994891              | 1    |
| memop/i32.load8_s                     | 3335641              | 1    |
| memop/i32.load8_u                     | 3311818              | 1    |
| memop/i32.load16_s                    | 3329692              | 1    |
| memop/i32.load16_u                    | 3313553              | 1    |
| memop/i64.load8_s                     | 3327915              | 1    |
| memop/i64.load8_u                     | 3339366              | 1    |
| memop/i64.load16_s                    | 3335801              | 1    |
| memop/i64.load16_u                    | 3314977              | 1    |
| memop/i64.load32_s                    | 3173561              | 1    |
| memop/i64.load32_u                    | 3141991              | 1    |
| memop/i32.store8                      | 3088941              | 1    |
| memop/i32.store16                     | 3112168              | 1    |
| memop/i64.store8                      | 3099665              | 1    |
| memop/i64.store16                     | 3073307              | 1    |
| memop/i64.store32                     | 3089168              | 1    |
| memop/memory.size                     | 29983891             | 14   |
| memop/memory.grow                     | 1013755413           | 475  |
| memop/memory.fill                     | 209740450            | 98   |
| memop/memory.copy                     | 234136065            | 109  |
| ctrlop/select                         | 4721446              | 2    |
| ctrlop/call                           | 22623684             | 10   |
| ctrlop/call_indirect                  | 49193868             | 23   |
| vconst/v128.const                     | 2279475              | 1    |
| vconst/v128.const_add_locals          | 2286726              | 1    |
| vconst/v128.const_add_constants       | 3906932              | 1    |
| vvunop/v128.not                       | 2281380              | 1    |
| vvbinop/v128.and                      | 2283393              | 1    |
| vvbinop/v128.andnot                   | 2285421              | 1    |
| vvbinop/v128.or                       | 2286500              | 1    |
| vvbinop/v128.xor                      | 2285266              | 1    |
| vvternop/v128.bitselect               | 2951872              | 1    |
| vvtestop/v128.any_true                | 3393005              | 1    |
| vshuffle/i8x16.shuffle                | 6579499              | 3    |
| vswizzle/i8x16.swizzle                | 3238868              | 1    |
| vsplat/i8x16.splat                    | 2694720              | 1    |
| vsplat/i16x8.splat                    | 2699343              | 1    |
| vsplat/i32x4.splat                    | 2693483              | 1    |
| vsplat/i64x2.splat                    | 2838601              | 1    |
| vsplat/f32x4.splat                    | 2292233              | 1    |
| vsplat/f64x2.splat                    | 2277681              | 1    |
| vextlane/i32x4.extract_lane           | 2288834              | 1    |
| vextlane/i64x2.extract_lane           | 2281040              | 1    |
| vextlane/f32x4.extract_lane           | 2285973              | 1    |
| vextlane/f64x2.extract_lane           | 2279043              | 1    |
| vextlane/i8x16.extract_lane_s         | 3134180              | 1    |
| vextlane/i8x16.extract_lane_u         | 3140567              | 1    |
| vextlane/i16x8.extract_lane_s         | 3131464              | 1    |
| vextlane/i16x8.extract_lane_u         | 3122871              | 1    |
| vreplane/i8x16.replace_lane           | 2630529              | 1    |
| vreplane/i16x8.replace_lane           | 2678328              | 1    |
| vreplane/i32x4.replace_lane           | 2628713              | 1    |
| vreplane/i64x2.replace_lane           | 2765207              | 1    |
| vreplane/f32x4.replace_lane           | 2296442              | 1    |
| vreplane/f64x2.replace_lane           | 2287761              | 1    |
| virelop/i8x16.eq                      | 2293488              | 1    |
| virelop/i8x16.ne                      | 3111266              | 1    |
| virelop/i8x16.lt_s                    | 2281040              | 1    |
| virelop/i8x16.gt_s                    | 2291192              | 1    |
| virelop/i8x16.le_s                    | 2820961              | 1    |
| virelop/i8x16.le_u                    | 2564682              | 1    |
| virelop/i8x16.ge_s                    | 2847484              | 1    |
| virelop/i8x16.ge_u                    | 2550260              | 1    |
| virelop/i16x8.eq                      | 2282920              | 1    |
| virelop/i16x8.ne                      | 3089897              | 1    |
| virelop/i16x8.lt_s                    | 2280684              | 1    |
| virelop/i16x8.gt_s                    | 2279632              | 1    |
| virelop/i16x8.le_s                    | 2561806              | 1    |
| virelop/i16x8.le_u                    | 2822781              | 1    |
| virelop/i16x8.ge_s                    | 2548316              | 1    |
| virelop/i16x8.ge_u                    | 2829451              | 1    |
| virelop/i32x4.eq                      | 2283448              | 1    |
| virelop/i32x4.ne                      | 3106255              | 1    |
| virelop/i32x4.lt_s                    | 2286249              | 1    |
| virelop/i32x4.gt_s                    | 2280790              | 1    |
| virelop/i32x4.le_s                    | 2825269              | 1    |
| virelop/i32x4.le_u                    | 2828294              | 1    |
| virelop/i32x4.ge_s                    | 2826074              | 1    |
| virelop/i32x4.ge_u                    | 2835173              | 1    |
| virelop/i64x2.eq                      | 2288031              | 1    |
| virelop/i64x2.ne                      | 3230420              | 1    |
| virelop/i64x2.lt_s                    | 2285252              | 1    |
| virelop/i64x2.gt_s                    | 2282410              | 1    |
| virelop/i64x2.le_s                    | 3220222              | 1    |
| virelop/i64x2.ge_s                    | 3232310              | 1    |
| virelop/i8x16.lt_u                    | 4437719              | 2    |
| virelop/i8x16.gt_u                    | 4438374              | 2    |
| virelop/i16x8.lt_u                    | 4436135              | 2    |
| virelop/i16x8.gt_u                    | 4442673              | 2    |
| virelop/i32x4.lt_u                    | 4434795              | 2    |
| virelop/i32x4.gt_u                    | 4451656              | 2    |
| vfrelop/f32x4.eq                      | 2289693              | 1    |
| vfrelop/f32x4.ne                      | 2290051              | 1    |
| vfrelop/f32x4.lt                      | 2289498              | 1    |
| vfrelop/f32x4.gt                      | 2284377              | 1    |
| vfrelop/f32x4.le                      | 2290232              | 1    |
| vfrelop/f32x4.ge                      | 2281284              | 1    |
| vfrelop/f64x2.eq                      | 2277818              | 1    |
| vfrelop/f64x2.ne                      | 2282373              | 1    |
| vfrelop/f64x2.lt                      | 2291040              | 1    |
| vfrelop/f64x2.gt                      | 2282748              | 1    |
| vfrelop/f64x2.le                      | 2294532              | 1    |
| vfrelop/f64x2.ge                      | 2288775              | 1    |
| viunop/i8x16.abs                      | 2291468              | 1    |
| viunop/i16x8.abs                      | 2280046              | 1    |
| viunop/i32x4.abs                      | 2279184              | 1    |
| viunop/i64x2.abs                      | 3089763              | 1    |
| viunop/i8x16.neg                      | 2289275              | 1    |
| viunop/i16x8.neg                      | 2286706              | 1    |
| viunop/i32x4.neg                      | 2291721              | 1    |
| viunop/i64x2.neg                      | 2285494              | 1    |
| viunop/i8x16.popcnt                   | 7658621              | 3    |
| vq15mulr/i16x8.q15mulr_sat_s          | 3784516              | 1    |
| vdot/i32x4.dot_i16x8_s                | 2280798              | 1    |
| vfunop/f32x4.abs                      | 4432879              | 2    |
| vfunop/f32x4.neg                      | 4437159              | 2    |
| vfunop/f64x2.abs                      | 4443033              | 2    |
| vfunop/f64x2.neg                      | 4439775              | 2    |
| vfunop/f32x4.ceil                     | 4715478              | 2    |
| vfunop/f32x4.floor                    | 4707083              | 2    |
| vfunop/f32x4.trunc                    | 4731216              | 2    |
| vfunop/f32x4.nearest                  | 4741693              | 2    |
| vfunop/f64x2.ceil                     | 4743789              | 2    |
| vfunop/f64x2.floor                    | 4736929              | 2    |
| vfunop/f64x2.trunc                    | 4768758              | 2    |
| vfunop/f64x2.nearest                  | 4722029              | 2    |
| vfunop/f32x4.sqrt                     | 11909759             | 5    |
| vfunop/f64x2.sqrt                     | 28754052             | 13   |
| vitestop/i8x16.all_true               | 4020501              | 1    |
| vitestop/i16x8.all_true               | 4009930              | 1    |
| vitestop/i32x4.all_true               | 4007172              | 1    |
| vitestop/i64x2.all_true               | 4127105              | 1    |
| vbitmask/i8x16.bitmask                | 2812589              | 1    |
| vbitmask/i16x8.bitmask                | 2999613              | 1    |
| vbitmask/i32x4.bitmask                | 2825318              | 1    |
| vbitmask/i64x2.bitmask                | 2821670              | 1    |
| vnarrow/i8x16.narrow_i16x8_s          | 2278820              | 1    |
| vnarrow/i8x16.narrow_i16x8_u          | 2290517              | 1    |
| vnarrow/i16x8.narrow_i32x4_s          | 2286178              | 1    |
| vnarrow/i16x8.narrow_i32x4_u          | 2283914              | 1    |
| vextend/i16x8.extend_low_i8x16_s      | 2279806              | 1    |
| vextend/i16x8.extend_low_i8x16_u      | 2281460              | 1    |
| vextend/i32x4.extend_low_i16x8_s      | 2287162              | 1    |
| vextend/i32x4.extend_low_i16x8_u      | 2288149              | 1    |
| vextend/i64x2.extend_low_i32x4_s      | 2274830              | 1    |
| vextend/i64x2.extend_low_i32x4_u      | 2290239              | 1    |
| vextend/i16x8.extend_high_i8x16_s     | 3364912              | 1    |
| vextend/i16x8.extend_high_i8x16_u     | 2299492              | 1    |
| vextend/i32x4.extend_high_i16x8_s     | 3365884              | 1    |
| vextend/i32x4.extend_high_i16x8_u     | 2285125              | 1    |
| vextend/i64x2.extend_high_i32x4_s     | 3363150              | 1    |
| vextend/i64x2.extend_high_i32x4_u     | 2289037              | 1    |
| vishiftop/i16x8.shl                   | 4905322              | 2    |
| vishiftop/i16x8.shr_s                 | 4920384              | 2    |
| vishiftop/i16x8.shr_u                 | 4653229              | 2    |
| vishiftop/i32x4.shl                   | 4645202              | 2    |
| vishiftop/i32x4.shr_s                 | 4605475              | 2    |
| vishiftop/i32x4.shr_u                 | 4839191              | 2    |
| vishiftop/i64x2.shl                   | 4869598              | 2    |
| vishiftop/i64x2.shr_u                 | 4896717              | 2    |
| vishiftop/i8x16.shl                   | 6606060              | 3    |
| vishiftop/i8x16.shr_s                 | 7487786              | 3    |
| vishiftop/i8x16.shr_u                 | 5805345              | 2    |
| vishiftop/i64x2.shr_s                 | 8202532              | 3    |
| vibinop/i8x16.add                     | 2290777              | 1    |
| vibinop/i8x16.sub                     | 2277513              | 1    |
| vibinop/i16x8.add                     | 2286560              | 1    |
| vibinop/i16x8.sub                     | 2297935              | 1    |
| vibinop/i32x4.add                     | 2288857              | 1    |
| vibinop/i32x4.sub                     | 2279913              | 1    |
| vibinop/i64x2.add                     | 2282895              | 1    |
| vibinop/i64x2.sub                     | 2285539              | 1    |
| viminmaxop/i8x16.min_s                | 2280439              | 1    |
| viminmaxop/i8x16.min_u                | 2281968              | 1    |
| viminmaxop/i8x16.max_s                | 2282247              | 1    |
| viminmaxop/i8x16.max_u                | 2280849              | 1    |
| viminmaxop/i16x8.min_s                | 2280901              | 1    |
| viminmaxop/i16x8.min_u                | 2288799              | 1    |
| viminmaxop/i16x8.max_s                | 2277870              | 1    |
| viminmaxop/i16x8.max_u                | 2285753              | 1    |
| viminmaxop/i32x4.min_s                | 2279967              | 1    |
| viminmaxop/i32x4.min_u                | 2285015              | 1    |
| viminmaxop/i32x4.max_s                | 2282701              | 1    |
| viminmaxop/i32x4.max_u                | 2285599              | 1    |
| visatbinop/i8x16.add_sat_s            | 2280666              | 1    |
| visatbinop/i8x16.add_sat_u            | 2294966              | 1    |
| visatbinop/i8x16.sub_sat_s            | 2290257              | 1    |
| visatbinop/i8x16.sub_sat_u            | 2280274              | 1    |
| visatbinop/i16x8.add_sat_s            | 2282386              | 1    |
| visatbinop/i16x8.add_sat_u            | 2287171              | 1    |
| visatbinop/i16x8.sub_sat_s            | 2293264              | 1    |
| visatbinop/i16x8.sub_sat_u            | 2278714              | 1    |
| vimul/i16x8.mul                       | 2285924              | 1    |
| vimul/i32x4.mul                       | 4442625              | 2    |
| vimul/i64x2.mul                       | 8696470              | 4    |
| vavgr/i8x16.avgr_u                    | 2288912              | 1    |
| vavgr/i16x8.avgr_u                    | 2284714              | 1    |
| vextmul/i16x8.extmul_low_i8x16_s      | 3376533              | 1    |
| vextmul/i64x2.extmul_low_i32x4_s      | 3482095              | 1    |
| vextmul/i64x2.extmul_high_i32x4_s     | 3497125              | 1    |
| vextmul/i64x2.extmul_low_i32x4_u      | 3371070              | 1    |
| vextmul/i64x2.extmul_high_i32x4_u     | 3354884              | 1    |
| vextmul/i16x8.extmul_high_i8x16_s     | 5527014              | 2    |
| vextmul/i16x8.extmul_low_i8x16_u      | 3372046              | 1    |
| vextmul/i16x8.extmul_high_i8x16_u     | 4436641              | 2    |
| vextmul/i32x4.extmul_low_i16x8_s      | 4438891              | 2    |
| vextmul/i32x4.extmul_high_i16x8_s     | 4436691              | 2    |
| vextmul/i32x4.extmul_low_i16x8_u      | 4447665              | 2    |
| vextmul/i32x4.extmul_high_i16x8_u     | 4432009              | 2    |
| vextadd/i16x8.extadd_pairwise_i8x16_s | 2958664              | 1    |
| vextadd/i16x8.extadd_pairwise_i8x16_u | 2422942              | 1    |
| vextadd/i32x4.extadd_pairwise_i16x8_s | 2386428              | 1    |
| vextadd/i32x4.extadd_pairwise_i16x8_u | 6300985              | 2    |
| vfbinop/f32x4.add                     | 4706482              | 2    |
| vfbinop/f32x4.sub                     | 4718986              | 2    |
| vfbinop/f32x4.mul                     | 4732541              | 2    |
| vfbinop/f64x2.add                     | 4704300              | 2    |
| vfbinop/f64x2.sub                     | 4695326              | 2    |
| vfbinop/f64x2.mul                     | 4714185              | 2    |
| vfbinop/f32x4.div                     | 20378557             | 9    |
| vfbinop/f64x2.div                     | 22531606             | 10   |
| vfbinop/f32x4.min                     | 8453136              | 3    |
| vfbinop/f32x4.max                     | 9222678              | 4    |
| vfbinop/f64x2.min                     | 8412447              | 3    |
| vfbinop/f64x2.max                     | 9272221              | 4    |
| vfbinop/f32x4.pmin                    | 2284672              | 1    |
| vfbinop/f32x4.pmax                    | 2282812              | 1    |
| vfbinop/f64x2.pmin                    | 2292003              | 1    |
| vfbinop/f64x2.pmax                    | 2283124              | 1    |
| vtrunc/i32x4.trunc_sat_f32x4_s        | 5316438              | 2    |
| vtrunc/i32x4.trunc_sat_f64x2_s_zero   | 4037134              | 1    |
| vtrunc/i32x4.trunc_sat_f32x4_u        | 9773760              | 4    |
| vtrunc/i32x4.trunc_sat_f64x2_u_zero   | 6273400              | 2    |
| vconvert/f32x4.convert_i32x4_s        | 2287934              | 1    |
| vconvert/f64x2.convert_low_i32x4_s    | 2285302              | 1    |
| vconvert/f32x4.convert_i32x4_u        | 10500593             | 4    |
| vconvert/f64x2.convert_low_i32x4_u    | 4056735              | 1    |
| vdemote/f32x4.demote_f64x2_zero       | 4448410              | 2    |
| vpromote/f64x2.promote_low_f32x4      | 4476502              | 2    |
| vvar/local.get                        | 2272716              | 1    |
| vvar/global.get                       | 17216559             | 8    |
| vvar/global.set                       | 2285555              | 1    |
| vvar/local.tee                        | 2283432              | 1    |
| vmem/v128.load                        | 3681680              | 1    |
| vmem/v128.load_unaligned              | 3662602              | 1    |
| vmem/v128.store                       | 2999838              | 1    |
| vmem/v128.store_unaligned             | 3009864              | 1    |
| vmem/v128.load8x8_s                   | 3699170              | 1    |
| vmem/v128.load8x8_u                   | 3702007              | 1    |
| vmem/v128.load16x4_s                  | 3747272              | 1    |
| vmem/v128.load16x4_u                  | 3721991              | 1    |
| vmem/v128.load32x2_s                  | 3735795              | 1    |
| vmem/v128.load32x2_u                  | 3707907              | 1    |
| vmem/v128.load32_zero                 | 3690223              | 1    |
| vmem/v128.load64_zero                 | 3681823              | 1    |
| vmem/v128.load8_splat                 | 3714479              | 1    |
| vmem/v128.load16_splat                | 3737613              | 1    |
| vmem/v128.load32_splat                | 3730518              | 1    |
| vmem/v128.load64_splat                | 3681506              | 1    |
| vmem/v128.load8_lane                  | 3876614              | 1    |
| vmem/v128.load16_lane                 | 3793853              | 1    |
| vmem/v128.load32_lane                 | 3859034              | 1    |
| vmem/v128.load64_lane                 | 3854663              | 1    |
| vmem/v128.store8_lane                 | 2937368              | 1    |
| vmem/v128.store16_lane                | 2951188              | 1    |
| vmem/v128.store32_lane                | 2945276              | 1    |
| vmem/v128.store64_lane                | 2947094              | 1    |
