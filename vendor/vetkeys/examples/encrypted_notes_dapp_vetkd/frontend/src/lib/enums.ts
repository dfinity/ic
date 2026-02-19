export type KeysOfUnion<T extends object> = T extends T ? keyof T : never;

export function enumIs<EnumType extends object, T extends EnumType>(
  p: EnumType,
  key: KeysOfUnion<T>
): p is T {
  return (key as string) in p;
}
