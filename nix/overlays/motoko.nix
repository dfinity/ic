self: super:
let
  motoko = import self.sources.motoko { inherit (self) system; };
in
{
  inherit (motoko) moc;
}
