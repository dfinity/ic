use num_bigint_dig::{BigUint, ModInverse};
use num_traits::{
    identities::{One, Zero},
    ToPrimitive,
};
use quote::quote;
use std::collections::BTreeMap;
use std::str::FromStr;

struct FieldElementConfig {
    ident: syn::Ident,
    limbs: usize,
    modulus: BigUint,
    modulus_m2: BigUint,
    monty_r1: BigUint,
    monty_r2: BigUint,
    monty_r3: BigUint,
    p_dash: u64,
    is_p_3_mod_4: bool,
    params: BTreeMap<String, BigUint>,
}

impl FieldElementConfig {
    fn new(ident: syn::Ident, modulus: BigUint, mut params: BTreeMap<String, BigUint>) -> Self {
        let limb_size = 64; // bits of u64
        let limbs = ((modulus.bits() + limb_size - 1) / limb_size) as usize;

        let m64 = BigUint::one() << limb_size;

        let m_inv_m64 = modulus.clone().mod_inverse(m64).unwrap().to_u64().unwrap();
        // Montgomery param (-p)^-1 mod 2^64
        let p_dash = 0u64.wrapping_sub(m_inv_m64);
        // Montgomery R value: 2^(64*limbs) mod p
        let monty_r1 = (BigUint::one() << (64 * limbs)) % &modulus;
        // Montgomery R2 value: (R*R) % p
        let monty_r2 = (BigUint::one() << (2 * 64 * limbs)) % &modulus;
        // Montgomery R3 value: (R*R*R) % p
        let monty_r3 = (BigUint::one() << (3 * 64 * limbs)) % &modulus;

        // Modulus minus 2: p-2
        let modulus_m2 = &modulus - BigUint::from_bytes_be(&[2]);

        let is_p_3_mod_4 = modulus.get_limb(0) % 4 == 3;

        if params.contains_key("SSWU_Z") && !params.contains_key("SSWU_C2") {
            assert!(is_p_3_mod_4, "Shanks-Tonelli not implemented");
            let mod_p1_over_4 = (&modulus + BigUint::one()) >> 2;
            let z = params.get("SSWU_Z").unwrap();
            // The constant `C2` is the square root of `-Z`.
            let sswu_c2 = (&modulus - z).modpow(&mod_p1_over_4, &modulus);
            params.insert("SSWU_C2".to_string(), sswu_c2);
        }

        Self {
            ident,
            limbs,
            modulus,
            modulus_m2,
            monty_r1,
            monty_r2,
            monty_r3,
            p_dash,
            is_p_3_mod_4,
            params,
        }
    }
}

struct NameAndValue {
    name: syn::Ident,
    value: syn::LitStr,
}

impl syn::parse::Parse for NameAndValue {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let name: syn::Ident = input.parse()?;
        let _eq: syn::token::Eq = input.parse()?;
        let value: syn::LitStr = input.parse()?;
        Ok(NameAndValue { name, value })
    }
}

fn parse_integer(v: &str) -> BigUint {
    if v.starts_with("0x") {
        BigUint::parse_bytes(&v.as_bytes()[2..], 16).expect("Unable to parse integer")
    } else {
        BigUint::from_str(v).expect("Unable to parse integer")
    }
}

fn parse_integer_relative(modulus: &BigUint, v: &str) -> BigUint {
    if let Some(v) = v.strip_prefix('-') {
        modulus - parse_integer(v)
    } else {
        parse_integer(v)
    }
}

impl syn::parse::Parse for FieldElementConfig {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let ident: syn::Ident = input.parse()?;

        let _comma: syn::token::Comma = input.parse()?;

        let m_name: syn::Ident = input.parse()?;
        if m_name != "Modulus" {
            return Err(syn::Error::new_spanned(m_name, "expected Modulus first"));
        }
        let _eq: syn::token::Eq = input.parse()?;
        let m_val: syn::LitStr = input.parse()?;
        let _comma: syn::token::Comma = input.parse()?;

        let params: syn::punctuated::Punctuated<NameAndValue, syn::token::Comma> =
            input.parse_terminated(NameAndValue::parse)?;

        let modulus = parse_integer(&m_val.value());

        let mut fe_params: BTreeMap<String, BigUint> = BTreeMap::new();

        for nvp in params {
            let name = format!("{}", nvp.name);
            let value = nvp.value.value();

            let existing = fe_params.get(&value).cloned();

            if let Some(existing) = existing {
                fe_params.insert(name, existing.clone());
            } else {
                let value = parse_integer_relative(&modulus, &value);
                fe_params.insert(name, value);
            }
        }

        Ok(Self::new(ident, modulus, fe_params))
    }
}

/// Return the BigUint encoded as a sequence of u64 limbs in little-endian order
fn biguint_as_u64s(bn: &BigUint, limbs: usize) -> Vec<u64> {
    let limb_size = 64; // bits of a u64
    let mut bn: BigUint = bn.clone();
    let m64 = BigUint::one() << limb_size;
    let mut ret = vec![];

    while bn > BigUint::zero() {
        let limb: BigUint = &bn % &m64;
        ret.push(limb.to_u64().unwrap());
        bn >>= 64;
    }

    while ret.len() < limbs {
        ret.push(0);
    }

    ret
}

#[proc_macro]
pub fn derive_field_element(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let config: FieldElementConfig = syn::parse(input).unwrap();

    if !num_bigint_dig::prime::probably_prime(&config.modulus, 5) {
        panic!("Modulus is not prime");
    }

    let mut gen = proc_macro2::TokenStream::new();
    gen.extend(define_fe_struct(&config));

    for param in &config.params {
        gen.extend(custom_param(&config, param.0));
    }

    if config.is_p_3_mod_4 {
        gen.extend(p_3_mod_4_extras(&config));
    }

    gen.into()
}

fn define_fe_struct(config: &FieldElementConfig) -> proc_macro2::TokenStream {
    let ident = config.ident.clone();
    let ident_str = format!("{}", ident);
    let limbs = config.limbs;

    let modulus_limbs = biguint_as_u64s(&config.modulus, limbs);
    let modulus_m2_limbs = biguint_as_u64s(&config.modulus_m2, limbs);
    let monty_r1_limbs = biguint_as_u64s(&config.monty_r1, limbs);
    let monty_r2_limbs = biguint_as_u64s(&config.monty_r2, limbs);
    let monty_r3_limbs = biguint_as_u64s(&config.monty_r3, limbs);
    let p_dash = config.p_dash;

    quote! {
        #[derive(Copy, Clone, Zeroize)]
        pub struct #ident {
            limbs: [u64; #limbs]
        }

        impl Default for #ident {
            fn default() -> Self {
                Self::zero()
            }
        }

        impl PartialEq for #ident {
            fn eq(&self, other: &Self) -> bool {
                bool::from(self.ct_eq(other))
            }
        }
        impl Eq for #ident {}

        impl std::fmt::Debug for #ident {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}(0x{})", #ident_str, hex::encode(self.as_bytes()))
            }
        }

        impl #ident {

            #[inline]
            fn add_limb(x: u64, y: u64, carry: &mut u64) -> u64 {
                let z = (x as u128) + (y as u128) + (*carry as u128);
                *carry = (z >> 64) as u64;
                z as u64
            }

            #[inline]
            fn sub_limb(x: u64, y: u64, borrow: &mut u64) -> u64 {
                let ret = (x as u128).wrapping_sub((y as u128) + ((*borrow & 1) as u128));
                *borrow = (ret >> 64) as u64;
                ret as u64
            }

            #[inline]
            fn mul_add(x: u64, y: u64, z: u64, carry: &mut u64) -> u64 {
                let ret = ((x as u128) * (y as u128)) + (z as u128) + (*carry as u128);
                *carry = (ret >> 64) as u64;
                ret as u64
            }

            const MODULUS: [u64; #limbs] = [#(#modulus_limbs,)*];
            const MODULUS_MINUS_2: [u64; #limbs] = [#(#modulus_m2_limbs,)*];
            const MONTY_R1: [u64; #limbs] = [#(#monty_r1_limbs,)*];
            const MONTY_R2: Self = Self::from_limbs([#(#monty_r2_limbs,)*]);
            const MONTY_R3: Self = Self::from_limbs([#(#monty_r3_limbs,)*]);
            const P_DASH: u64 = #p_dash;

            /// Initialize from limbs (private constructor)
            const fn from_limbs(limbs: [u64; #limbs]) -> Self {
                Self { limbs }
            }

            /// Return zero (in Montgomery form)
            pub fn zero() -> Self {
                Self::from_limbs([0u64; #limbs])
            }

            /// Return one (in Montgomery form)
            pub fn one() -> Self {
                Self::from_limbs(Self::MONTY_R1)
            }

            fn ct_eq(&self, other: &Self) -> subtle::Choice {
                use subtle::ConstantTimeEq;

                let mut cmp = subtle::Choice::from(1u8);

                for i in 0..#limbs {
                    cmp &= self.limbs[i].ct_eq(&other.limbs[i]);
                }

                cmp
            }

            /// Return true if and only if self is equal to zero
            pub fn is_zero(&self) -> subtle::Choice {
                self.ct_eq(&Self::zero())
            }

            /// If assign is true then set self to other
            pub fn ct_assign(&mut self, other: &Self, assign: subtle::Choice) {
                use subtle::ConditionallySelectable;

                for i in 0..#limbs {
                    self.limbs[i] = u64::conditional_select(&self.limbs[i], &other.limbs[i], assign);
                }
            }

            /// Parse the given byte array as a field element.
            ///
            /// Return None if the byte array does not represeent an integer in [0,p)
            pub fn from_bytes(bytes: &[u8]) -> std::option::Option<Self> {
                if bytes.len() != 8 * #limbs {
                    return None;
                }

                let mut limbs = [0u64; #limbs];

                for i in 0..#limbs {
                    limbs[#limbs - 1 - i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
                }

                // If lhs < rhs then lhs - rhs will underflow; if it doesn't then lhs >= rhs
                let mut borrow = 0;
                for i in 0..#limbs {
                    let _ = Self::sub_limb(limbs[i], Self::MODULUS[i], &mut borrow);
                }

                let is_gte = borrow == 0;

                if is_gte {
                    return None;
                }

                // Multiply by R2 to convert into Montgomery form
                Some(Self::from_limbs(limbs).mul(&Self::MONTY_R2))
            }

            pub fn from_bytes_wide(bytes: &[u8]) -> Option<Self> {
                if bytes.len() > 2 * 8 * #limbs {
                    return None;
                }

                let mut wide_bytes = [0u8; 2 * 8 * #limbs];
                wide_bytes[2 * 8 * #limbs - bytes.len()..].copy_from_slice(bytes);

                let mut limbs = [0u64; 2 * #limbs];

                for i in 0..2 * #limbs {
                    limbs[2 * #limbs - 1 - i] = u64::from_be_bytes(wide_bytes[i * 8..(i + 1) * 8].try_into().unwrap());
                }

                // First reduce then mul by R3 to convert to Montgomery form
                Some(Self::redc(&limbs).mul(&Self::MONTY_R3))
            }

            /// Return the encoding of this field element
            pub fn as_bytes(&self) -> [u8; 8*#limbs] {
                // Convert from Montgomery form
                let value = Self::redc(&self.limbs);
                let mut ret = [0u8; 8 * #limbs];
                for i in 0..#limbs {
                    ret[8 * i..(8 * i + 8)]
                        .copy_from_slice(&value.limbs[#limbs - 1 - i].to_be_bytes());
                }
                ret
            }

            /// Return self + rhs mod p
            pub fn add(&self, rhs: &Self) -> Self {
                let mut sum = [0u64; #limbs + 1];
                let mut carry = 0;
                for i in 0..#limbs {
                    sum[i] = Self::add_limb(self.limbs[i], rhs.limbs[i], &mut carry);
                }
                sum[#limbs] = carry;

                // Attempt to subtract the modulus, to ensure the result is in the field.
                Self::mod_sub(&sum, Self::MODULUS)
            }

            /// Return self - rhs mod p
            pub fn subtract(&self, rhs: &Self) -> Self {
                Self::mod_sub(&self.limbs, rhs.limbs)
            }

            fn mod_sub(l: &[u64], r: [u64; #limbs]) -> Self {
                let mut borrow = 0;
                let mut w = [0u64; #limbs];
                for i in 0..#limbs {
                    w[i] = Self::sub_limb(l[i], r[i], &mut borrow);
                }

                for i in #limbs..l.len() {
                    let _ = Self::sub_limb(l[i], 0, &mut borrow);
                }

                // Use borrow as a mask to conditionally add
                let mut carry = 0;
                for i in 0..#limbs {
                    w[i] = Self::add_limb(w[i], Self::MODULUS[i] & borrow, &mut carry);
                }

                Self::from_limbs(w)
            }

            fn redc(z_in: &[u64]) -> Self {
                let mut z = [0u64; 2 * #limbs + 1];
                z[0..z_in.len()].copy_from_slice(z_in);

                for i in 0..#limbs {
                    let y = u64::wrapping_mul(z[i], Self::P_DASH);

                    let mut carry = 0;
                    for j in 0..#limbs {
                        z[i + j] = Self::mul_add(Self::MODULUS[j], y, z[i + j], &mut carry);
                    }

                    for j in #limbs + i..2 * #limbs + 1 {
                        z[j] = Self::add_limb(z[j], 0, &mut carry);
                    }
                }

                Self::mod_sub(&z[#limbs..], Self::MODULUS)
            }

            /// Return self * rhs mod p
            pub fn mul(&self, rhs: &Self) -> Self {
                let mut product = [0u64; 2 * #limbs];

                for i in 0..#limbs {
                    let mut carry = 0;

                    for j in 0..#limbs {
                        product[i + j] = Self::mul_add(
                            self.limbs[i],
                            rhs.limbs[j],
                            product[i + j],
                            &mut carry,
                        );
                    }

                    product[i + #limbs] = carry;
                }

                Self::redc(&product)
            }

            /// Return self * self mod p
            pub fn square(&self) -> Self {
                self.mul(self)
            }

            /// Return `self^power`
            ///
            /// Variable time with respect to the exponent, which should only be a
            /// constant.
            fn pow_vartime(&self, power: &[u64; #limbs]) -> Self {
                let mut z = Self::one();
                for i in 0..#limbs {
                    for b in (0..64).rev() {
                        z = z.square();

                        if ((power[#limbs-1-i] >> b) & 1) == 1 {
                            z = z.mul(self);
                        }
                    }
                }
                z
            }

            /// Return the multiplicative inverse of self, if self is non-zero, or else
            /// zero
            pub fn invert(&self) -> Self {
                // Since p is prime we can just use Fermat's little theorem to compute
                // an inverse. The only case that fails is self == 0 in which case we
                // return 0 which is never a valid multiplicative inverse.
                self.pow_vartime(&Self::MODULUS_MINUS_2)
            }
        }
    }
}

fn custom_param(config: &FieldElementConfig, param: &str) -> proc_macro2::TokenStream {
    let ident = config.ident.clone();
    let fn_ident = syn::parse_str::<syn::Ident>(&param.to_lowercase()).unwrap();
    let value = config.params.get(param).unwrap();
    // pre-convert into Montgomery form
    let limbs = biguint_as_u64s(
        &((value * &config.monty_r1) % &config.modulus),
        config.limbs,
    );

    quote! {
        impl #ident {
            pub fn #fn_ident() -> Self {
                Self::from_limbs([#(#limbs,)*])
            }
        }
    }
}

fn p_3_mod_4_extras(config: &FieldElementConfig) -> proc_macro2::TokenStream {
    let ident = config.ident.clone();
    let limbs = config.limbs;

    let mod_p1_over_4 = (&config.modulus + BigUint::one()) >> 2;
    let mod_p1_over_4_limbs = biguint_as_u64s(&mod_p1_over_4, limbs);

    let mod_m3_over_4 = (&config.modulus - BigUint::from_bytes_be(&[3])) >> 2;
    let mod_m3_over_4_limbs = biguint_as_u64s(&mod_m3_over_4, limbs);

    quote! {
        impl #ident {
            const MODULUS_PLUS_1_OVER_4: [u64; #limbs] = [#(#mod_p1_over_4_limbs,)*];
            const MODULUS_MINUS_3_OVER_4: [u64; #limbs] = [#(#mod_m3_over_4_limbs,)*];

            pub fn progenitor(&self) -> Self {
                self.pow_vartime(&Self::MODULUS_MINUS_3_OVER_4)
            }

            /// Return the square root of self mod p, or zero if no square root exists.
            ///
            /// The validity of the result is determined by the returned Choice
            pub fn sqrt(&self) -> (subtle::Choice, Self) {
                // For p == 3 (mod 4) square root can be computed using x^(p+1)/4
                // though will be nonsense for non quadratic roots.
                let mut sqrt = self.pow_vartime(&Self::MODULUS_PLUS_1_OVER_4);

                let sqrt2 = sqrt.square();

                let is_correct_sqrt = sqrt2.ct_eq(self);

                // zero the result if invalid
                sqrt.ct_assign(&Self::zero(), !is_correct_sqrt);

                (is_correct_sqrt, sqrt)
            }
        }
    }
}
