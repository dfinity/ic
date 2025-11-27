mod secret_array {
    use crate::SecretArray;

    #[test]
    fn should_expose_secret_as_expected() {
        const SECRET_SIZE: usize = 64;
        const SECRET_BYTE: u8 = 137;
        let input = [SECRET_BYTE; SECRET_SIZE];

        let sec = SecretArray::new_and_dont_zeroize_argument(&input);

        assert_eq!(input, *sec.expose_secret());
    }

    #[test]
    fn should_redact_debug_logging() {
        const SECRET_SIZE: usize = 64;
        const SECRET_BYTE: u8 = 137;
        let input = [SECRET_BYTE; SECRET_SIZE];

        let sec = SecretArray::new_and_dont_zeroize_argument(&input);

        let debug_string = format!("{sec:?}");

        assert!(debug_string.contains("REDACTED"));
        assert!(!debug_string.contains(&SECRET_BYTE.to_string()[..]));
    }

    #[test]
    fn should_work_for_greater_than_32() {
        // Need to make sure const generics support allows us to create arrays of length
        // greater than 32.
        let input = [137; 512];

        // Just need to make sure this compiles.
        let _sec = SecretArray::new_and_dont_zeroize_argument(&input);
    }

    #[test]
    fn should_clear_input_after_new_and_zeroize_argument() {
        const SECRET_SIZE: usize = 64;
        let mut input = [137; SECRET_SIZE];
        let input_clone = input;
        let input_ptr = input.as_ptr();

        let sec = SecretArray::new_and_zeroize_argument(&mut input);

        assert_ne!(*sec.expose_secret(), [0; SECRET_SIZE]);

        assert_eq!(&input, &[0; SECRET_SIZE]);

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(input_ptr, SECRET_SIZE) },
            input_clone
        );
    }

    #[test]
    fn should_clear_memory_after_dropping() {
        const SECRET_SIZE: usize = 64;
        let input = [137; SECRET_SIZE];

        let ptr: *const u8;

        {
            let sec = SecretArray::new_and_dont_zeroize_argument(&input);
            ptr = sec.expose_secret().as_ptr();
            assert_eq!(
                unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
                input
            );
        }

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );
    }

    #[test]
    fn should_clear_memory_after_move_into_function() {
        const SECRET_SIZE: usize = 64;
        const INPUT: [u8; SECRET_SIZE] = [137; SECRET_SIZE];

        let sec = SecretArray::new_and_dont_zeroize_argument(&INPUT);
        let ptr = sec.expose_secret().as_ptr();
        assert_eq!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            INPUT
        );

        fn move_into_me(moved_sec: SecretArray<SECRET_SIZE>) {
            let ptr = moved_sec.expose_secret().as_ptr();
            assert_eq!(
                unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
                INPUT
            );
        }
        move_into_me(sec);

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            INPUT
        );
    }

    #[test]
    fn should_compare_equal_for_clones() {
        const SECRET_SIZE: usize = 64;

        let sec = SecretArray::new_and_dont_zeroize_argument(&[137; SECRET_SIZE]);
        let sec2 = sec.clone();

        assert_eq!(sec, sec2);
    }

    #[test]
    fn should_deserialize_from_serialized() {
        const SECRET_SIZE: usize = 64;

        let sec = SecretArray::new_and_dont_zeroize_argument(&[137; SECRET_SIZE]);

        let serialized = serde_cbor::to_vec(&sec).expect("failed to serialize SecretArray");

        assert_eq!(serialized.len(), 66);

        let deserialized: SecretArray<SECRET_SIZE> =
            serde_cbor::from_slice(&serialized[..]).expect("failed to deserialize SecretArray");

        assert_eq!(sec, deserialized);
    }

    #[test]
    fn should_serialization_be_equivalent_to_compact_bytestring() {
        const SECRET_SIZE: usize = 32;

        let sec = SecretArray::new_and_dont_zeroize_argument(&[137; SECRET_SIZE]);

        let serialized = serde_cbor::to_vec(&sec).expect("failed to serialize SecretArray");

        let bytes = serde_bytes::ByteBuf::from(vec![137; SECRET_SIZE]);
        let expected = serde_cbor::to_vec(&bytes).expect("failed to serialize array");

        assert_eq!(serialized, expected);
    }

    #[test]
    fn should_fail_deserializing_from_bad_length() {
        const SECRET_SIZE: usize = 64;
        const BAD_LENGTH: usize = 63;
        assert_ne!(SECRET_SIZE, BAD_LENGTH);

        // Include CBOR header (88 to indicate array, followed by length)
        let bad_serialized = [vec![88_u8, BAD_LENGTH as u8], vec![137; BAD_LENGTH]].concat();

        let deserialized_err = serde_cbor::from_slice::<SecretArray<SECRET_SIZE>>(&bad_serialized);

        let err = deserialized_err.unwrap_err();
        let err_msg = format!("{err}");
        assert!(err_msg.contains("invalid length"));
    }

    #[test]
    fn should_clear_memory_when_composed() {
        const SECRET_SIZE: usize = 64;
        let input = [137; SECRET_SIZE];

        let ptr: *const u8;

        struct SuperType {
            secret: SecretArray<SECRET_SIZE>,
            _public: [u8; 32],
        }

        {
            let stuff = SuperType {
                secret: SecretArray::new_and_dont_zeroize_argument(&input),
                _public: [1; 32],
            };

            ptr = stuff.secret.expose_secret().as_ptr();
        }

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );
    }
}

mod secret_vec {
    use crate::SecretVec;

    #[test]
    fn should_expose_secret_as_expected() {
        const SECRET_SIZE: usize = 64;
        const SECRET_BYTE: u8 = 137;
        let input = vec![SECRET_BYTE; SECRET_SIZE];

        let sec = SecretVec::new_and_dont_zeroize_argument(&input);

        assert_eq!(input, *sec.expose_secret());
    }

    #[test]
    fn should_redact_debug_logging() {
        const SECRET_SIZE: usize = 64;
        const SECRET_BYTE: u8 = 137;
        let input = vec![SECRET_BYTE; SECRET_SIZE];

        let sec = SecretVec::new_and_dont_zeroize_argument(&input);

        let debug_string = format!("{sec:?}");

        assert!(debug_string.contains("REDACTED"));
        assert!(!debug_string.contains(&SECRET_BYTE.to_string()[..]));
    }

    #[test]
    fn should_clear_input_after_new_and_zeroize_argument() {
        const SECRET_SIZE: usize = 64;
        let mut input = vec![137; SECRET_SIZE];
        let input_clone = input.clone();
        let input_ptr = input.as_ptr();

        let sec = SecretVec::new_and_zeroize_argument(&mut input);

        assert_ne!(*sec.expose_secret(), [0; SECRET_SIZE]);

        assert!(input.is_empty());

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(input_ptr, SECRET_SIZE) },
            input_clone
        );
    }

    #[test]
    fn should_clear_memory_after_dropping() {
        const SECRET_SIZE: usize = 64;
        let input = vec![137; SECRET_SIZE];

        let ptr: *const u8;

        {
            let sec = SecretVec::new_and_dont_zeroize_argument(&input);
            ptr = sec.expose_secret().as_ptr();
            assert_eq!(
                unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
                input
            );
        }

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );
    }

    #[test]
    fn should_clear_memory_after_move_into_function() {
        const SECRET_SIZE: usize = 64;
        let input = vec![137; SECRET_SIZE];

        let sec = SecretVec::new_and_dont_zeroize_argument(&input);
        let ptr = sec.expose_secret().as_ptr();
        assert_eq!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );

        fn move_into_me(moved_sec: SecretVec) {
            let input = vec![137; SECRET_SIZE]; // just non-DRY this, so it can live in the fn
            let ptr = moved_sec.expose_secret().as_ptr();
            assert_eq!(
                unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
                input
            );
        }
        move_into_me(sec);

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );
    }

    #[test]
    fn should_compare_equal_for_clones() {
        const SECRET_SIZE: usize = 64;

        let sec = SecretVec::new_and_dont_zeroize_argument(&[137; SECRET_SIZE]);
        let sec2 = sec.clone();

        assert_eq!(sec, sec2);
    }

    #[test]
    fn should_deserialize_from_serialized() {
        const SECRET_SIZE: usize = 64;

        let sec = SecretVec::new_and_dont_zeroize_argument(&[137; SECRET_SIZE]);

        let serialized = serde_cbor::to_vec(&sec).expect("failed to serialize SecretVec");

        assert_eq!(serialized.len(), 144);

        let deserialized =
            serde_cbor::from_slice(&serialized[..]).expect("failed to deserialize SecretVec");

        assert_eq!(sec, deserialized);
    }

    #[test]
    fn should_clear_memory_when_composed() {
        const SECRET_SIZE: usize = 64;
        let input = vec![137; SECRET_SIZE];

        let ptr: *const u8;

        struct SuperType {
            secret: SecretVec,
            _public: [u8; 32],
        }

        {
            let stuff = SuperType {
                secret: SecretVec::new_and_dont_zeroize_argument(&input),
                _public: [1; 32],
            };

            ptr = stuff.secret.expose_secret().as_ptr();
        }

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );
    }
}

mod secret_bytes {
    use crate::SecretBytes;

    #[test]
    fn should_expose_secret_as_expected() {
        const SECRET_SIZE: usize = 64;
        const SECRET_BYTE: u8 = 137;
        let input = vec![SECRET_BYTE; SECRET_SIZE];

        let sec = SecretBytes::new_from_unowned(&input);

        assert_eq!(input, *sec.expose_secret());
    }

    #[test]
    fn should_redact_debug_logging() {
        const SECRET_SIZE: usize = 64;
        const SECRET_BYTE: u8 = 137;
        let input = vec![SECRET_BYTE; SECRET_SIZE];

        let sec = SecretBytes::new_from_unowned(&input);

        let debug_string = format!("{sec:?}");

        assert!(debug_string.contains("REDACTED"));
        assert!(!debug_string.contains(&SECRET_BYTE.to_string()[..]));
    }

    #[test]
    fn should_move_input_after_new() {
        const SECRET_SIZE: usize = 64;
        let input = vec![137; SECRET_SIZE];
        let input_ptr = input.as_ptr();
        let input_clone = input.clone();

        let sec = SecretBytes::new(input);

        assert_eq!(sec.expose_secret(), input_clone);
        assert_eq!(sec.expose_secret().as_ptr(), input_ptr);
    }

    #[test]
    fn should_clear_memory_after_dropping() {
        const SECRET_SIZE: usize = 64;
        let input = vec![137; SECRET_SIZE];

        let ptr: *const u8;

        {
            let sec = SecretBytes::new_from_unowned(&input);
            ptr = sec.expose_secret().as_ptr();
            assert_eq!(
                unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
                input
            );
        }

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );
    }

    #[test]
    fn should_clear_memory_after_move_into_function() {
        const SECRET_SIZE: usize = 64;
        let input = vec![137; SECRET_SIZE];

        let sec = SecretBytes::new_from_unowned(&input);
        let ptr = sec.expose_secret().as_ptr();
        assert_eq!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );

        fn move_into_me(moved_sec: SecretBytes) {
            let input = vec![137; SECRET_SIZE]; // just non-DRY this, so it can live in the fn
            let ptr = moved_sec.expose_secret().as_ptr();
            assert_eq!(
                unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
                input
            );
        }
        move_into_me(sec);

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );
    }

    #[test]
    fn should_compare_equal_for_clones() {
        const SECRET_SIZE: usize = 64;

        let sec = SecretBytes::new_from_unowned(&[137; SECRET_SIZE]);
        let sec2 = sec.clone();

        assert_eq!(sec, sec2);
    }

    #[test]
    fn should_deserialize_from_serialized() {
        const SECRET_SIZE: usize = 64;

        let sec = SecretBytes::new_from_unowned(&[137; SECRET_SIZE]);

        let serialized = serde_cbor::to_vec(&sec).expect("failed to serialize SecretBytes");

        assert_eq!(serialized.len(), 66);

        let deserialized =
            serde_cbor::from_slice(&serialized[..]).expect("failed to deserialize SecretBytes");

        assert_eq!(sec, deserialized);
    }

    #[test]
    fn should_have_compact_bytestring_serialization() {
        const SECRET_SIZE: usize = 32;

        let sec = SecretBytes::new_from_unowned(&[137; SECRET_SIZE]);

        let serialized = serde_cbor::to_vec(&sec).expect("failed to serialize SecretBytes");

        let bytes = serde_bytes::ByteBuf::from(vec![137; SECRET_SIZE]);
        let expected = serde_cbor::to_vec(&bytes).expect("failed to serialize array");

        assert_eq!(serialized, expected);
    }

    #[test]
    fn should_clear_memory_when_composed() {
        const SECRET_SIZE: usize = 64;
        let input = vec![137; SECRET_SIZE];

        let ptr: *const u8;

        struct SuperType {
            secret: SecretBytes,
            _public: [u8; 32],
        }

        {
            let stuff = SuperType {
                secret: SecretBytes::new_from_unowned(&input),
                _public: [1; 32],
            };

            ptr = stuff.secret.expose_secret().as_ptr();
        }

        // Can't test for 0, since memory may already be used elsewhere.
        assert_ne!(
            unsafe { core::slice::from_raw_parts(ptr, SECRET_SIZE) },
            input
        );
    }
}
