use crate::crypto::canister_threshold_sig::error::IDkgTranscriptIdError;
use crate::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
use crate::Height;
use ic_base_types::{PrincipalId, SubnetId};

#[test]
fn should_increment_transcript_id_correctly() {
    let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(12345));
    let id = 0;
    let height = Height::new(0);

    let mut transcript_id = IDkgTranscriptId::new(subnet_id, id, height);

    assert_eq!(transcript_id.source_subnet, subnet_id);
    assert_eq!(transcript_id.source_height, height);
    assert_eq!(transcript_id.id, id);

    for i in 1..100 {
        transcript_id = transcript_id.increment();

        assert_eq!(transcript_id.source_subnet, subnet_id);
        assert_eq!(transcript_id.source_height, height);
        assert_eq!(transcript_id.id, i);
    }
}

#[test]
fn should_update_height_correctly() {
    let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(12345));
    let id = 0;
    let height = Height::new(0);

    let mut transcript_id = IDkgTranscriptId::new(subnet_id, id, height);

    assert_eq!(transcript_id.source_subnet, subnet_id);
    assert_eq!(transcript_id.source_height, height);
    assert_eq!(transcript_id.id, id);

    for i in 1..100 {
        let new_height = Height::from(i);
        let maybe_transcript_id = transcript_id.update_height(new_height);

        assert!(maybe_transcript_id.is_ok());
        transcript_id = maybe_transcript_id.unwrap();

        assert_eq!(transcript_id.source_subnet, subnet_id);
        assert_eq!(transcript_id.source_height, new_height);
        assert_eq!(transcript_id.id, id);
    }
}

#[test]
fn should_update_id_with_same_height() {
    let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(12345));

    let id = 1000;
    let height = Height::new(5000);

    let initial_transcript_id = IDkgTranscriptId::new(subnet_id, id, height);

    let updated_transcript_id = initial_transcript_id.update_height(height);

    assert!(updated_transcript_id.is_ok());
    let transcript_id = updated_transcript_id.unwrap();

    assert_eq!(transcript_id.source_height, height);
    assert_eq!(transcript_id.id, id);
    assert_eq!(transcript_id.source_subnet, subnet_id);
}

#[test]
fn should_not_decrease_height() {
    let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(12345));

    let id = 1000;
    let height = Height::new(5000);

    let transcript_id = IDkgTranscriptId::new(subnet_id, id, height);

    let smaller_height = Height::new(4999);
    let updated_transcript_id = transcript_id.update_height(smaller_height);

    assert_eq!(
        updated_transcript_id.unwrap_err(),
        IDkgTranscriptIdError::DecreasedBlockHeight {
            existing_height: height,
            updated_height: smaller_height
        }
    );
}
