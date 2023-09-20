use crate::{
    governance::LOG_PREFIX,
    neuron_store::NeuronStore,
    pb::v1::governance::{
        migration::{MigrationStatus, Progress},
        Migration, Migrations,
    },
};
use ic_nns_common::pb::v1::NeuronId;

pub const NEURON_INDEXES_MIGRATION_BATCH_SIZE: usize = 1000;

pub fn neuron_stable_indexes_building_is_enabled() -> bool {
    cfg! { any(test, feature = "test") }
}

pub(crate) fn maybe_run_migrations(
    mut migrations: Migrations,
    neuron_store: &mut NeuronStore,
) -> Migrations {
    if neuron_stable_indexes_building_is_enabled() {
        migrations.neuron_indexes_migration = Some(maybe_run_neuron_index_migration(
            migrations
                .neuron_indexes_migration
                .clone()
                .unwrap_or_default(),
            neuron_store,
        ));
    }
    migrations
}

/// Runs neuron indexes migration when possible.
fn maybe_run_neuron_index_migration(
    migration: Migration,
    neuron_store: &mut NeuronStore,
) -> Migration {
    if !neuron_stable_indexes_building_is_enabled() {
        return migration;
    }

    let migration_status = migration
        .status
        .and_then(|status| MigrationStatus::from_i32(status));

    let last_neuron_id = match migration_status {
        // The first time running the migration, starting at 0.
        None => NeuronId { id: 0 },
        Some(MigrationStatus::Unspecified) => {
            eprintln!("{}Unspecified migration status", LOG_PREFIX);
            return migration;
        }
        Some(MigrationStatus::Succeeded) => return migration,
        Some(MigrationStatus::Failed) => return migration,
        Some(MigrationStatus::InProgress) => match migration.progress {
            Some(Progress::LastNeuronId(last_neuron_id)) => last_neuron_id,
            None => {
                eprintln!("{}Neuron index migration progress is wrong", LOG_PREFIX);
                return migration;
            }
        },
    };

    match neuron_store.batch_add_heap_neurons_to_stable_indexes(
        last_neuron_id,
        NEURON_INDEXES_MIGRATION_BATCH_SIZE,
    ) {
        Err(failure_reason) => Migration {
            status: Some(MigrationStatus::Failed as i32),
            failure_reason: Some(failure_reason),
            progress: None,
        },
        Ok(Some(new_last_neuron_id)) => Migration {
            status: Some(MigrationStatus::InProgress as i32),
            failure_reason: None,
            progress: Some(Progress::LastNeuronId(new_last_neuron_id)),
        },
        Ok(None) => Migration {
            status: Some(MigrationStatus::Succeeded as i32),
            failure_reason: None,
            progress: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::Neuron;
    use ic_base_types::PrincipalId;
    use ic_nns_common::pb::v1::NeuronId;
    use maplit::btreemap;

    #[test]
    fn migrate_neuron_indexes_one_neuron_succeeded() {
        let mut neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                id: Some(NeuronId { id: 1 }),
                account: [1u8; 32].to_vec(),
                controller: Some(PrincipalId::new_user_test_id(1)),
                ..Default::default()
            },
        });

        assert_eq!(
            maybe_run_neuron_index_migration(Migration::default(), &mut neuron_store),
            Migration {
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None
            }
        );
    }

    #[test]
    fn migrate_neuron_indexes_one_neuron_failed() {
        // A practically impossible scenario: neurons with the same account, just to test that the
        // failure status and reason is correctly set.
        let mut neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                id: Some(NeuronId { id: 1 }),
                account: [1u8; 32].to_vec(),
                controller: Some(PrincipalId::new_user_test_id(1)),
                ..Default::default()
            },
            2 => Neuron {
                id: Some(NeuronId { id: 2 }),
                account: [1u8; 32].to_vec(),
                controller: Some(PrincipalId::new_user_test_id(2)),
                ..Default::default()
            },
        });

        let migration = maybe_run_neuron_index_migration(Migration::default(), &mut neuron_store);

        assert_eq!(migration.status, Some(MigrationStatus::Failed as i32));
        assert_eq!(migration.progress, None);
        assert!(
            migration
                .failure_reason
                .clone()
                .unwrap()
                .contains("already exists in the index"),
            "{:?}",
            migration.failure_reason
        );
    }

    #[test]
    fn migrate_neuron_indexes_already_succeeded() {
        let mut neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                id: Some(NeuronId { id: 1 }),
                account: [1u8; 32].to_vec(),
                controller: Some(PrincipalId::new_user_test_id(1)),
                ..Default::default()
            },
        });

        assert_eq!(
            maybe_run_neuron_index_migration(
                Migration {
                    status: Some(MigrationStatus::Succeeded as i32),
                    failure_reason: None,
                    progress: None
                },
                &mut neuron_store
            ),
            Migration {
                status: Some(MigrationStatus::Succeeded as i32),
                failure_reason: None,
                progress: None
            }
        );
    }

    #[test]
    fn migrate_neuron_indexes_already_failed() {
        let mut neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                id: Some(NeuronId { id: 1 }),
                account: [1u8; 32].to_vec(),
                controller: Some(PrincipalId::new_user_test_id(1)),
                ..Default::default()
            },
        });

        assert_eq!(
            maybe_run_neuron_index_migration(
                Migration {
                    status: Some(MigrationStatus::Failed as i32),
                    failure_reason: Some("It somehow failed".to_string()),
                    progress: None
                },
                &mut neuron_store
            ),
            Migration {
                status: Some(MigrationStatus::Failed as i32),
                failure_reason: Some("It somehow failed".to_string()),
                progress: None
            }
        );
    }
}
