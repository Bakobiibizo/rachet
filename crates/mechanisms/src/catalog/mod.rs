//! Declared initial mechanism catalog.
//!
//! Catalog presence records a design hypothesis. Only entries with
//! [`CatalogStatus::ImplementNow`] are compiled or selectable.

use rachet_core::mechanisms::MechanismId;

/// The checked-in source of truth for human and tool inspection.
pub const CATALOG_TOML: &str = include_str!("../../catalog/catalog.toml");

/// Catalog planning status. This is distinct from a runtime manifest status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CatalogStatus {
    ImplementNow,
    Proposed,
}

/// One immutable entry in the initial catalog.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CatalogEntry {
    pub id: MechanismId,
    pub name: &'static str,
    pub status: CatalogStatus,
    pub summary: &'static str,
}

/// The section 24 catalog in allocated-ID order.
pub const INITIAL_CATALOG: [CatalogEntry; 13] = [
    CatalogEntry {
        id: MechanismId::M00,
        name: "record-only",
        status: CatalogStatus::ImplementNow,
        summary: "Establish the protocol and simulator null condition.",
    },
    CatalogEntry {
        id: MechanismId::M01,
        name: "naive-reputation",
        status: CatalogStatus::ImplementNow,
        summary: "Test whether simple correctness history predicts future validation.",
    },
    CatalogEntry {
        id: MechanismId::M02,
        name: "reputation-stake",
        status: CatalogStatus::Proposed,
        summary: "Make careless claims expose accumulated credibility.",
    },
    CatalogEntry {
        id: MechanismId::M03,
        name: "commit-reveal",
        status: CatalogStatus::Proposed,
        summary: "Reduce copying and consensus following.",
    },
    CatalogEntry {
        id: MechanismId::M04,
        name: "customer-standing",
        status: CatalogStatus::Proposed,
        summary: "Discount synthetic demand and reputation farming.",
    },
    CatalogEntry {
        id: MechanismId::M05,
        name: "challenge-bonds",
        status: CatalogStatus::Proposed,
        summary: "Make frivolous challenges costly.",
    },
    CatalogEntry {
        id: MechanismId::M06,
        name: "challenge-bounties",
        status: CatalogStatus::Proposed,
        summary: "Reward useful falsification and minority findings.",
    },
    CatalogEntry {
        id: MechanismId::M07,
        name: "deferred-compensation",
        status: CatalogStatus::Proposed,
        summary: "Attach future payout to durable claim survival.",
    },
    CatalogEntry {
        id: MechanismId::M08,
        name: "reputation-maturity",
        status: CatalogStatus::Proposed,
        summary: "Prevent rapid reputation farming and season claims.",
    },
    CatalogEntry {
        id: MechanismId::M09,
        name: "self-challenge",
        status: CatalogStatus::Proposed,
        summary: "Reward disclosure and continued monitoring.",
    },
    CatalogEntry {
        id: MechanismId::M10,
        name: "information-weighting",
        status: CatalogStatus::Proposed,
        summary: "Discount redundant agreement and reward uncertainty reduction.",
    },
    CatalogEntry {
        id: MechanismId::M11,
        name: "domain-reputation",
        status: CatalogStatus::Proposed,
        summary: "Infer validator specialization from history.",
    },
    CatalogEntry {
        id: MechanismId::M12,
        name: "portfolio-exposure",
        status: CatalogStatus::Proposed,
        summary: "Limit unchecked accumulation of outstanding liability.",
    },
];

pub fn entry(id: MechanismId) -> Option<&'static CatalogEntry> {
    INITIAL_CATALOG.iter().find(|entry| entry.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_catalog_ids_and_statuses_are_locked() {
        assert_eq!(INITIAL_CATALOG.len(), 13);
        for (number, entry) in INITIAL_CATALOG.iter().enumerate() {
            assert_eq!(entry.id.get(), u16::try_from(number).unwrap());
            let expected = if number < 2 {
                CatalogStatus::ImplementNow
            } else {
                CatalogStatus::Proposed
            };
            assert_eq!(entry.status, expected);
        }
    }

    #[test]
    fn checked_in_toml_matches_the_locked_status_boundary() {
        assert_eq!(CATALOG_TOML.matches("[[mechanism]]").count(), 13);
        assert_eq!(
            CATALOG_TOML.matches("status = \"implement-now\"").count(),
            2
        );
        assert_eq!(CATALOG_TOML.matches("status = \"proposed\"").count(), 11);

        for number in 0..=12 {
            assert_eq!(
                CATALOG_TOML
                    .matches(&format!("id = \"M{number:02}\""))
                    .count(),
                1
            );
        }

        let proposed = CATALOG_TOML.split("[[mechanism]]").skip(3);
        for entry in proposed {
            assert!(entry.contains("status = \"proposed\""));
            assert!(entry.contains("implementation = \"\""));
        }
    }

    #[test]
    fn only_implemented_entries_are_selectable_by_the_core_config() {
        use rachet_core::mechanisms::{
            CanonicalMechanismConfig, MechanismSelection, MechanismSetConfig, MechanismVersion,
        };
        use rachet_core::primitives::ProtocolVersion;

        for entry in INITIAL_CATALOG {
            let selection = MechanismSelection::new(
                entry.id,
                MechanismVersion::V1_0_0,
                CanonicalMechanismConfig::empty(),
            );
            let result = MechanismSetConfig::new(ProtocolVersion::V1, vec![selection]);
            match entry.status {
                CatalogStatus::ImplementNow => assert!(result.is_ok()),
                CatalogStatus::Proposed => {
                    assert_eq!(result.unwrap_err().code(), "MECHANISM_NOT_IMPLEMENTED")
                }
            }
        }
    }
}
