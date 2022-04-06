use asn1_rs::oid;
use oid_registry::{OidEntry, OidRegistry};

pub fn get() -> OidRegistry<'static> {
    let mut registry = OidRegistry::default().with_crypto().with_kdf().with_pkcs9();

    // Because full with_x509() feature is filesize-consuming, we cherry-pick necessary entries.
    // Copied and modified from https://docs.rs/oid-registry/latest/src/oid_registry/opt/rustwide/target/x86_64-unknown-linux-gnu/debug/build/oid-registry-b0c4436d31da2508/out/oid_db.rs.html
    registry.insert(
        oid!(1.3.101 .112),
        OidEntry::new(
            "ed25519",
            "Edwards-curve Digital Signature Algorithm (EdDSA) Ed25519",
        ),
    );
    registry.insert(
        oid!(1.3.101 .113),
        OidEntry::new(
            "ed448",
            "Edwards-curve Digital Signature Algorithm (EdDSA) Ed448",
        ),
    );

    registry.insert(oid!(2.5.4), OidEntry::new("x509", "X.509"));
    registry.insert(
        oid!(2.5.4 .0),
        OidEntry::new("objectClass", "Object classes"),
    );
    registry.insert(
        oid!(2.5.4 .1),
        OidEntry::new("aliasedEntryName", "Aliased entry/object name"),
    );
    registry.insert(
        oid!(2.5.4 .2),
        OidEntry::new(
            "knowledgeInformation",
            "'knowledgeInformation' attribute type",
        ),
    );
    registry.insert(oid!(2.5.4 .3), OidEntry::new("commonName", "Common Name"));
    registry.insert(oid!(2.5.4 .4), OidEntry::new("surname", "Surname"));
    registry.insert(
        oid!(2.5.4 .5),
        OidEntry::new("serialNumber", "Serial Number"),
    );
    registry.insert(oid!(2.5.4 .6), OidEntry::new("countryName", "Country Name"));
    registry.insert(
        oid!(2.5.4 .7),
        OidEntry::new("localityName", "Locality Name"),
    );
    registry.insert(
        oid!(2.5.4 .8),
        OidEntry::new("stateOrProvinceName", "State or Province name"),
    );
    registry.insert(
        oid!(2.5.4 .9),
        OidEntry::new("streetAddress", "Street Address"),
    );
    registry.insert(
        oid!(2.5.4 .10),
        OidEntry::new("organizationName", "Organization Name"),
    );
    registry.insert(
        oid!(2.5.4 .11),
        OidEntry::new("organizationalUnit", "Organizational Unit"),
    );
    registry.insert(oid!(2.5.4 .12), OidEntry::new("title", "Title"));
    registry.insert(oid!(2.5.4 .13), OidEntry::new("description", "Description"));
    registry.insert(
        oid!(2.5.4 .14),
        OidEntry::new("searchGuide", "Search Guide"),
    );
    registry.insert(
        oid!(2.5.4 .15),
        OidEntry::new("businessCategory", "Business Category"),
    );
    registry.insert(
        oid!(2.5.4 .16),
        OidEntry::new("postalAddress", "Postal Address"),
    );
    registry.insert(oid!(2.5.4 .17), OidEntry::new("postalCode", "Postal Code"));
    registry.insert(oid!(2.5.4 .41), OidEntry::new("name", "Name"));
    registry.insert(oid!(2.5.4 .42), OidEntry::new("givenName", "Given Name"));
    registry.insert(
        oid!(2.5.4 .43),
        OidEntry::new("initials", "Initials of an individual's name"),
    );
    registry.insert(
        oid!(2.5.4 .44),
        OidEntry::new(
            "generationQualifier",
            "Generation information to qualify an individual's name",
        ),
    );
    registry.insert(
        oid!(2.5.4 .45),
        OidEntry::new("uniqueIdentifier", "Unique Identifier"),
    );
    registry.insert(
        oid!(2.5.4 .46),
        OidEntry::new("dnQualifier", "DN Qualifier"),
    );

    // Additional entries that are missing in oid_registry
    registry.insert(
        oid!(1.3.101 .110),
        OidEntry::new(
            "X25519",
            "Curve25519 (or X25519) algorithm used with the Diffie-Hellman operation",
        ),
    );
    registry.insert(
        oid!(1.3.101 .111),
        OidEntry::new(
            "X448",
            "Curve448 (or X448) algorithm used with the Diffie-Hellman operation",
        ),
    );

    registry
}
