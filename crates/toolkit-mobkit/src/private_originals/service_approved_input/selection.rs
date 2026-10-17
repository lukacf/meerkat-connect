//! Canonical approved source selection. The legacy object has no discriminator
//! and keeps exactly its existing fields. Only the new set has a version tag.
use super::*;


#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::private_originals) struct ApprovedTaskHeader {
    pub parent: PrivateOriginalRef,
    pub acquisition: StoreKey,
    pub original_task: NativeOriginalTask,
    pub before_ms: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(in crate::private_originals) struct ApprovedTaskMember {
    pub header: ApprovedTaskHeader,
    pub grant: PrivateServiceGrantRef,
}

impl std::ops::Deref for ApprovedTaskMember {
    type Target = ApprovedTaskHeader;
    fn deref(&self) -> &Self::Target { &self.header }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::private_originals) struct ApprovedServiceMember {
    pub connection: Id,
    pub grant: PrivateServiceGrantRef,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::private_originals) enum BatchVersion { PublicServicesV1 }

#[derive(Clone, PartialEq, Eq)]
pub(in crate::private_originals) struct ApprovedTaskBatch {
    pub kind: BatchVersion,
    pub header: ApprovedTaskHeader,
    pub set_sha256: String,
    pub members: Vec<ApprovedServiceMember>,
    pub catalog: PrivateServiceGrantRef,
}

// These explicit wire types preserve strict deserialization and the singleton's
// original field order. The in-memory header is never flattened into a record.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SingleWire {
    parent: PrivateOriginalRef,
    acquisition: StoreKey,
    original_task: NativeOriginalTask,
    grant: PrivateServiceGrantRef,
    before_ms: u64,
}

impl Serialize for ApprovedTaskMember {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SingleWire { parent: self.parent.clone(), acquisition: self.acquisition.clone(),
            original_task: self.original_task.clone(), grant: self.grant.clone(),
            before_ms: self.before_ms }.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for ApprovedTaskMember {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = SingleWire::deserialize(deserializer)?;
        Ok(Self { header: ApprovedTaskHeader { parent: value.parent, acquisition: value.acquisition,
            original_task: value.original_task, before_ms: value.before_ms }, grant: value.grant })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchWire {
    kind: BatchVersion,
    parent: PrivateOriginalRef,
    acquisition: StoreKey,
    original_task: NativeOriginalTask,
    before_ms: u64,
    set_sha256: String,
    members: Vec<ApprovedServiceMember>,
    catalog: PrivateServiceGrantRef,
}
impl Serialize for ApprovedTaskBatch {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        BatchWire { kind: self.kind.clone(), parent: self.header.parent.clone(),
            acquisition: self.header.acquisition.clone(), original_task: self.header.original_task.clone(),
            before_ms: self.header.before_ms, set_sha256: self.set_sha256.clone(),
            members: self.members.clone(), catalog: self.catalog.clone() }.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for ApprovedTaskBatch {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = BatchWire::deserialize(deserializer)?;
        let selected = Self { kind: value.kind, header: ApprovedTaskHeader { parent: value.parent,
            acquisition: value.acquisition, original_task: value.original_task, before_ms: value.before_ms },
            set_sha256: value.set_sha256, members: value.members, catalog: value.catalog };
        ApprovedTaskLink::Batch(selected.clone()).validate().map_err(|_| serde::de::Error::custom("invalid public-service set"))?;
        Ok(selected)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(in crate::private_originals) enum ApprovedTaskLink {
    Batch(ApprovedTaskBatch),
    Single(ApprovedTaskMember),
}

impl std::ops::Deref for ApprovedTaskLink {
    type Target = ApprovedTaskHeader;
    fn deref(&self) -> &Self::Target {
        match self { Self::Single(value) => &value.header, Self::Batch(value) => &value.header }
    }
}

impl ApprovedTaskLink {
    #[cfg(test)]
    pub(super) fn header_mut(&mut self) -> &mut ApprovedTaskHeader {
        match self { Self::Single(value) => &mut value.header, Self::Batch(value) => &mut value.header }
    }

    pub(in crate::private_originals) fn single(header: ApprovedTaskHeader, grant: PrivateServiceGrantRef) -> Self {
        Self::Single(ApprovedTaskMember { header, grant })
    }

    pub(in crate::private_originals) fn singleton_grant(&self) -> Result<&PrivateServiceGrantRef, PrivateOriginalError> {
        match self { Self::Single(value) => Ok(&value.grant), Self::Batch(_) => Err(PrivateOriginalError::Denied) }
    }

    pub(in crate::private_originals) fn attachment_grant(&self, server: &str) -> Result<&PrivateServiceGrantRef, PrivateOriginalError> {
        match self {
            Self::Single(value) => Ok(&value.grant),
            Self::Batch(value) => value.members.iter().find(|member| member.connection.as_str() == server)
                .map(|member| &member.grant).ok_or(PrivateOriginalError::Denied),
        }
    }

    pub(in crate::private_originals) fn attachment_member(&self, grant: &PrivateServiceGrantRef) -> Result<ApprovedTaskMember, PrivateOriginalError> {
        self.attachments().into_iter().find(|member| &member.grant == grant).ok_or(PrivateOriginalError::Denied)
    }

    pub(in crate::private_originals) fn contains(&self, grant: &PrivateServiceGrantRef) -> bool {
        match self {
            Self::Single(value) => &value.grant == grant,
            Self::Batch(value) => &value.catalog == grant || value.members.iter().any(|member| &member.grant == grant),
        }
    }

    pub(in crate::private_originals) fn grants(&self) -> Vec<&PrivateServiceGrantRef> {
        match self {
            Self::Single(value) => vec![&value.grant],
            Self::Batch(value) => std::iter::once(&value.catalog)
                .chain(value.members.iter().map(|member| &member.grant)).collect(),
        }
    }

    /// A typed member projection for the existing attachment owner. It creates
    /// no source, approval, association or native authority of its own.
    pub(in crate::private_originals) fn attachments(&self) -> Vec<ApprovedTaskMember> {
        match self {
            Self::Single(value) => vec![value.clone()],
            Self::Batch(value) => value.members.iter().map(|member| ApprovedTaskMember {
                header: value.header.clone(), grant: member.grant.clone(),
            }).collect(),
        }
    }

    pub(in crate::private_originals) fn validate(&self) -> Result<(), PrivateOriginalError> {
        if let Self::Batch(value) = self {
            if value.members.len() < 2
                || value.members.len() > crate::installed_host::operator_setup::MAX_PUBLIC_SERVICE_BATCH
                || value.set_sha256.len() != 64
                || !value.set_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || value.members.windows(2).any(|pair| pair[0].connection >= pair[1].connection)
                || value.members.iter().any(|member| member.grant.route != value.header.parent.route)
                || value.catalog.route != value.header.parent.route
                || value.members.iter().any(|member| member.grant.route == value.catalog.route && member.grant.decision == value.catalog.decision)
                || value.members.iter().enumerate().any(|(index, member)| value.members[..index].iter()
                    .any(|prior| prior.grant.route == member.grant.route && prior.grant.decision == member.grant.decision))
            { return Err(PrivateOriginalError::Conflict); }
        }
        Ok(())
    }
}
