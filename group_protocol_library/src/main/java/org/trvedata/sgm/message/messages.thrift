namespace java org.trvedata.sgm.message

// ***********************************************************************
// Structs for Utils

struct AeadMessage {
    1: required binary c,
    2: required binary a,
}

// ***********************************************************************
// Structs for serializing MembershipSet

struct MembershipSetStruct {
    // Instead of explicitly labelling members as non-removed or removed,
    // we use the fact that members are removed iff they have a RemoveInfoStruct.
    // Note that this only works because MembershipSet uses the rule that
    // removes always take effect (noting that the add-wins semantics doesn't
    // appear because we disallow re-adds).  If the membership rules are
    // changed, we would need to explicitly track who is in members and
    // who is in removedMembers.
    1: required list<MemberInfoStruct> membersAndRemovedMembers,
    // From now on we denote members by indices in the above list instead of serialized IdentityKey's.
    2: required list<RemoveInfoStruct> removeInfos,
    // From now on we denote RemoveInfo's by indices in the removeInfos list instead of RemoveInfoStruct's.
}

struct MemberInfoStruct {
    1: required binary id, // IdentityKey (serialized)
    2: optional i32 adder,
    3: optional i32 messageNumber,
    4: required list<i32> removeMessages,
    5: required set<i32> acks,
}

struct RemoveInfoStruct {
    1: required i32 remover,
    2: required i32 messageNumber,
    3: required set<i32> removedUsers,
    4: required set<i32> acks,
}

//***********************************************************************
// Structs for modular version

struct SignedMessageStruct {
    1: required binary content,
    2: required binary sender,
    3: required binary signature,
}

struct ModularMessageStruct {
    1: required bool dcgka,//else application
    2: required bool welcome,
    3: required binary content,
    4: optional binary orderInfo,//required except for group creation message, when it is null
    5: optional binary signatureUpdate,
}

struct TrivialDcgkaMessage {
    1: required FullDcgkaMessageType type,
    2: required list<binary> added,//users intended to be added
    3: required list<binary> removed,//users intended to be removed
}

struct SignatureWelcomeMessage {
    1: required map<binary, binary> currentPublicKeys,
}

struct VectorClockMessage {
    1: required binary sender,
    2: required map<binary, i32> clock,
}

struct AckOrdererTimestamp {
    1: required i32 number,
    2: optional binary ackAuthor,
    3: optional i32 ackNumber,
    4: optional binary clock,
}

// Structs for FullDcgkaProtocol

enum FullDcgkaMessageType {
    CREATE,
    UPDATE,
    REMOVE,
    ADD,
    WELCOME,
    ACK,
    ACK_WITH_UPDATE,
    ADD_ACK,
}

struct FullDcgkaMessage {
    1: required FullDcgkaMessageType type,
    2: required binary message, // one of the message types below, depending on type.
}

struct CreateMessage {
    1: required list<binary> idsExcludingSender,
    2: required list<binary> ciphertexts,
}

struct UpdateMessage {
    1: required list<binary> ciphertexts,
}

struct RemoveMessage {
    1: required binary removed,
    2: required list<binary> ciphertexts,
}

struct AddMessage {
    1: required binary added,
}

struct WelcomeMessage {
    1: required binary strongRemoveDgm,
    2: required binary prfForAdded,
}

struct AckMessage {
    1: required map<binary, binary> forwards,
}

struct AckWithUpdateMessage {
    1: required AckMessage ack;
    2: required UpdateMessage update;
}

struct AddAckMessage {
    1: required binary prfForAdded,
}

// Structs for TwoPartyProtocol

struct TwoPartyMessage {
    1: required binary ciphertext,// For an initiating message, this is a serialized
            // message from PreKeySecret, otherwise it is the public key encryption of a
            // serialized TwoPartyPlaintext.
    2: required bool senderOtherPkSender,
    3: required i32 receiverPkIndex,
}

struct TwoPartyPlaintext {
    1: required binary appPlaintext,
    2: required binary receiverNewSk,
    3: required i32 senderNewPkIndex,
    4: required binary senderNewPk,
}

// Structs for HPKE

struct HPKEMessage {
    1: required binary dhPublicKey,
    2: required binary symmetricCiphertext,
}

// Structs for Signature keys

struct SignatureStruct {
    1: required binary algOutput,
    2: required binary hashedPoint,
}

// Structs for PreKeys

struct PreKeyCiphertext {
    1: required binary ephemeralKey,
    2: required i32 preKeyId,
    3: required binary ciphertext,
}