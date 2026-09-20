// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CascadiaProofRegistry {
    struct AuditBatch {
        bytes32 merkleRoot;
        uint256 batchStartTime;
        uint256 batchEndTime;
        uint256 eventCount;
        uint256 anchoredAt;
    }

    struct DecisionRecord {
        bytes32 evidenceHash;
        address approverAddress;
        uint256 timestamp;
    }

    uint256 public auditBatchCount;
    mapping(uint256 => AuditBatch) private auditBatches;
    mapping(bytes32 => DecisionRecord) private decisionRecords;

    event AuditBatchAnchored(
        uint256 indexed batchId,
        bytes32 merkleRoot,
        uint256 batchStartTime,
        uint256 batchEndTime,
        uint256 eventCount
    );

    event DecisionRecorded(
        string decisionId,
        bytes32 evidenceHash,
        string decisionType,
        address approverAddress,
        uint256 timestamp,
        bytes approverSignature
    );

    function anchorAuditBatch(
        bytes32 merkleRoot,
        uint256 batchStartTime,
        uint256 batchEndTime,
        uint256 eventCount
    ) external {
        require(eventCount > 0, "empty audit batch");
        require(batchEndTime >= batchStartTime, "invalid batch window");
        uint256 batchId = auditBatchCount;
        auditBatchCount += 1;
        auditBatches[batchId] = AuditBatch(
            merkleRoot,
            batchStartTime,
            batchEndTime,
            eventCount,
            block.timestamp
        );
        emit AuditBatchAnchored(batchId, merkleRoot, batchStartTime, batchEndTime, eventCount);
    }

    function getAuditBatch(uint256 batchId)
        external
        view
        returns (bytes32 merkleRoot, uint256 batchStartTime, uint256 batchEndTime, uint256 eventCount, uint256 anchoredAt)
    {
        AuditBatch memory batch = auditBatches[batchId];
        return (batch.merkleRoot, batch.batchStartTime, batch.batchEndTime, batch.eventCount, batch.anchoredAt);
    }

    function recordDecision(
        string calldata decisionId,
        bytes32 evidenceHash,
        string calldata decisionType,
        address approverAddress,
        uint256 timestamp,
        bytes calldata approverSignature
    ) external {
        require(approverAddress != address(0), "invalid approver");
        require(timestamp > 0, "invalid timestamp");
        require(decisionRecords[keccak256(bytes(decisionId))].timestamp == 0, "decision already recorded");
        require(_recover(evidenceHash, approverSignature) == approverAddress, "invalid approver signature");
        decisionRecords[keccak256(bytes(decisionId))] = DecisionRecord(evidenceHash, approverAddress, timestamp);
        emit DecisionRecorded(decisionId, evidenceHash, decisionType, approverAddress, timestamp, approverSignature);
    }

    function getDecisionRecord(string calldata decisionId)
        external
        view
        returns (bytes32 evidenceHash, address approverAddress, uint256 timestamp)
    {
        DecisionRecord memory record = decisionRecords[keccak256(bytes(decisionId))];
        return (record.evidenceHash, record.approverAddress, record.timestamp);
    }

    function _recover(bytes32 evidenceHash, bytes calldata signature) private pure returns (address) {
        require(signature.length == 65, "invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "invalid signature recovery id");
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", evidenceHash));
        return ecrecover(digest, v, r, s);
    }
}
