// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "./sigVerfication.sol";

contract BlockHeaderValidator {

    struct BlockHeader {
        bytes32 previousBlockHash;
        bytes32 currentBlockHash;
        uint256 timestamp;
    }
    BlockHeader public latestBlockHeader;
    BlockHeader[] public headerHistory; // list of verified headers

    struct ConsensusRule{
        uint number_of_signer_required;
        address[] Cnode_addresses;
    }

    mapping(uint => ConsensusRule) public bc_data;

    SignatureVerifier verifyblkSig  = new SignatureVerifier();
    uint public gasUsed;

    constructor() {
        headerHistory.push(BlockHeader({
            previousBlockHash: 0x0000000000000000000000000000000000000000000000000000000000000000, //genesis block
            currentBlockHash:0x3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a,
            timestamp: 0
        }));
    }


    function headerUpdate(
        uint _bcId,
        bytes32 previousBlockHeaderHash,
        bytes32 currentBlockHeaderHash,
        uint256 _timestamp,
        bytes[] memory signature
    ) public returns(bool) {
        uint gasBefore = gasleft();
        //get remote consensus rule: t = required number of signature; pkCnodes = public keys of C-nodes in BC 1/2
        uint t;
        address[] memory pkCnodes;
        (t, pkCnodes) = getBCInfo(_bcId);
        // verify blkHeader signature (t-out-of-n) based on remote consensus rule
        bool _sigValid = verifyblkSig.verifySignature(t, currentBlockHeaderHash, signature, pkCnodes);
        if (_sigValid == true){
            //verify it is a next valid block header
            bool _nextHeaderValid = verifyHeaderUpdate(previousBlockHeaderHash, currentBlockHeaderHash, _timestamp);
            if (_nextHeaderValid == true){
                headerHistory.push(BlockHeader(previousBlockHeaderHash, currentBlockHeaderHash, _timestamp)); // add header to header history
                uint gasAfter = gasleft();
                gasUsed = gasBefore - gasAfter;
                return  true;
            }
            else {
                uint gasAfter = gasleft();
                gasUsed = gasBefore - gasAfter;
                return false;
            }
        }
        else{
            uint gasAfter = gasleft();
            gasUsed = gasBefore - gasAfter;
            return false;
        }
    }

    function verifyHeaderUpdate(bytes32 _previousBlockHash, bytes32 _blockHash, uint256 _timestamp) internal returns(bool) {
        latestBlockHeader = getLastBlockHeader();
        BlockHeader memory nextBlockHeader = BlockHeader({
            previousBlockHash: _previousBlockHash,
            currentBlockHash: _blockHash,
            timestamp: _timestamp
        });

        require(nextBlockHeader.previousBlockHash == latestBlockHeader.currentBlockHash, "Block is not a next valid block from previous block header");
        require(nextBlockHeader.timestamp > latestBlockHeader.timestamp, "Block timestamp is not greater than previous block timestamp");

        bytes32 calculatedBlockHash = calculateBlockHash(nextBlockHeader.previousBlockHash, nextBlockHeader.timestamp);
        require(calculatedBlockHash == nextBlockHeader.currentBlockHash, "Block hash is invalid");
        addNewBlockHeadertoHistory(nextBlockHeader);

        return true;
    }

    function addNewBlockHeadertoHistory(BlockHeader memory newBlockHeader) internal {
        latestBlockHeader = newBlockHeader;
    }

    function getLastBlockHeader() public view returns (BlockHeader memory) {
        return headerHistory[headerHistory.length - 1];
    }

    function calculateBlockHash(bytes32 _previousBlockHash, uint256 _timestamp) internal pure returns(bytes32) {
        bytes32 hash = keccak256(abi.encodePacked(_previousBlockHash, _timestamp));
        return hash;
    }

    //---------------------- xccRule --------------------------------------------------------
    function setxccRules(uint _BCID, uint _numOfSigner, address[] memory _publicKeys) public {
        bc_data[_BCID] = ConsensusRule({
            number_of_signer_required: _numOfSigner,
            Cnode_addresses: _publicKeys
        });
    }

    function getBCInfo(uint _BCId) public view returns (uint, address[] memory){
        return (bc_data[_BCId].number_of_signer_required, bc_data[_BCId].Cnode_addresses);
    }
    //==================================================================================


    //-------------------------- xcVerification ----------------------------------------------------------
    function verifyProof(bytes32 _txHash, uint _blockIndex, bytes32[] memory _Mproof) public view returns (bool){
        bool isTxValid = verifyTx(_txHash, _blockIndex, _Mproof);
        return isTxValid;
    }

    function verifyTx(bytes32 txHash, uint _blockNumber, bytes32[] memory proof) public view returns (bool) {
        bytes32 proofElement;
        bytes32 computedHash = txHash;
        for (uint256 i = 32; i <= proof.length; i += 32) {
            assembly {
                proofElement := mload(add(proof, i))
            }
            if (computedHash < proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        // Check the merkle proof
        bytes32 _MHroot = getHeader(_blockNumber);
        if (computedHash == _MHroot){
            return true;
        }
        else{
            return false;
        }
    }

    function getHeader(uint _index) public view returns (bytes32){
        return headerHistory[_index].currentBlockHash;
    }
    //==============================================================================================================================

}
