// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

contract SignatureVerifier {

    uint public SigVerifyGas;

    function verifySignature(uint _t, bytes32 _blockHeaderHash, bytes[] memory signature, address[] memory publicKeys) public returns (bool) {
        uint gasBefore = gasleft();
        uint t = _t;
        uint count_signers = 0;
        for (uint i = 0; i < publicKeys.length; i++) {
            for (uint j = 0; j < signature.length; j++) {
                address recoveredPublicKey = recoverSigner(_blockHeaderHash, signature[j]);
                if (recoveredPublicKey == publicKeys[i]) {
                   count_signers++;
                }
            }
        }
        uint gasAfter = gasleft();
        SigVerifyGas = gasBefore - gasAfter;
        if (count_signers == t){
            return true;
        }
        else
            return false;
    }

    function recoverSigner(bytes32 _blockHeaderHash, bytes memory _signature) internal pure returns (address) {
        bytes32 _messageHash = hashMessage(_blockHeaderHash);
        uint8 v;
        bytes32 r;
        bytes32 s;
        address _signer;
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }
        _signer = ecrecover(_messageHash, v, r, s);
        return _signer;
    }

    function hashMessage(bytes32 message) internal pure returns (bytes32) {
        string memory prefix = "\x19Ethereum Signed Message:\n32";
        return keccak256(abi.encodePacked(prefix, message));
    }

}
