// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureVerifierWithOZ is EIP712 {

    struct Message {
        string message;
    }

    bytes32 public constant MESSAGE_TYPEHASH = keccak256(
        "Message(string message)"
    );

    constructor(string memory name, string memory version) EIP712(name, version) {}

    // returns the hash of the fully encoded EIP712 message for this domain i.e. the keccak256 digest of an EIP-712 typed data (EIP-191 version `0x01`).
    function getMessageHash(string calldata _message) public view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(abi.encode(MESSAGE_TYPEHASH, keccak256(bytes(_message))))
            );
    }

    function verifySignerOZ(
        string calldata message,
        bytes memory signature,
        address signer
    )
        public
        view
        returns (bool)
    {
        // You can also use isValidSignatureNow
        address actualSigner = getSignerOZ(getMessageHash(message), signature);

        return (actualSigner == signer);
    }

    function getSignerOZ(bytes32 digest, bytes memory signature) public pure returns (address) {
        (address signer, /*ECDSA.RecoverError recoverError*/, /*bytes32 signatureLength*/ ) =
            ECDSA.tryRecover(digest, signature);

        // The above is equivalent to each of the following:
        // address signer = ECDSA.recover(hashedMessage, _v, _r, _s);
        // address signer = ecrecover(hashedMessage, _v, _r, _s);

        // bytes memory packedSignature = abi.encodePacked(_r, _s, _v); // <-- Yes, the order here is different!
        // address signer = ECDSA.recover(hashedMessage, packedSignature);
        return signer;
    }

}
