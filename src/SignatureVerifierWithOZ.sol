// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureVerifier {
    function getSignerOZ(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public pure returns (address) {
        bytes32 hashedMessage = bytes32(message);
        (address signer, /*ECDSA.RecoverError recoverError*/, /*bytes32 signatureLength*/ ) =
            ECDSA.tryRecover(hashedMessage, _v, _r, _s);

        // The above is equivalent to each of the following:
        // address signer = ECDSA.recover(hashedMessage, _v, _r, _s);
        // address signer = ecrecover(hashedMessage, _v, _r, _s);

        // bytes memory packedSignature = abi.encodePacked(_r, _s, _v); // <-- Yes, the order here is different!
        // address signer = ECDSA.recover(hashedMessage, packedSignature);
        return signer;
    }

    function verifySignerOZ(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer
    )
        public
        pure
        returns (bool)
    {
        // You can also use isValidSignatureNow
        address actualSigner = getSignerOZ(message, _v, _r, _s);
        require(actualSigner == signer);
        return true;
    }
}
