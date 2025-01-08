// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { SignatureVerifierWithOZ } from "../src/SignatureVerifierWithOZ.sol";
import { Test } from "forge-std/Test.sol";

contract SignatureVerifierTestWithOZ is Test {
    SignatureVerifierWithOZ private _signatureVerifierWithOZ;
    Account private _bob = makeAccount("bob");
    Account private _attacker = makeAccount("attacker");

    function setUp() external {
        _signatureVerifierWithOZ = new SignatureVerifierWithOZ("SigVerifierOZ", "1");
    }

    function testDeploy() external {
        assertNotEq(address(_signatureVerifierWithOZ), address(0));
    }

    function testVerifySignature() external {
        string memory message = "Hello, I am Bob";

        bytes32 digest = _signatureVerifierWithOZ.getMessageHash(message);

        // Bob signs the message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_bob.key, digest);

        // we store the signature
        bytes memory signature = abi.encodePacked(r, s, v);

        // Now, we will verify whether the address claiming to be Bob is actually Bob or not.

        assertTrue(_signatureVerifierWithOZ.verifySignerOZ(message, signature, _bob.addr));
        assertFalse(_signatureVerifierWithOZ.verifySignerOZ(message, signature, _attacker.addr));
    }
}
