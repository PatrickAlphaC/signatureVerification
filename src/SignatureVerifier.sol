// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract SignatureVerifier {
    /*//////////////////////////////////////////////////////////////
                           SIMPLE SIGNATURES
    //////////////////////////////////////////////////////////////*/
    function getSignerSimple(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public pure returns (address) {
        bytes32 hashedMessage = bytes32(message); // if string, we'd use keccak256(abi.encodePacked(string))
        address signer = ecrecover(hashedMessage, _v, _r, _s);
        return signer;
    }

    function verifySignerSimple(
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
        address actualSigner = getSignerSimple(message, _v, _r, _s);
        require(signer == actualSigner);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                           EIP-191 SIGNATURES
    //////////////////////////////////////////////////////////////*/
    /* 
    * People liked signatures, and wanted to use them to send transactions by signatues. Standard ETH transactions have
    the following components:
     * 
     * RLP<nonce, gasPrice, startGas, to, value, data>
     * 
    * So, if someone signed a transaction with these values, they could hypothetically send it to the network. We want
    to allow users to sign transactions to get this data, so others can send transactions for them. 
     * however, there is an issue. 
     * In our example above, we used this:
     * 
     * ecrecover(_hashedMessage, _v, _r, _s);
     * 
    * We assumed that the order was <hash, v, r, s>, but that was just because that's what this contract decided. Any
    contract could hypothetically put these in any order, and this would make it very difficult for wallets to display
    to the user what was going on!
     * 
    * So, we as a web3 community decided on a standard for encoding & decoding signatures. The format we chose looks
    like this:
     * 
     * 0x19 <1 byte version> <version specific data> <data to sign>.
     * 
    * 0x19 is a prefix saying "hey! I'm a signature!". 0x19 was chosen because it's a weird number not used in any other
    context. It's decimal value is 25, we don't really use 25 for anything. 
     * 
    * Additionally, this ensures that the data associated with a signed message cannot be a valid ETH transaction
    itself, because of how ETH transactions are encoded. There are some other reasons for this number as well. 
     * 
    * Then, the <1 byte version> is what version of "signed data" the user is using. Perhaps in the future we want to
    format our signed data different. This <1 byte version> allows us to do that. There are 3 commonly used versions as
    of today:
     * 
     * 0x00: Data with intended validator 
     * 0x01: Structured data
     * 0x45: personal_sign messages
     * 
     * 0x01 is used most often in production dapps, and associated with EIP-712. We'll talk about that later.
     * 
     * Let's see what these look like
     */

    function getSigner191(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public view returns (address) {
        // Arguments when calculating hash to validate
        // 1: byte(0x19) - the initial 0x19 byte
        // 2: byte(0) - the version byte
        // 3: version specific data, for version 0, it's the intended validator address
        // 4-6 : Application specific data

        bytes1 prefix = bytes1(0x19);
        bytes1 eip191Version = bytes1(0);
        address indendedValidatorAddress = address(this);
        bytes32 applicationSpecificData = bytes32(message);

        // 0x19 <1 byte version> <version specific data> <data to sign>
        bytes32 hashedMessage =
            keccak256(abi.encodePacked(prefix, eip191Version, indendedValidatorAddress, applicationSpecificData));

        address signer = ecrecover(hashedMessage, _v, _r, _s);
        return signer;
    }

    function verifySigner191(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer
    )
        public
        view
        returns (bool)
    {
        address actualSigner = getSigner191(message, _v, _r, _s);
        require(signer == actualSigner);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                           EIP-712 SIGNATURES
    //////////////////////////////////////////////////////////////*/

    /* 
    * EIP-191 was cool, but not enough detail. The "4-6 : Application specific data" of EIP-191 wasn't specific enough.
    On user wallets, when prompted to sign some structured data, they would just be shown some horrible bytestring/hex.
    So the community came together to structure that application specific data so users could know more clearly what
    they were signing. 
     * 
     * You'll notice, we still follow EIP-191, but now we have a way to format the data inside EIP-191.
     * 
    * In this EIP, we add a lot of structures to make verification of the data extensible and strict. For EIP-191,
    version 0 looked like this:
     * 
     * 0x19 0x00 <intended_validator> <data to sign>
     * 
     * EIP-712, aka version 1, looks like this:
     * 
     * 0x19 0x01 <domainSeparator> <hashStruct(message)>
     * 
    * A domain separator is the hash of a struct which defines the domain of the message being signed. It contains one
    or all of the following:
     * 
     * string name
     * string version 
     * uint256 chainId
     * address verifyingContract
     * bytes32 salt
     * 
     * This is known as the `eip712Domain`. 
     * 
    * This way, contracts can know that a signature was created specificly for this contract or not. We wouldn't want a
    signature for a different contract to work on your contract! Knowing this, we can rewrite our EIP-712 data to be:
     * 
     * 0x19 0x01 <hashStruct(eip712Domain)> <hashStruct(message)>
     * 
     * So... What's a hashStruct? Well, here is the symbolic definition:
     * `hashStruct(s : 𝕊) = keccak256(typeHash ‖ encodeData(s))` where `typeHash = keccak256(encodeType(typeOf(s)))`
     * 
    * A hashStruct is just a hash of a struct, that includes a hash of what the struct looks like. The hash of the type
    of the struct is known as the typehash. 
     * 
     * 0x19 0x01 <hashStruct(eip712Domain)> <hashStruct(message)>
    * 0x19 0x01 <keccak256(keccak256(encodeType(typeOf(eip712Domain))) || eip712Domain)>
    <keccak256(keccak256(encodeType(typeOf(message))) ‖ message)>
     * 
     * well that's horrible to read, more simply, we can say:
     * 
    * 0x19 0x01 <hash of who verifies this signature, and what the verifier looks like> <hash of signed structured
    message, and what the sig looks like>
     * 
     * Let's look at this example:
     * 
    */

    /*
    * Here, we have our EIP-712 domain struct, which we will hash into the TYPEHASH for our eip712Domain.
    */
    struct EIP712Domain {
        // bytes32 salt; if you'd like to include, you can, but it's not required
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    // Here is the hash of our EIP721 domain struct
    bytes32 constant EIP712DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    // Here is where things get a bit hairy
    // Since we want to make sure signatures ONLY work for our contract, on our chain, with our application
    // We need to define some variables
    // Often, it's best to make these immutables so they can't ever change
    EIP712Domain eip_712_domain_separator_struct;
    bytes32 public immutable i_domain_separator;

    constructor() {
        // Here, we define what our "domain" struct looks like.
        eip_712_domain_separator_struct = EIP712Domain({
            name: "SignatureVerifier", // this can be whatever you want
            version: "1", // this can be whatever you want
            chainId: 1, // ideally this is your chainId
            verifyingContract: address(this) // ideally, you set this as "this", but you could make it whatever contract
                // you want to use to verify signatures
         });

        // Then, we define who is going to verify our signatures? Now that we know what the format of our domain is
        i_domain_separator = keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(eip_712_domain_separator_struct.name)),
                keccak256(bytes(eip_712_domain_separator_struct.version)),
                eip_712_domain_separator_struct.chainId,
                eip_712_domain_separator_struct.verifyingContract
            )
        );
    }

    // THEN we need to define what our message hash struct looks like.
    struct Message {
        uint256 number;
    }

    bytes32 public constant MESSAGE_TYPEHASH = keccak256("Message(uint256 number)");

    function getSignerEIP712(uint256 message, uint8 _v, bytes32 _r, bytes32 _s) public view returns (address) {
        // Arguments when calculating hash to validate
        // 1: byte(0x19) - the initial 0x19 byte
        // 2: byte(1) - the version byte
        // 3: hashstruct of domain separator (includes the typehash of the domain struct)
        // 4: hashstruct of message (includes the typehash of the message struct)

        // bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        // bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, nonces[msg.sender], _hashedMessage));
        // address signer = ecrecover(prefixedHashMessage, _v, _r, _s);
        // require(msg.sender == signer);
        // return signer;

        bytes1 prefix = bytes1(0x19);
        bytes1 eip712Version = bytes1(0x01); // EIP-712 is version 1 of EIP-191
        bytes32 hashStructOfDomainSeparator = i_domain_separator;

        // now, we can hash our message struct
        bytes32 hashedMessage = keccak256(abi.encode(MESSAGE_TYPEHASH, Message({ number: message })));

        // And finally, combine them all
        bytes32 digest = keccak256(abi.encodePacked(prefix, eip712Version, hashStructOfDomainSeparator, hashedMessage));
        return ecrecover(digest, _v, _r, _s);
    }

    function verifySigner712(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer
    )
        public
        view
        returns (bool)
    {
        address actualSigner = getSignerEIP712(message, _v, _r, _s);

        require(signer == actualSigner);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                  REPLAY RESISTANT SIGNATURES
    //////////////////////////////////////////////////////////////*/
    // To prevent signature replay attacks, smart contracts must:
    // 1. Have every signature have a unique nonce that is validated
    // 2. Set and check an expiration date
    // 3. Restrict the s value to a single half
    // 4. Include a chainId to prevent cross-chain replay attacks
    // 5. Any other unique identifiers (for example, if you have multiple things to sign in the same contract/chain/etc)

    // Optional, but ideal:
    // 6. Check signature length (to look for EIP-2098)
    // 7. Check if claimant is a contract (ERC-1271 aka, contract compatibility)
    // 8. Check ecrecover's return result

    // In order to get our signatures to be replay resistant, we need to add a deadline and nonce to our signature.
    struct ReplayResistantMessage {
        uint256 number;
        uint256 deadline;
        uint256 nonce;
    }

    bytes32 public constant REPLAY_RESISTANT_MESSAGE_TYPEHASH =
        keccak256("Message(uint256 number,uint256 deadline,uint256 nonce)");

    // Now, we also need to keep track of nonces!
    mapping(address => mapping(uint256 => bool)) public noncesUsed;
    mapping(address => uint256) public latestNonce;

    // Now, this is basically the same, we just include a deadline and a nonce in our signature
    function getSignerReplayResistant(
        uint256 message,
        uint256 deadline,
        uint256 nonce,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    )
        public
        view
        returns (address)
    {
        // Arguments when calculating hash to validate
        // 1: byte(0x19) - the initial 0x19 byte
        // 2: byte(1) - the version byte
        // 3: hashstruct of domain separator (includes the typehash of the domain struct)
        // 4: hashstruct of message (includes the typehash of the message struct)
        bytes1 prefix = bytes1(0x19);
        bytes1 eip712Version = bytes1(0x01); // EIP-712 is version 1 of EIP-191
        bytes32 hashStructOfDomainSeparator = i_domain_separator;

        bytes32 hashedMessage = keccak256(
            abi.encode(
                REPLAY_RESISTANT_MESSAGE_TYPEHASH,
                ReplayResistantMessage({ number: message, deadline: deadline, nonce: nonce })
            )
        );

        bytes32 digest = keccak256(abi.encodePacked(prefix, eip712Version, hashStructOfDomainSeparator, hashedMessage));
        return ecrecover(digest, _v, _r, _s);
    }

    function verifySignerReplayResistant(
        ReplayResistantMessage memory message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer
    )
        public
        returns (bool)
    {
        // 1. Use unused unique nonce
        require(!noncesUsed[signer][message.nonce], "Need unique nonce");
        noncesUsed[signer][message.nonce] = true;
        latestNonce[signer] = message.nonce;

        // 2. Expiration Date
        require(block.timestamp < message.deadline, "Expired");

        // Check ecrecover's return result
        address actualSigner = getSignerReplayResistant(message.number, message.deadline, message.nonce, _v, _r, _s);
        require(signer == actualSigner);

        // 3. Restrict the s value to a single half
        // This prevents "signature malleability"
        // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/b5a7f977d8a57b6854545522e36d91a0c11723cd/contracts/utils/cryptography/ECDSA.sol#L128
        if (uint256(_s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert("bad s");
        }

        // 4. Use chainId
        // we have it in our domain separator, so it should be ok

        // 5. Other
        // None
        return true;
    }
}
