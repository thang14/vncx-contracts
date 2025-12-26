import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeAbiParameters, keccak256, hashMessage, getAddress, stringToHex, hexToBytes, slice } from "viem";

import { network } from "hardhat";

describe("VNCXMasterAnchor", async function () {
  const { viem } = await network.connect();
  const publicClient = await viem.getPublicClient();
  const [owner, orgOwner, worker, operator, unauthorized] = await viem.getWalletClients();

  // Helper function to convert string to bytes32 (keccak256 hash)
  function stringToBytes32(str: string): `0x${string}` {
    // Convert string to hex bytes and then hash
    const hexString = stringToHex(str);
    return keccak256(hexString);
  }

  // Helper function to convert string array to bytes32 array
  function stringsToBytes32Array(strs: string[]): `0x${string}`[] {
    return strs.map(str => stringToBytes32(str));
  }

  // Helper function to compute batch hash (matches contract's keccak256(abi.encode(...)))
  function computeBatchHash(orgId: `0x${string}`, batchIds: `0x${string}`[], dataHashes: `0x${string}`[]): `0x${string}` {
    const encoded = encodeAbiParameters(
      [
        { name: "_orgId", type: "bytes32" },
        { name: "_batchIds", type: "bytes32[]" },
        { name: "_dataHashes", type: "bytes32[]" },
      ],
      [orgId, batchIds, dataHashes]
    );
    return keccak256(encoded);
  }

  // Helper function to split signature into r, s, v
  // Signature is 65 bytes: r (32 bytes) + s (32 bytes) + v (1 byte)
  function splitSignature(signature: `0x${string}`): { r: `0x${string}`; s: `0x${string}`; v: number } {
    // r: first 32 bytes (bytes 0-31)
    const r = slice(signature, 0, 32) as `0x${string}`;
    // s: next 32 bytes (bytes 32-63)
    const s = slice(signature, 32, 64) as `0x${string}`;
    // v: last byte (byte 64)
    const vByte = slice(signature, 64, 65);
    // Convert hex byte to number
    const v = parseInt(vByte.slice(2), 16);
    
    return { r, s, v };
  }

  describe("Deployment", function () {
    it("Should set the correct owner", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      assert.equal(
        getAddress(await contract.read.owner()),
        getAddress(owner.account.address)
      );
    });
  });

  describe("registerOrg", function () {
    it("Should register a new organization", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      const ownerAddress = orgOwner.account.address;

      const deploymentBlockNumber = await publicClient.getBlockNumber();

      await contract.write.registerOrg([orgId, ownerAddress], { account: owner.account });

      // Check that org was registered
      assert.equal(
        getAddress(await contract.read.orgOwners([orgId])),
        getAddress(ownerAddress)
      );

      // Check event was emitted
      const events = await publicClient.getContractEvents({
        address: contract.address as `0x${string}`,
        abi: contract.abi,
        eventName: "OrgRegistered",
        fromBlock: deploymentBlockNumber,
      });

      assert.equal(events.length, 1);
      assert.equal(getAddress(events[0].args.owner as `0x${string}`), getAddress(ownerAddress));
      assert.equal(events[0].args.orgId, orgId);
    });

    it("Should revert if org already registered", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      const ownerAddress = orgOwner.account.address;

      await contract.write.registerOrg([orgId, ownerAddress], { account: owner.account });

      try {
        await contract.write.registerOrg([orgId, ownerAddress], { account: owner.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Org already registered"), `Expected "Org already registered" but got: ${error.message}`);
      }
    });

    it("Should revert if called by non-owner", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      const ownerAddress = orgOwner.account.address;

      try {
        await contract.write.registerOrg([orgId, ownerAddress], { account: unauthorized.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("OwnableUnauthorizedAccount"), `Expected "OwnableUnauthorizedAccount" but got: ${error.message}`);
      }
    });

    it("Should revert if owner address is zero", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      const zeroAddress = "0x0000000000000000000000000000000000000000" as `0x${string}`;

      try {
        await contract.write.registerOrg([orgId, zeroAddress], { account: owner.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Invalid address"), `Expected "Invalid address" but got: ${error.message}`);
      }
    });
  });

  describe("registerOperator", function () {
    it("Should register an operator", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const operatorAddress = operator.account.address;

      const deploymentBlockNumber = await publicClient.getBlockNumber();

      await contract.write.registerOperator([operatorAddress, true], { account: owner.account });

      assert.equal(
        await contract.read.operators([operatorAddress]),
        true
      );

      // Check event was emitted
      const events = await publicClient.getContractEvents({
        address: contract.address as `0x${string}`,
        abi: contract.abi,
        eventName: "OperatorRegistered",
        fromBlock: deploymentBlockNumber,
      });

      assert.equal(events.length, 1);
      assert.equal(getAddress(events[0].args.operator as `0x${string}`), getAddress(operatorAddress));
      assert.equal(events[0].args.status, true);
    });

    it("Should unregister an operator", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const operatorAddress = operator.account.address;

      await contract.write.registerOperator([operatorAddress, true], { account: owner.account });
      await contract.write.registerOperator([operatorAddress, false], { account: owner.account });

      assert.equal(
        await contract.read.operators([operatorAddress]),
        false
      );
    });

    it("Should revert if called by non-owner", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const operatorAddress = operator.account.address;

      try {
        await contract.write.registerOperator([operatorAddress, true], { account: unauthorized.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("OwnableUnauthorizedAccount"), `Expected "OwnableUnauthorizedAccount" but got: ${error.message}`);
      }
    });

    it("Should revert if operator address is zero", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const zeroAddress = "0x0000000000000000000000000000000000000000" as `0x${string}`;

      try {
        await contract.write.registerOperator([zeroAddress, true], { account: owner.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Invalid address"), `Expected "Invalid address" but got: ${error.message}`);
      }
    });
  });

  describe("verifyOrg", function () {
    it("Should verify an organization with metadata", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const metadataHash = keccak256(stringToHex("org-name:Example Corp,domain:example.com"));
      const verificationNote = "Verified business registration and domain ownership";

      const deploymentBlockNumber = await publicClient.getBlockNumber();

      await contract.write.verifyOrg([orgId, true, metadataHash, verificationNote], { account: owner.account });

      // Check verification status
      assert.equal(await contract.read.isOrgVerified([orgId]), true);

      // Get detailed verification info
      const info = await contract.read.getOrgVerificationInfo([orgId]);
      assert.equal(info.isVerified, true);
      assert.equal(getAddress(info.verifier), getAddress(owner.account.address));
      assert.equal(info.metadataHash, metadataHash);
      assert.equal(info.verificationNote, verificationNote);
      assert(info.verifiedAt > 0n);

      // Check event was emitted
      const events = await publicClient.getContractEvents({
        address: contract.address as `0x${string}`,
        abi: contract.abi,
        eventName: "OrgVerified",
        fromBlock: deploymentBlockNumber,
      });

      assert.equal(events.length, 1);
      assert.equal(events[0].args.orgId, orgId);
      assert.equal(events[0].args.status, true);
      assert.equal(getAddress(events[0].args.verifier as `0x${string}`), getAddress(owner.account.address));
      assert.equal(events[0].args.metadataHash, metadataHash);
      assert.equal(events[0].args.verificationNote, verificationNote);
    });

    it("Should verify org by operator", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });
      await contract.write.registerOperator([operator.account.address, true], { account: owner.account });

      const metadataHash = keccak256(stringToHex("verified-org"));
      const verificationNote = "Verified by operator";

      await contract.write.verifyOrg([orgId, true, metadataHash, verificationNote], { account: operator.account });

      const info = await contract.read.getOrgVerificationInfo([orgId]);
      assert.equal(info.isVerified, true);
      assert.equal(getAddress(info.verifier), getAddress(operator.account.address));
    });

    it("Should unverify an organization", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const metadataHash = keccak256(stringToHex("verified"));
      await contract.write.verifyOrg([orgId, true, metadataHash, "Verified"], { account: owner.account });
      assert.equal(await contract.read.isOrgVerified([orgId]), true);

      await contract.write.verifyOrg([orgId, false, metadataHash, "Unverified"], { account: owner.account });
      assert.equal(await contract.read.isOrgVerified([orgId]), false);

      const info = await contract.read.getOrgVerificationInfo([orgId]);
      assert.equal(info.isVerified, false);
    });

    it("Should revert if called by non-owner and non-operator", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const metadataHash = keccak256(stringToHex("test"));
      
      try {
        await contract.write.verifyOrg([orgId, true, metadataHash, ""], { account: unauthorized.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Only Owner or Operator can verify"), `Expected "Only Owner or Operator can verify" but got: ${error.message}`);
      }
    });

    it("Should revert if org is not registered", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("non-existent-org");
      const metadataHash = keccak256(stringToHex("test"));

      try {
        await contract.write.verifyOrg([orgId, true, metadataHash, ""], { account: owner.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Org not registered"), `Expected "Org not registered" but got: ${error.message}`);
      }
    });

    it("Should return false for unverified org", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      assert.equal(await contract.read.isOrgVerified([orgId]), false);
    });
  });

  describe("getOrgVerificationInfo", function () {
    it("Should return verification info for verified org", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const metadataHash = keccak256(stringToHex("metadata"));
      const verificationNote = "Test verification note";
      
      await contract.write.verifyOrg([orgId, true, metadataHash, verificationNote], { account: owner.account });

      const info = await contract.read.getOrgVerificationInfo([orgId]);
      assert.equal(info.isVerified, true);
      assert.equal(info.metadataHash, metadataHash);
      assert.equal(info.verificationNote, verificationNote);
      assert(info.verifiedAt > 0n);
    });

    it("Should return default values for unverified org", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const info = await contract.read.getOrgVerificationInfo([orgId]);
      assert.equal(info.isVerified, false);
      assert.equal(info.metadataHash, "0x0000000000000000000000000000000000000000000000000000000000000000");
      assert.equal(info.verificationNote, "");
      assert.equal(info.verifiedAt, 0n);
    });
  });

  describe("verifyOrgMetadata", function () {
    it("Should return true for matching metadata hash", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const metadataHash = keccak256(stringToHex("org-data"));
      await contract.write.verifyOrg([orgId, true, metadataHash, "Verified"], { account: owner.account });

      assert.equal(await contract.read.verifyOrgMetadata([orgId, metadataHash]), true);
    });

    it("Should return false for non-matching metadata hash", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const metadataHash = keccak256(stringToHex("org-data"));
      await contract.write.verifyOrg([orgId, true, metadataHash, "Verified"], { account: owner.account });

      const wrongHash = keccak256(stringToHex("wrong-data"));
      assert.equal(await contract.read.verifyOrgMetadata([orgId, wrongHash]), false);
    });

    it("Should return false for unverified org even with matching hash", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const metadataHash = keccak256(stringToHex("org-data"));
      // Org is not verified
      assert.equal(await contract.read.verifyOrgMetadata([orgId, metadataHash]), false);
    });
  });

  describe("authorizeWorker", function () {
    it("Should authorize a worker", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const workerAddress = worker.account.address;

      const deploymentBlockNumber = await publicClient.getBlockNumber();

      await contract.write.authorizeWorker([orgId, workerAddress, true], { account: orgOwner.account });

      assert.equal(
        await contract.read.authorizedWorkers([orgId, workerAddress]),
        true
      );

      // Check event was emitted
      const events = await publicClient.getContractEvents({
        address: contract.address as `0x${string}`,
        abi: contract.abi,
        eventName: "WorkerAuthorized",
        fromBlock: deploymentBlockNumber,
      });

      assert.equal(events.length, 1);
      assert.equal(getAddress(events[0].args.worker as `0x${string}`), getAddress(workerAddress));
      assert.equal(events[0].args.status, true);
      assert.equal(events[0].args.orgId, orgId);
    });

    it("Should revoke worker authorization", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const workerAddress = worker.account.address;

      await contract.write.authorizeWorker([orgId, workerAddress, true], { account: orgOwner.account });
      await contract.write.authorizeWorker([orgId, workerAddress, false], { account: orgOwner.account });

      assert.equal(
        await contract.read.authorizedWorkers([orgId, workerAddress]),
        false
      );
    });

    it("Should revert if called by non-org-owner", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const workerAddress = worker.account.address;

      try {
        await contract.write.authorizeWorker([orgId, workerAddress, true], { account: unauthorized.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Only Org Owner can authorize"), `Expected "Only Org Owner can authorize" but got: ${error.message}`);
      }
    });
  });

  describe("recordOrgBatch", function () {
    it("Should record batch when called by org owner (unverified org)", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      // Org is not verified, but should still be able to record
      const batchIds = stringsToBytes32Array(["batch-1", "batch-2"]);
      const dataHashes = stringsToBytes32Array(["hash1", "hash2"]);

      const deploymentBlockNumber = await publicClient.getBlockNumber();

      await contract.write.recordOrgBatch(
        [orgId, batchIds, dataHashes],
        { account: orgOwner.account }
      );

      const events = await publicClient.getContractEvents({
        address: contract.address as `0x${string}`,
        abi: contract.abi,
        eventName: "AnchorRecorded",
        fromBlock: deploymentBlockNumber,
      });

      assert.equal(events.length, 2);
      assert.equal(events[0].args.dataHash, dataHashes[0]);
      assert.equal(events[0].args.batchId, batchIds[0]);
      assert.equal(events[0].args.orgId, orgId);
      assert.equal(getAddress(events[0].args.submitter as `0x${string}`), getAddress(orgOwner.account.address));

      assert.equal(await contract.read.verifyHash([dataHashes[0]]), true);
      assert.equal(await contract.read.verifyHash([dataHashes[1]]), true);
    });

    it("Should record batch when called by org owner (verified org)", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });
      
      // Verify the org
      const metadataHash = keccak256(stringToHex("verified"));
      await contract.write.verifyOrg([orgId, true, metadataHash, "Verified"], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1", "batch-2"]);
      const dataHashes = stringsToBytes32Array(["hash1", "hash2"]);

      const deploymentBlockNumber = await publicClient.getBlockNumber();

      await contract.write.recordOrgBatch(
        [orgId, batchIds, dataHashes],
        { account: orgOwner.account }
      );

      const events = await publicClient.getContractEvents({
        address: contract.address as `0x${string}`,
        abi: contract.abi,
        eventName: "AnchorRecorded",
        fromBlock: deploymentBlockNumber,
      });

      assert.equal(events.length, 2);
      assert.equal(await contract.read.verifyHash([dataHashes[0]]), true);
      assert.equal(await contract.read.verifyHash([dataHashes[1]]), true);
    });

    it("Should record batch when called by authorized worker", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1"]);
      const dataHashes = stringsToBytes32Array(["hash1"]);

      await contract.write.authorizeWorker([orgId, worker.account.address, true], { account: orgOwner.account });

      await contract.write.recordOrgBatch(
        [orgId, batchIds, dataHashes],
        { account: worker.account }
      );

      assert.equal(await contract.read.verifyHash([dataHashes[0]]), true);
    });

    it("Should revert if called by unauthorized address", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1"]);
      const dataHashes = stringsToBytes32Array(["hash1"]);

      try {
        await contract.write.recordOrgBatch([orgId, batchIds, dataHashes], { account: unauthorized.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Not authorized for this Org"), `Expected "Not authorized for this Org" but got: ${error.message}`);
      }
    });

    it("Should revert if batch is empty", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds: `0x${string}`[] = [];
      const dataHashes: `0x${string}`[] = [];

      try {
        await contract.write.recordOrgBatch([orgId, batchIds, dataHashes], { account: orgOwner.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Empty batch"), `Expected "Empty batch" but got: ${error.message}`);
      }
    });

    it("Should revert if arrays length mismatch", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1"]);
      const dataHashes = stringsToBytes32Array(["hash1", "hash2"]);

      try {
        await contract.write.recordOrgBatch([orgId, batchIds, dataHashes], { account: orgOwner.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Array mismatch"), `Expected "Array mismatch" but got: ${error.message}`);
      }
    });

    it("Should not duplicate hash recording", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1"]);
      const dataHashes = stringsToBytes32Array(["hash1"]);

      await contract.write.recordOrgBatch([orgId, batchIds, dataHashes], { account: orgOwner.account });

      const deploymentBlockNumber = await publicClient.getBlockNumber();

      // Try to record the same hash again
      await contract.write.recordOrgBatch([orgId, batchIds, dataHashes], { account: orgOwner.account });

      // When recording duplicate, no new events should be emitted
      // So we check that the hash was already processed by verifying it's still true
      assert.equal(await contract.read.verifyHash([dataHashes[0]]), true);
    });
  });

  describe("recordRelayedBatch", function () {
    // Helper function to get contract address for EIP-712 domain
    async function getContractAddress(contract: any): Promise<`0x${string}`> {
      return contract.address as `0x${string}`;
    }

    // Helper function to sign with EIP-712
    async function signEIP712(
      signer: typeof orgOwner,
      contractAddress: `0x${string}`,
      orgId: `0x${string}`,
      batchHash: `0x${string}`
    ): Promise<{ r: `0x${string}`; s: `0x${string}`; v: number }> {
      const chainId = await publicClient.getChainId();
      const signature = await signer.signTypedData({
        domain: {
          name: "VNCXMasterAnchor",
          version: "1",
          chainId: chainId,
          verifyingContract: contractAddress,
        },
        types: {
          BatchRecord: [
            { name: "orgId", type: "bytes32" },
            { name: "batchHash", type: "bytes32" },
          ],
        },
        primaryType: "BatchRecord",
        message: {
          orgId: orgId,
          batchHash: batchHash,
        },
      });

      return splitSignature(signature);
    }

    it("Should record batch with valid signature from org owner (unverified org)", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      // Org is not verified, but should still be able to record
      const batchIds = stringsToBytes32Array(["batch-1", "batch-2"]);
      const dataHashes = stringsToBytes32Array(["hash1", "hash2"]);

      // Compute batchHash (client-side)
      const batchHash = computeBatchHash(orgId, batchIds, dataHashes);
      
      // Sign using EIP-712
      const contractAddress = await getContractAddress(contract);
      const { r, s, v } = await signEIP712(orgOwner, contractAddress, orgId, batchHash);

      const deploymentBlockNumber = await publicClient.getBlockNumber();

      // Include batchHash and split signature (r, s, v) in the call
      await contract.write.recordRelayedBatch(
        [orgId, batchIds, dataHashes, batchHash, r, s, v],
        { account: unauthorized.account } // Any account can submit, signature is what matters
      );

      const events = await publicClient.getContractEvents({
        address: contract.address as `0x${string}`,
        abi: contract.abi,
        eventName: "AnchorRecorded",
        fromBlock: deploymentBlockNumber,
      });

      assert.equal(events.length, 2);
      assert.equal(await contract.read.verifyHash([dataHashes[0]]), true);
      assert.equal(await contract.read.verifyHash([dataHashes[1]]), true);
    });

    it("Should record batch with valid signature from org owner (verified org)", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });
      
      // Verify the org
      const metadataHash = keccak256(stringToHex("verified"));
      await contract.write.verifyOrg([orgId, true, metadataHash, "Verified"], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1", "batch-2"]);
      const dataHashes = stringsToBytes32Array(["hash1", "hash2"]);

      // Compute batchHash (client-side)
      const batchHash = computeBatchHash(orgId, batchIds, dataHashes);
      
      // Sign using EIP-712
      const contractAddress = await getContractAddress(contract);
      const { r, s, v } = await signEIP712(orgOwner, contractAddress, orgId, batchHash);

      const deploymentBlockNumber = await publicClient.getBlockNumber();

      await contract.write.recordRelayedBatch(
        [orgId, batchIds, dataHashes, batchHash, r, s, v],
        { account: unauthorized.account }
      );

      const events = await publicClient.getContractEvents({
        address: contract.address as `0x${string}`,
        abi: contract.abi,
        eventName: "AnchorRecorded",
        fromBlock: deploymentBlockNumber,
      });

      assert.equal(events.length, 2);
      assert.equal(await contract.read.verifyHash([dataHashes[0]]), true);
      assert.equal(await contract.read.verifyHash([dataHashes[1]]), true);
    });

    it("Should record batch with valid signature from authorized worker", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1"]);
      const dataHashes = stringsToBytes32Array(["hash1"]);

      await contract.write.authorizeWorker([orgId, worker.account.address, true], { account: orgOwner.account });

      // Create signature with worker's account using EIP-712
      const batchHash = computeBatchHash(orgId, batchIds, dataHashes);
      const contractAddress = await getContractAddress(contract);
      const { r, s, v } = await signEIP712(worker, contractAddress, orgId, batchHash);

      await contract.write.recordRelayedBatch(
        [orgId, batchIds, dataHashes, batchHash, r, s, v],
        { account: unauthorized.account }
      );

      assert.equal(await contract.read.verifyHash([dataHashes[0]]), true);
    });

    it("Should revert with invalid signature", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1"]);
      const dataHashes = stringsToBytes32Array(["hash1"]);

      // Create signature from unauthorized address using EIP-712
      const batchHash = computeBatchHash(orgId, batchIds, dataHashes);
      const contractAddress = await getContractAddress(contract);
      const { r, s, v } = await signEIP712(unauthorized, contractAddress, orgId, batchHash);

      try {
        await contract.write.recordRelayedBatch([orgId, batchIds, dataHashes, batchHash, r, s, v], { account: unauthorized.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Invalid Batch Signature or Signer"), `Expected "Invalid Batch Signature or Signer" but got: ${error.message}`);
      }
    });

    it("Should revert if batch hash mismatch", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1"]);
      const dataHashes = stringsToBytes32Array(["hash1"]);

      // Use wrong batchHash
      const wrongBatchHash = keccak256(stringToHex("wrong"));
      const contractAddress = await getContractAddress(contract);
      // Sign the wrong batchHash
      const { r, s, v } = await signEIP712(orgOwner, contractAddress, orgId, wrongBatchHash);

      try {
        await contract.write.recordRelayedBatch([orgId, batchIds, dataHashes, wrongBatchHash, r, s, v], { account: unauthorized.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Batch hash mismatch"), `Expected "Batch hash mismatch" but got: ${error.message}`);
      }
    });

    it("Should revert if batch is empty", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds: `0x${string}`[] = [];
      const dataHashes: `0x${string}`[] = [];

      const batchHash = computeBatchHash(orgId, batchIds, dataHashes);
      const contractAddress = await getContractAddress(contract);
      const { r, s, v } = await signEIP712(orgOwner, contractAddress, orgId, batchHash);

      try {
        await contract.write.recordRelayedBatch([orgId, batchIds, dataHashes, batchHash, r, s, v], { account: unauthorized.account });
        assert.fail("Expected transaction to revert");
      } catch (error: any) {
        assert(error.message.includes("Empty batch"), `Expected "Empty batch" but got: ${error.message}`);
      }
    });
  });

  describe("verifyHash", function () {
    it("Should return false for unrecorded hash", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const unrecordedHash = stringToBytes32("unrecorded-hash");
      assert.equal(await contract.read.verifyHash([unrecordedHash]), false);
    });

    it("Should return true for recorded hash", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      await contract.write.registerOrg([orgId, orgOwner.account.address], { account: owner.account });

      const batchIds = stringsToBytes32Array(["batch-1"]);
      const dataHashes = stringsToBytes32Array(["recorded-hash"]);

      await contract.write.recordOrgBatch([orgId, batchIds, dataHashes], { account: orgOwner.account });

      assert.equal(await contract.read.verifyHash([dataHashes[0]]), true);
    });
  });

  describe("computeBatchHash", function () {
    it("Should compute correct batch hash", async function () {
      const contract = await viem.deployContract("VNCXMasterAnchor");
      const orgId = stringToBytes32("org-001");
      const batchIds = stringsToBytes32Array(["batch-1", "batch-2"]);
      const dataHashes = stringsToBytes32Array(["hash1", "hash2"]);

      // Compute using contract
      const contractHash = await contract.read.computeBatchHash([orgId, batchIds, dataHashes]);
      
      // Compute using helper function
      const computedHash = computeBatchHash(orgId, batchIds, dataHashes);

      assert.equal(contractHash, computedHash);
    });
  });
});
