const { expect } = require("chai");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

const ethSigUtil = require("@metamask/eth-sig-util");
const Wallet = require("ethereumjs-wallet");
const { EIP712Domain, domainSeparator } = require("../scripts/helper");

const { expectRevert, constants } = require('@openzeppelin/test-helpers');

const chain = "hardhat";
const name = "AwlForwarder";
const version = "1.0";

describe("Forwarder contract", function () {
    async function deployTokenFixture() {
      const Forwarder = await ethers.getContractFactory("Forwarder");
      const [owner, addr1, addr2] = await ethers.getSigners();
      
      const forwarder = await Forwarder.deploy(name, version);
  
      await forwarder.deployed();
  
      return { Forwarder, forwarder, owner, addr1, addr2 };
    }

    describe("Whitelist", function () {
        describe("addSenderToWhitelist", function () {
            it("success", async function() {
                const {forwarder, addr1} = await loadFixture(deployTokenFixture);
                expect(await forwarder.addSenderToWhitelist(addr1.address));
            });

            it("already whitelisted", async function () {
                const {forwarder, owner} = await loadFixture(deployTokenFixture);
                await expect(
                    forwarder.addSenderToWhitelist(owner.address)
                ).to.be.revertedWith("AwlForwarder: sender address is already whitelisted");
            });

            it("Prevents non-owners from executing", async function () {
                const {forwarder, addr1, addr2} = await loadFixture(deployTokenFixture);
                await expect(
                    forwarder.connect(addr1).addSenderToWhitelist(addr2.address)
                ).to.be.revertedWith("Ownable: caller is not the owner");
            });
        });
    });
});
