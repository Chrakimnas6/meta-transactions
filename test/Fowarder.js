const { expect } = require("chai");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

const ethSigUtil = require("@metamask/eth-sig-util");
const Wallet = require("ethereumjs-wallet");
const { EIP712Domain, domainSeparator } = require("../scripts/helper");

const { expectRevert, constants } = require('@openzeppelin/test-helpers');

const chain = "hardhat";
const name = "AwlForwarder"; 
const version = "1.0";

const provider = ethers.getDefaultProvider();

describe("Forwarder contract", function () {
    async function deployForwarderFixture() {
      const Forwarder = await ethers.getContractFactory("Forwarder");
      const [owner, addr1, addr2] = await ethers.getSigners();
      
      const forwarder = await Forwarder.deploy(name, version);
  
      await forwarder.deployed();

      domain = {
        name,
        version,
        chainId: 31337,
        verifyingContract: forwarder.address,
      };

      types = {
        EIP712Domain,
        ForwardRequest: [{
            name: 'from',
            type: 'address'
          },
          {
            name: 'to',
            type: 'address'
          },
          {
            name: 'value',
            type: 'uint256'
          },
          {
            name: 'gas',
            type: 'uint256'
          },
          {
            name: 'nonce',
            type: 'uint256'
          },
          {
            name: 'data',
            type: 'bytes'
          },
        ],
      };
  
      return { Forwarder, forwarder, domain, types, owner, addr1, addr2 };
    }

    describe("Whitelist", function () {
        describe("addSenderToWhitelist", function () {
            it("Success", async function() {
                const {forwarder, addr1} = await loadFixture(deployForwarderFixture);
                expect(await forwarder.addSenderToWhitelist(addr1.address));
            });

            it("Already whitelisted", async function () {
                const {forwarder, owner} = await loadFixture(deployForwarderFixture);
                await expect(
                    forwarder.addSenderToWhitelist(owner.address)
                ).to.be.revertedWith("AwlForwarder: sender address is already whitelisted");
            });

            it("Prevents non-owners from executing", async function () {
                const {forwarder, addr1, addr2} = await loadFixture(deployForwarderFixture);
                await expect(
                    forwarder.connect(addr1).addSenderToWhitelist(addr2.address)
                ).to.be.revertedWith("Ownable: caller is not the owner");
            });
        });

        describe("removeSenderFromWhitelist", function () {
            it("Success", async function() {
                const {forwarder, owner} = await loadFixture(deployForwarderFixture);
                expect(await forwarder.removeSenderFromWhitelist(owner.address));
            });

            it("Prevents non-owners from executing", async function () {
                const {forwarder, owner, addr1} = await loadFixture(deployForwarderFixture);
                await expect(
                    forwarder.connect(addr1).removeSenderFromWhitelist(owner.address)
                ).to.be.revertedWith("Ownable: caller is not the owner");
            });
        });

        describe("isWhitelisted", function () {
            it("True", async function() {
                const {forwarder, owner} = await loadFixture(deployForwarderFixture);
                expect(await forwarder.isWhitelisted(owner.address));
            });

            it("False", async function () {
                const {forwarder, addr1} = await loadFixture(deployForwarderFixture);
                expect(await forwarder.isWhitelisted(addr1.address)).to.be.false;
            });
        });
    });

    describe("With message", function() {
        async function deployMessageFixture() {
            const {forwarder, domain, types} = await loadFixture(deployForwarderFixture);
            const wallet = Wallet["default"].generate();
            sender = ethers.utils.getAddress(wallet.getAddressString());
            req = {
                from: sender,
                to: constants.ZERO_ADDRESS,
                value: "0",
                gas: "1000000",
                nonce: Number(await forwarder.getNonce(sender)),
                data: "0x",
            }
            sign = ethSigUtil.signTypedData({
                privateKey: wallet.getPrivateKey(),
                data: {
                    types: types,
                    domain: domain,
                    primaryType: "ForwardRequest",
                    message: req,
                },
                version: ethSigUtil.SignTypedDataVersion.V4,
            });
            return {forwarder, sender, req, sign};
        };

        describe("Verify", function() {
            describe("Valid signature", function() {
                it("Success", async function() {
                    const {forwarder, req, sign} = await deployMessageFixture();
                    expect(await forwarder.verify(req, sign)).to.be.equal(true);
                    expect(await forwarder.getNonce(req.from)).to.be.equal(ethers.BigNumber.from(req.nonce));
                });
            });

            describe("Invalid signature", function() {
                it("Tampered from", async function() {
                    const {forwarder, owner} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    expect(await forwarder.verify({
                        ...req,
                        from: owner.address
                    }, sign))
                    .to.be.equal(false);
                });

                it("Tampered to", async function() {
                    const {forwarder, owner} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    expect(await forwarder.verify({
                        ...req,
                        to: owner.address
                    }, sign))
                    .to.be.equal(false);
                });

                it("Tampered value", async function() {
                    const {forwarder} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    expect(await forwarder.verify({
                        ...req,
                        value: ethers.utils.parseEther("1")
                    }, sign))
                    .to.be.equal(false);
                });

                it("Tampered nonce", async function() {
                    const {forwarder} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    expect(await forwarder.verify({
                        ...req,
                        nonce: req.nonce + 1
                    }, sign))
                    .to.be.equal(false);
                });

                it("Tampered data", async function() {
                    const {forwarder} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    expect(await forwarder.verify({
                        ...req,
                        data: "0x1742"
                    }, sign))
                    .to.be.equal(false);
                });

                it("Tampered signature", async function() {
                    const {forwarder} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    const tamperedSign = ethers.utils.arrayify(sign);
                    tamperedSign[42] ^= 0xff;
                    expect(await forwarder.verify(req, ethers.utils.hexlify(tamperedSign)))
                    .to.be.equal(false);
                });

            });
        });

        describe("Execute", function() {
            describe("Valid signature", function() {
                it("Success", async function() {
                    const {forwarder, req, sign} = await deployMessageFixture();
                    expect(await forwarder.execute(req, sign));
                    // after the execution, the nonce should be incremented
                    expect(await forwarder.getNonce(req.from)).to.be.equal(ethers.BigNumber.from(req.nonce + 1));
                });
            });

            describe("Invalid msg.sender", function() {
                it("msg.sender not whitelisted", async function() {
                    const {forwarder, addr1} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await loadFixture(deployMessageFixture);
                    await expect(
                        forwarder.connect(addr1).execute(req, sign)
                    ).to.be.revertedWith("AwlForwarder: sender of meta-transaction is not whitelisted");
                });
            });

            describe("Invalid Signature", function() {
                it("Tampered from", async function() {
                    const {forwarder, owner} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    await expect(forwarder.execute({
                        ...req,
                        from: owner.address
                    }, sign))
                    .to.be.revertedWith("AwlForwarder: signature does not match request");
                });

                it("Tampered to", async function() {
                    const {forwarder, owner} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    await expect(forwarder.execute({
                        ...req,
                        to: owner.address
                    }, sign))
                    .to.be.revertedWith("AwlForwarder: signature does not match request");
                });

                it("Tampered value", async function() {
                    const {forwarder} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    await expect (forwarder.execute({
                        ...req,
                        value: ethers.utils.parseEther("1")
                    }, sign))
                    .to.be.revertedWith("AwlForwarder: signature does not match request");
                });

                it("Tampered nonce", async function() {
                    const {forwarder} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    await expect(forwarder.execute({
                        ...req,
                        nonce: req.nonce + 1
                    }, sign))
                    .to.be.revertedWith("AwlForwarder: signature does not match request");
                });

                it("Tampered data", async function() {
                    const {forwarder} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    await expect(forwarder.execute({
                        ...req,
                        data: "0x1742"
                    }, sign))
                    .to.be.revertedWith("AwlForwarder: signature does not match request");
                });

                it("Tampered signature", async function() {
                    const {forwarder} = await loadFixture(deployForwarderFixture);
                    const {req, sign} = await deployMessageFixture();
                    const tamperedSign = ethers.utils.arrayify(sign);
                    tamperedSign[42] ^= 0xff;
                    await expect(forwarder.execute(req, ethers.utils.hexlify(tamperedSign)))
                    .revertedWith("AwlForwarder: signature does not match request");
                });
            });

            describe("Value > ETH balance", function () {
                it("Failure", async function() {
                    const {forwarder, domain, types} = await loadFixture(deployForwarderFixture);
                    const wallet = Wallet["default"].generate();
                    sender = ethers.utils.getAddress(wallet.getAddressString());
                    req = {
                        from: sender,
                        to: constants.ZERO_ADDRESS,
                        value: Number(await provider.getBalance(sender) + 1),
                        gas: "1000000",
                        nonce: Number(await forwarder.getNonce(sender)),
                        data: "0x",
                    }
                    sign = ethSigUtil.signTypedData({
                        privateKey: wallet.getPrivateKey(),
                        data: {
                            types: types,
                            domain: domain,
                            primaryType: "ForwardRequest",
                            message: req,
                        },
                        version: ethSigUtil.SignTypedDataVersion.V4,
                    });
                    await expect(forwarder.execute(req, sign)).to.be.reverted;
                });
            });
        });
    });

    describe("DOMAIN_SEPARATOR", function () {
        it("Success", async function() {
            const {forwarder} = await loadFixture(deployForwarderFixture);
            expect(await forwarder.DOMAIN_SEPARATOR()).to.be.equal(
                await domainSeparator(name, version, 31337, forwarder.address));
        });
    });

});
