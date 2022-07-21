async function main() {
    const [deployer] = await ethers.getSigners();
  
    console.log("Deploying contracts with the account:", deployer.address);
  
    console.log("Account balance:", (await deployer.getBalance()).toString());
  
    const Token = await ethers.getContractFactory("Token");
    const token = await Token.deploy();

    const Forwarder = await ethers.getContractFactory("Forwarder");
    const forwarder = await Forwarder.deploy("Forwarder", "1");
  
    console.log("Token address:", token.address);
    console.log("Forwarder address:", forwarder.address);
  }
  
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
  