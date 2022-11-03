const ethers = require("ethers");
const { scrypt, randomBytes } = require("crypto");
const { promisify } = require("util");

const createWallet = () => {
  const wallet = ethers.Wallet.createRandom();
  const walletAddress = wallet.address;
  const mnemonic = wallet.mnemonic.phrase;
  const privateKey = wallet.privateKey;
  return { walletAddress, mnemonic, privateKey };
};

const scryptAsync = promisify(scrypt);

const toHash = async (password) => {
  const salt = randomBytes(8).toString("hex");
  const buf = await scryptAsync(password, salt, 64);

  return `${buf.toString("hex")}.${salt}`;
};

const compare = async (storedPassword, suppliedPassword) => {
  const [hashedPassword, salt] = storedPassword.split(".");
  const buf = await scryptAsync(suppliedPassword, salt, 64);

  return buf.toString("hex") === hashedPassword;
};

module.exports = { createWallet, toHash, compare };
