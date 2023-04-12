const crypto = require("crypto");
const fs = require("fs");
const readline = require("readline");
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

//Generating the RSA public and private key pair using built in JS module
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

//Writing the keys in separate files
function keysToFiles() {
  try {
    fs.writeFileSync("publicKey.txt", publicKey);
    fs.writeFileSync("privateKey.txt", privateKey);
  } catch (err) {
    console.log("The following error has been caught" + err);
  }
}

console.log(
  "On program start the private and public and private key are written to different files \n"
);
keysToFiles();
rl.question(
  "What is the name of the file you want to encrypt?\n",
  (fileName) => {
    try {
      const data = fs.readFileSync(fileName, "utf8");
      //Using the built in .publicEncrypt to encrypt the data using RSA algorithm
      // and the keys we have previously generated
      const encryptedData = crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        Buffer.from(data)
      );

      //Writing the encrypted data to file
      fs.writeFileSync("encryptedData.txt", encryptedData.toString("base64"));
      console.log("Encrypted data written to file encryptedData.txt\n");

      // Starting from the encrypted data we use .privateDecrypt to reverse
      // the encryption using the private key we generated
      const decryptedData = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        encryptedData
      );
      console.log("Decrypting the data results in \n");
      console.log(decryptedData.toString());
      rl.close();
    } catch (err) {
      console.log("The following error has been caught" + err);
      rl.close();
    }
  }
);
