const crypto = require('crypto')
const convertHexToBytArray = (hex)=>{
  const bytes = []
  for (let c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
  return bytes;
}

const subArray = (array, start, end)=>{
  const result =[];
  for (start ; start <end; start ++){
    result.push(array[start])
  }
  return result;
}
const addZeroPaddingToStr = (str)=>{
  if (str.length % 8 === 0){
    return str;
  }
  const zeroPaddingArray = Buffer.alloc( 8 - (str.length % 8));
  const buffer =  Buffer.from(str);
  const result = Buffer.concat([buffer, zeroPaddingArray])
  return result.toString('utf-8')
}

const encryptDesCbc = (TextBuffer, secretKey, iv) => {
  const cipher = crypto.createCipheriv('des', secretKey, iv);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(TextBuffer), cipher.final()]);
};

const decryptDesCBC = (TextBuffer, secretKey, iv) => {
  // const iv = Buffer.alloc(8);
  const cipher = crypto.createDecipheriv('des-cbc', secretKey, iv);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(TextBuffer), cipher.final()]);
};

const convertStringToByteBlocksWithEightLength = (str)=>{
  const newStr = addZeroPaddingToStr(str);
  const blockArray = [];
  for (let i = 0; i<newStr.length; i+=8){
    blockArray.push(Buffer.from(newStr.substr(i, 8)))
  }
  return blockArray;
}

const generateMac = (str, macKey)=>{
  // const  macKeyBytes = convertHexToBytArray(macKey);
  const  leftPartOfKey = macKey.substr(0,16)
  const  rightPartOfKey =macKey.substr(16,32)
  const blockArray = convertStringToByteBlocksWithEightLength(str);
  let iv = Buffer.alloc(8);
  for (let i =0; i<blockArray.length-1; i++){
    iv= encryptDesCbc(blockArray[i], Buffer.from(leftPartOfKey, 'hex'), iv)
  }
  const decryptedLastIv = decryptDesCBC(iv, Buffer.from(rightPartOfKey, 'hex'), Buffer.alloc(8));
  const result = encryptDesCbc(decryptedLastIv, Buffer.from(leftPartOfKey, 'hex'), Buffer.alloc(8));
  return result.toString('hex')
}


module.exports = {
  convertHexToBytArray,
  subArray,
  encryptDesCbc,
  decryptDesCBC,
  addZeroPaddingToStr,
  convertStringToByteBlocksWithEightLength,
  generateMac
}