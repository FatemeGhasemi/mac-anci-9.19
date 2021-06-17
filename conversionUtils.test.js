const {
  convertHexToBytArray, subArray,
  decryptDesCBC, encryptDesCbc, addZeroPaddingToStr,
  convertStringToByteBlocksWithEightLength,
  generateMac
} = require('./conversionUtils')
const {assert} = require('chai')
const macKey = 'F5F2F4F8F6B6A3FDADCDDDABBDFABDBA'
const leftPartOfKey = 'F5F2F4F8F6B6A3FD'
const rightPartOfKey = 'ADCDDDABBDFABDBA'

describe('test convertHexToBytArray()', () => {
  it('should return correct byteArray', function () {
    const byteArray = convertHexToBytArray(macKey);
    assert.equal(byteArray.length, 16)
  });
  it('should return correct byteArray for first half of mac key', function () {
    const byteArray = convertHexToBytArray(leftPartOfKey);
    assert.equal(byteArray.length, 8)
  });
  it('should return correct byteArray for second half of mac key', function () {
    const byteArray = convertHexToBytArray(rightPartOfKey);
    assert.equal(byteArray.length, 8)
  });
})
describe('test subArray()', () => {
  it('should return first half of array', function () {
    const array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    const subArr = subArray(array, 0, 8)
    assert.equal(subArr.length, 8)
    assert.equal(subArr[7], 7)
  });
  it('should return second half of array', function () {
    const array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    const subArr = subArray(array, 8, 16)
    assert.equal(subArr.length, 8)
    assert.equal(subArr[7], 15)
  });
})

describe('test encryptDesCbc()', () => {
  it('should test decrypt and encrypt', function () {
    const plainText = '12345678';
    const key = Buffer.from(leftPartOfKey, 'hex')
    const iv = Buffer.alloc(8)
    const encrypted = encryptDesCbc(Buffer.from(plainText), key, iv)
    const decrypted = decryptDesCBC(encrypted, key, iv);
    assert.equal(decrypted.toString('utf-8'), plainText)

  });

  it('should fail for non eight byte plainText', function () {
    const plainText = '123456789';
    const key = Buffer.from(leftPartOfKey, 'hex')
    const iv = Buffer.alloc(8)
    const badFunc = () => {
      encryptDesCbc(Buffer.from(plainText), key, iv)
    }
    assert.throw(badFunc, 'error:0607F08A:digital envelope routines:EVP_EncryptFinal_ex:data not multiple of block length')
  });

  it('should fail for non eight iv length', function () {
    const plainText = '12345678';
    const key = Buffer.from(leftPartOfKey, 'hex')
    const iv = Buffer.alloc(7)
    const badFunc = () => {
      encryptDesCbc(Buffer.from(plainText), key, iv)
    }
    assert.throw(badFunc, 'Invalid IV length')
  });
})

describe('test addZeroPaddingToStr()', () => {
  it('should add padding', () => {
    // str with length 14
    const str = '12345678912345'
    const paddedStr = addZeroPaddingToStr(str)
    assert.notEqual(paddedStr.length, str.length)
    assert.equal(paddedStr.length, 16)
  });
  it('should not add padding', () => {
    // str with length 16
    const str = '1234567891234567'
    const paddedStr = addZeroPaddingToStr(str)
    assert.equal(paddedStr.length, str.length)
  });
})

describe('convertStringToByteBlocksWithEightLength()', () => {
  it('should return blockArray with length 2', function () {
    const str = '123456789';
    const blockArray = convertStringToByteBlocksWithEightLength(str);
    assert.equal(blockArray.length, 2);
    assert.equal(blockArray[0].length, 8)
    assert.equal(blockArray[1].length, 8)

  });
  it('should return blockArray with length 1', function () {
    const str = '12345678';
    const blockArray = convertStringToByteBlocksWithEightLength(str);
    assert.equal(blockArray.length, 1);
    assert.equal(blockArray[0].length, 8)
  });
})

describe('generateMac() test cases',  () => {
  it('should generate valid mac', function () {
    const str = '274982704923u9023842039842039'
    const generatedMac = generateMac(str, macKey);
    assert.equal(generatedMac, 'wrongExpectedMacKey')
  });

});