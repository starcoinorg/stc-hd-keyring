const hdkey = require('@starcoin/stc-wallet/hdkey')
const SimpleKeyring = require('@starcoin/stc-simple-keyring')
const bip39 = require('bip39')
const sigUtil = require('eth-sig-util')

// Options:
const hdPathString = `m/44'/101010'/0'/0`
const type = 'HD Key Tree'

class HdKeyring extends SimpleKeyring {

  /* PUBLIC METHODS */
  constructor(opts = {}) {
    super()
    this.type = type
    this.deserialize(opts)
  }

  serialize() {
    return Promise.resolve({
      mnemonic: this.mnemonic,
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath,
    })
  }

  deserialize(opts = {}) {
    this.opts = opts || {}
    this.wallets = []
    this.mnemonic = null
    this.root = null
    this.hdPath = opts.hdPath || hdPathString

    if (opts.mnemonic) {
      this._initFromMnemonic(opts.mnemonic)
    }

    if (opts.numberOfAccounts) {
      return this.addAccounts(opts.numberOfAccounts)
    }

    return Promise.resolve([])
  }

  addAccounts(numberOfAccounts = 1) {
    if (!this.root) {
      this._initFromMnemonic(bip39.generateMnemonic())
    }

    const oldLen = this.wallets.length
    const newWallets = []
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = this.root.deriveChild(i)
      const wallet = child.getWallet()
      newWallets.push(wallet)
      this.wallets.push(wallet)
    }
    const hexWallets = newWallets.map((w) => {
      return w.getAddress()
        .then((address) => {
          return sigUtil.normalize(address.toString('hex'))
        })
    })
    return Promise.all(hexWallets)
  }

  getAccounts() {
    return Promise.all(this.wallets.map((w) => {
      return w.getAddress()
        .then((address) => {
          return sigUtil.normalize(address.toString('hex'))
        })
    }))
  }

  exportAccount(address) {
    const wallet = this._getWalletForAccount(address)
    return Promise.resolve(wallet.getPrivateKey().toString('hex'))
  }

  /* PRIVATE METHODS */
  _initFromMnemonic(mnemonic) {
    this.mnemonic = mnemonic
    const seed = bip39.mnemonicToSeed(mnemonic)
    this.hdWallet = hdkey.fromMasterSeed(seed)
    this.root = this.hdWallet.derivePath(this.hdPath)
  }

  _getWalletForAccount(account) {
    const targetAddress = sigUtil.normalize(account)
    return this.wallets.find((w) => {
      return w.getAddress()
        .then((address) => {
          return sigUtil.normalize(address.toString('hex'))
        }).then((address) => {
          return ((address === targetAddress) || (sigUtil.normalize(address) === targetAddress))
        })
    })
  }
}

HdKeyring.type = type
module.exports = HdKeyring
