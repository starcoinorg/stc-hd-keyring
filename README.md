# HD Keyring

A simple JS class wrapped around [@starcoin/stc-wallet](https://github.com/starcoinorg/stc-wallet) designed to expose an interface common to many different signing strategies, to be used in a `KeyringController`, like is being used in [StarMask](https://starcoin.org/)

## The Keyring Class Protocol

One of the goals of this class is to allow developers to easily add new signing strategies to StarMask. We call these signing strategies Keyrings, because they can manage multiple keys.

### Keyring.type

A class property that returns a unique string describing the Keyring.
This is the only class property or method, the remaining methods are instance methods.

### constructor( options )

As a Javascript class, your Keyring object will be used to instantiate new Keyring instances using the new keyword.  For example:

```
const keyring = new YourKeyringClass(options);
```

The constructor currently receives an options object that will be defined by your keyring-building UI, once the user has gone through the steps required for you to fully instantiate a new keyring.  For example, choosing a pattern for a vanity account, or entering a seed phrase.

We haven't defined the protocol for this account-generating UI yet, so for now please ensure your Keyring behaves nicely when not passed any options object.

## Keyring Instance Methods

All below instance methods must return Promises to allow asynchronous resolution.

### serialize()

In this method, you must return any JSON-serializable JavaScript object that you like. It will be encoded to a string, encrypted with the user's password, and stored to disk. This is the same object you will receive in the deserialize() method, so it should capture all the information you need to restore the Keyring's state.

### deserialize( object )

As discussed above, the deserialize() method will be passed the JavaScript object that you returned when the serialize() method was called.

### addAccounts( n = 1 )

The addAccounts(n) method is used to inform your keyring that the user wishes to create a new account. You should perform whatever internal steps are needed so that a call to serialize() will persist the new account, and then return an array of the new account addresses.

The method may be called with or without an argument, specifying the number of accounts to create. You should generally default to 1 per call.

### getAccounts()

When this method is called, you must return an array of hex-string addresses for the accounts that your Keyring is able to sign for.

### getReceiptIdentifiers()

When this method is called, you must return an array of { address, receiptIdentifiers } for the accounts.


### getReceiptIdentifier(address)

Return the receiptIdentifier of the specified account.

### exportAccount(address)

Exports the specified account as a private key hex string.

