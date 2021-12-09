*************************
***   ASiC-E sample   ***
*************************

The archive contains 3 directories:

* OriginalContent: it contains the original files before inclusion into the ASiC-E container

* ASiC-E Container: it contains the signed and encrypted ASiC-E container containing the files located into the OriginalContent directory.
	
	The ASiC-E container, called "containerToSend.asice", contains a BORIS XML Message and two attachments that are referenced from it.
	It's digitally signed using the private key available from the sender keystore and it's also encrypted using the public certificate from the receiver keystore.

	On the receiver side, it needs to be decrypted using the private key of the receiver.
	The validation of the digital signature is performed using the built-in public certificate of the sender.
	An additional validation step is required though: in order to validate that the public certificate built into the ASiC-E container is actually the same
	as the one coming from IKAR (or from the sender keystore in this case).

* KeyStores: it contains 2 keystores, one for the sender of the ASiC-E container and another one for the receiver.
	
	The "senderKeyStore.jks" is password-protected.  The keystore password is "senderPwd" (without double-quotes).
	It contains a single entry with the following alias "senderalias" (without double-quotes).
	Under that alias, one will find the private key of the sender along with the associated self-signed certificate.

	The "receiverKeyStore.jks" is password-protected.  The keystore password is "receiverPwd" (without double-quotes).
	It contains a single entry with the following alias "receiveralias" (without double-quotes).
	Under that alias, one will find the private key of the receiver along with the associated self-signed certificate.
