# Crypto-Eck
cryptographic stuff

This is as a collection of cryptographic stuff, which is yet not included into a library or an application. 

Password Hashing:

The package password hashing is still a bit raw. 
It may perhaps be used in future to compare some password hashing schemes. 
Bcrypt and Battcrypt require Bouncy Castles lightweight Crypto API. 

Pomelo is a Password Hashing Scheme designed by Hongjun Wu. It was submitted to the Password Hashing Competition
and became one of the nine finalists. 
There is also key derivation function described in paper v3.

Battcrypt was designed by Steven Thomas and is also a finalist of the Password Hshing Comptition. 
This implementation does not contain the key derivation mode. It will be updated later. 

Catena is a Password-Scrambling Framework designed by Christian Forler, Stefan Lucks and Jakob Wenzel. The Password Hashing Competition gave special recognition to Catena and three other schemes. 
There are two instances: Catena-Dragonfly and Catena-Butterfly. Both can be used with the round-reduced version H' of Blake2b and also as FULL version. 

The latest Realease 1.52 of Bouncy Castle now contains a slightly modified version of this implementation of Bcrypt. 
It is only available here for comparison reasons. 

Digests:

Blake2b  is a cryptographic hash function, designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein. 

You can simply use it in this way:

      Blake2b b = new Blake2b(); // no key, no salt, no personalization
      b.update( anyByteArray1 );
      b.update( anyByteArray2 );
      byte[] hash = new byte[64];// full length of hash value
      b.doFinal(hash, 0); // result now holds the hash value (64 byte)

You can also set a 16 byte salt value and a 16 byte personalization string. 
The Tree Hashing Mode is not implemented. There is also a Java implementation of Joubin Mohammad Houshyar which includs the Tree Hashing Mode and a JCE-Provider. You can find it at:
https://github.com/alphazero/Blake2b

Author: Axel von dem Bruch

Contact: info@eck.cologne
