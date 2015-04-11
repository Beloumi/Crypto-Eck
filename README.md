# Crypto-Eck
cryptographic stuff

This is as a collection of cryptographic stuff, which is yet not included into a library or an application like Peafactory. 


Pomelo is a Password Hashing Scheme designed by Hongjun Wu. It was submitted to the Password Hashing Competition
and became one of the nine finalists. 
This is version v1, there is a newer version v2, which will be published here soon.


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
