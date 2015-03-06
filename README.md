# eck.cologne.crypto
cryptographic stuff

This is as a collection of cryptographic stuff, which is yet not included into a library or an application like Peafactory. 


Blake2b  is a cryptographic hash function, designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein. 

You can simply use it in this way:

      Blake2b b = new Blake2b(); // no key, no salt, no personalization
      b.update( anyByteArray1 );
      b.update( anyByteArray2 );
      byte[] hash = new byte[64];// full length of hash value
      b.doFinal(hash, 0); // result now holds the hash value (64 byte)

You can also set a 16 byte salt value and a 16 byte personalization string. 
The Tree Hashing Mode is not implemented. 

Author: Axel von dem Bruch

Contact: info@eck.cologne
