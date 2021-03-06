package cologne.eck.dr.op.crypto.password_hashing;


/**
 * version v3.3
 */

/*
 * Password Hashing Scheme Catena (v3.3)
 * Copyright (C) 2016  Axel von dem Bruch
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * See:  https://www.gnu.org/licenses/lgpl-2.1.html
 * You should have received a copy of the GNU General Public License 
 * along with this library.
 */


import java.util.Arrays;

import cologne.eck.dr.op.crypto.digest.*;


public abstract class Catena implements PasswordHashingScheme {

	
	protected Digest digest;// = new Blake2b();
	protected FastHash fastHash;// = new Blake2b_1();
	
	protected boolean fast = true; // use fastHash (here: round-reduced version) or not	

	// Values independent on instance:
	protected int hLen = 0;
	private final static int KEY_LEN = 16;

	protected String versionID; // V / version identifier
	// possible values: "Dragonfly", Dragonfly-Full", Butterfly", Butterfly-Full"
	
	// mode (d / domain) values: 
	private static final int PASSWORD_HASHING_MODE = 0;// "PASSWORD_SCRAMBLER"
	private static final int KEY_DERIVATION_MODE = 1;
//	private static final int PROOF_OF_WORK_MODE = 2;

	// Server Relief values: 
	public final static int REGULAR = 0;
	private final static int CLIENT = 1;
	
	// true = clear the password as soon as possible
	protected boolean overwrite = false;
	
	
	
	/**
	 * Use Catena with default cost parameters
	 * 
	 * @param pwd	the password
	 * @param salt	the salt
	 * @param data	the associated data or null
	 * @param hash	holds the resulting hash value
	 * 	 			the length of this vector indicates 
	 * 				the length of the resulting hash value
	 */
	public void hashPassword(
			byte[] pwd, byte[] salt, byte[] data, 
			byte[] hash) {
		
		catena(pwd, salt, data, 
		getDefaultLambda(), getDefaultMinGarlic(), getDefaultGarlic(), 
		REGULAR, PASSWORD_HASHING_MODE, hash);
	}
	
	/**
	 * Catena password hashing with cost parameters
	 * 
	 * @param pwd			the password
	 * @param salt			the salt
	 * @param data			the associated data or null
	 * @param lambda		the depth of the graph
	 * @param min_garlic	the min. Garlic
	 * @param garlic		the cost parameter
	 * @param hash			holds the resulting hash value, 
	 * 						the length of this vector indicates 
	 * 						the length of the resulting hash value
	 */
	public void hashPassword(
			byte[] pwd, byte[] salt, byte[] data,  
		     int lambda, int min_garlic, int garlic, 	    
		     byte[] hash) {
		
		catena(pwd, salt, data, 
				lambda, garlic, garlic, 
				REGULAR, PASSWORD_HASHING_MODE, hash);
	}
	
	/**
	 * Catena with arguments from reference implementation 
	 * 
	 * @param pwd			the password
	 * @param salt			the salt
	 * @param data			the associated data or null
	 * @param lambda		the depth of the graph
	 * @param min_garlic	the min. Garlic
	 * @param garlic		the cost parameter
	 * @param _client		indicates if Catena uses server relief or not
	 * @param tweak_id		the mode to run: PASSWORD_HASHING_MODE 
	 * 						or KEY_DERIVATION_MODE 
	 * @param hash			holds the resulting hash value, 
	 * 						the length of this vector indicates 
	 * 						the length of the resulting hash value
	 */
	public void catena(
			 byte[] pwd, byte[] salt, byte[] data,  
		     int lambda, int  min_garlic, int garlic, 
		     int _client, int  tweak_id, 
		     byte[] hash) {
		_catena(
				 pwd, salt, salt, data,  
			     lambda, min_garlic, garlic, 
			     _client, tweak_id, 
			     hash);
	}
	
	/**
	 * Catena with arguments from reference implementation and a public input 
	 * 
	 * @param pwd			the password
	 * @param salt			the salt: if publicInput is used, this value 
	 * 						is only used for the initial hash
	 * @param publicInput	the public input for the randomization layer 
	 * 						(if the salt is kept secret) to avoid cache-timing attacks
	 * @param data			the associated data or null
	 * @param lambda		the depth of the graph
	 * @param min_garlic	the min. Garlic
	 * @param garlic		the cost parameter
	 * @param hashlen		the length of the resulting hash value
	 * @param _client		indicates if Catena uses server relief or not
	 * @param tweak_id		the mode to run: PASSWORD_HASHING_MODE 
	 * 						or KEY_DERIVATION_MODE 
	 * @param hash			holds the resulting hash value, 
	 * 						the length of this vector indicates 
	 * 						the length of the resulting hash value
	 */
	public void _catena(
			 byte[] pwd, byte[] salt, byte[] publicInput, byte[] data,  
		     int lambda, int  min_garlic, int garlic,
		     int _client, int  tweak_id, 
		     byte[] hash) {
		
		hLen = digest.getOutputSize();
		
		int hashlen = hash.length;
		
		if((hashlen > hLen) || (garlic > 63) || (min_garlic > garlic) || 
				(lambda == 0)){
			throw new IllegalArgumentException("illegal argument for __Catena");
		}
		
		if (publicInput == null && salt != null) {
			publicInput = salt;
		}

		byte[] x = new byte[hLen];
		byte[] hv = new byte[hLen];
		byte[] t = new byte[4];
		int c;

		// Compute H(V)
		digest.update(versionID.getBytes() );// Encoding?
		digest.doFinal(hv, 0);
		digest.reset();

		// Compute Tweak 
		t[0] = (byte)tweak_id;
		t[1] = (byte)lambda;
		t[2] = (byte)hashlen;
		int saltlen = 0;
		if (salt != null){
			saltlen = salt.length;
		}
		t[3] = (byte)saltlen;

		// Compute H(AD) 
		digest.update(data);
		digest.doFinal(x, 0);
		digest.reset();

		// Compute the initial value to hash  
		digest.update(hv);
		digest.update(t);
		digest.update(x);
		digest.update(pwd);
		digest.update(salt);
		digest.doFinal(x, 0);
		digest.reset();

		// Overwrite Password if enabled
		if (overwrite == true) {
			erasePwd(pwd);
		}

		// provide resistance against weak garbage collector attacks:
		flap(x, lambda, (min_garlic+1)/2, publicInput, x);

		for(c=min_garlic; c <= garlic; c++) {
			flap(x, lambda, c, publicInput,  x);
		  	
		    if( (c==garlic) && (CLIENT == _client)) {
		    	System.arraycopy(x, 0, hash, 0, hashlen);
		    	return;
		    }
		    digest.update( (byte) c);
		    digest.update(x);
		    digest.doFinal(x, 0);	  
		    digest.reset();
		}
		System.arraycopy(x, 0, hash, 0, hashlen);
	}

	// Server Relief
	/**
	 * Call this function on client side to use the server relief. 
	 * 
	 * @param pwd			password
	 * @param salt			salt 
	 * @param data			associated data
	 * @param lambda		depth of graph
	 * @param min_garlic	min. Garlic
	 * @param garlic		cost parameter
	 * @param hashlen		length of hash value
	 * @param triplesIndex				value to store the result
	 */
	public void catenaClient(
			byte[] pwd, byte[] salt, byte[] data, 
			int lambda, int min_garlic, int garlic, 
			int hashlen, byte[] x) {
		catena(pwd, salt, data, 
				lambda, min_garlic, garlic, 
				CLIENT, PASSWORD_HASHING_MODE, x);
	}
	
	// increase garlic but not minGarlic!!
	/**
	 * Call this function on server side 
	 * for the result value of the function 
	 * catenaClient to use the server relief
	 * 
	 * @param garlic	the cost parameter
	 * @param triplesIndex			the resulting hash value 
	 * 					of the function catenaClient
	 * @param hashlen	the length of the hash value
	 * @param hash		the resulting hash valueresulting 
	 */
	public void catenaServer(
			int garlic, byte[] x,
			int hashlen, byte[] hash) {
		byte[] z = new byte[hLen];
  
		if (hashlen > hLen){
			throw new IllegalArgumentException("illegal length of output");
		}
		digest.update((byte) garlic);
		digest.update(x, 0, hLen);
		digest.doFinal(z, 0);
		digest.reset();
		System.arraycopy(z,  0,  hash,  0,  hashlen);
		Arrays.fill(z,  (byte) 0);
	}

	/**
	 * Client-independent update: Increase the cost
	 * parameter without knowledge of the password 
	 * 
	 * @param old_hash		the previous hash value
	 * @param lambda		the depth of the graph
	 * @param salt			the salt value
	 * @param old_garlic	the previous used cost parameter
	 * @param new_garlic	the new cost parameter
	 * @param hashlen		the length of the hash value
	 * @param new_hash		the resulting hash value
	 */
	public void ciUpdate(
			byte[] old_hash,  int lambda,
			byte[] salt,  
			int old_garlic, int new_garlic,
			int hashlen, byte[] new_hash) {
		int c;
		hLen = digest.getOutputSize();
		byte[] x = new byte[hLen];

		System.arraycopy(old_hash, 0, x, 0, hashlen);

		for(c=old_garlic+1; c <= new_garlic; c++) {
		     flap(x, lambda, c, salt, x);
		     digest.update((byte) c);
		     digest.update(x);
		     digest.doFinal(x,  0);
		     digest.reset();

		     for(int i= hashlen; i < hLen; i++) {
		    	 x[i] = (byte) 0;
		     }
		}
		System.arraycopy(x, 0, new_hash, 0, hashlen); 
	}

	/**
	 * Use Catena as key derivation function to
	 * derive a cryptographic key with arbitrary length. 
	 * 
	 * @param pwd			the password
	 * @param salt			the salt: if publicInput is used, this value 
	 * 						is only used for the initial hash
	 * @param publicInput	the public input for the randomization layer 
	 * 						(if the salt is kept secret) to avoid cache-timing attacks.
	 * 						If value is null, the salt value is used instead
	 * @param data			the associated data 
	 * @param lambda		the depth of the graph
	 * @param min_garlic	min. cost parameter
	 * @param garlic		the cost parameter
	 * @param key_id		the key identifier
	 * @param key			the result key, the length 
	 * 						of the vector indicates the 
	 * 						length of the result key
	 */
	public void deriveKey(
			byte[] pwd, byte[] salt, byte[] publicInput, byte[] data,  
	       int lambda, int  min_garlic, int garlic, 
	       int key_id, byte[] key) {
		
		int keylen = key.length;
		hLen = digest.getOutputSize();
		byte[] hash = new byte[hLen];
		int len = keylen / hLen;
		int rest = keylen % hLen;
		long i;

		// default is FULL
		if(fastHash == null) {
			fast = false;
			//fastHash = digest;
		}  else {
			fast = true;
		}
		_catena(pwd, salt, publicInput, data, 
				lambda, min_garlic, garlic, 
				REGULAR, KEY_DERIVATION_MODE,
				hash);

		for(i=0; i < len; i++) {

			long tmp = i;
		    digest.update( (byte) 0);
		    digest.update(long2bytesLE(tmp));
		    digest.update( (byte) key_id);
		    digest.update(int2bytesLE(keylen));
		    digest.update(hash);
		    digest.doFinal(key, (int) i * hLen);
		    digest.reset();
		}

		if(rest > 0) {
			
			long tmp = i;// TO_LITTLE_ENDIAN_64(i);
			digest.update( (byte) 0);
			digest.update(long2bytesLE(tmp));
			digest.update( (byte) key_id);
			digest.update(int2bytesLE(keylen));
			digest.update(hash);
			digest.doFinal(hash, 0);
			digest.reset();
			System.arraycopy(hash,  0,  key,  len * hLen,  rest);
		}
	}

	public void catenaKeyedHashing(
			byte[] pwd, byte[] salt, byte[] data,
			int lambda, int  min_garlic, int garlic, 
			int  hashlen, byte[] key, 
			long uuid, byte[] chash) {
		
		hLen = digest.getOutputSize();
		byte[] keystream = new byte[hLen];
		long tmp = uuid;
		
		catena(pwd, salt, data, 
				lambda, min_garlic, garlic, 
				REGULAR, PASSWORD_HASHING_MODE, chash);
 
		digest.update(key, 0, KEY_LEN);
		digest.update(long2bytesLE(tmp));
		digest.update((byte) garlic);
		digest.update(key, 0, KEY_LEN);
		digest.doFinal(keystream,  0);

		for(int i=0; i<hashlen; i++){
			chash[i] ^= keystream[i];
		}
	}

	//====== ABSTRACT METHODS ======	
	
	/** The function f lap consists of three phases: 
	 * (1) an initialization phase, where the memory of size 2g · n bits 
	 * is written in a sequential order, 
	 * (2) the function Γ depending on the public input γ, and 
	 * (3) a call to a memory-hard function F 
	 *
	 * 
	 * @param triplesIndex			64 byte vector
	 * @param lambda	depth of graph
	 * @param garlic	cost parameter
	 * @param salt		salt parameter, recommended at least 16 bytes
	 * @param h			value, holds the result
	 */
	public abstract void flap(byte[] x, int lambda, int garlic, byte[] salt, byte[] h);
	

	
	
	//====== Implemented Methods ======
		
	/**
	 * Clear the password 
	 * 
	 * @param pwd	the password to be cleared
	 */
	private final void erasePwd(byte[] pwd) {
		Arrays.fill(pwd, (byte) 0);
	}

	private final static byte[] int2bytesLE(int val) {
		byte[] result = new byte[4];
		result[0] = (byte) val;
		result[1] = (byte)(val >>>  8);
		result[2] = (byte)(val >>>  16);
		result[3] = (byte)(val >>>  24);
		return result;		
	}
	
	private final static byte[] long2bytesLE(long longValue) {
	    return new byte[] {
	        (byte) (longValue),
	        (byte) (longValue >> 8),
	        (byte) (longValue >> 16),
	        (byte) (longValue >> 24),
	        (byte) (longValue >> 32),
	        (byte) (longValue >> 40),
	        (byte) (longValue >> 48),
	        (byte) (longValue >> 56)
	    };
	}
	
	//====== GETTER & SETTER ======
	
	
	/**
	 * returns the default cost parameter
	 * of the child class 
	 */
	public abstract int getDefaultGarlic();
	
	/**
	 * returns the default minGarlic parameter
	 * of the child class 
	 */
	public abstract int getDefaultMinGarlic();
	
	/**
	 * returns the default parameter for the graphs depth
	 * of the child class 
	 */
	public abstract int getDefaultLambda();
	
	/**
	 * @return the versionID
	 */
	public String getVersionID() {
		return versionID;
	}
	/**
	 * @param versionID the versionID to set
	 */
	public void setVersionID(String versionID) {
		this.versionID = versionID;
	}
	/**
	 * @param _digest	the hash function for Catena
	 */
	public void setDigest(Digest _digest) {
		digest = _digest;
	}
	/**
	 * @param _fastDigest	 the possibly round-reduced hash function
	 */
	public void setFastHash(FastHash _fastHash) {
		fastHash = _fastHash;
	}
	/**
	 * @return	the hash function for Catena
	 */
	public Digest getDigest() {
		return digest;
	}
	/**
	 * @return	 the possibly round-reduced hash function
	 */
	public FastHash getFastHash() {
		return fastHash;
	}
	/**
	 * @return 	value that indicates if the 
	 * 			password is cleared as soon as possible
	 */
	public boolean isOverwrite() {
		return overwrite;
	}

	/**
	 * @param 	if true, the password 
	 * 			is cleared as soon as possible
	 */
	public void setOverwrite(boolean _overwrite) {
		this.overwrite = _overwrite;
	}
	/**
	 * @return 	value indicates if round-reduced 
	 * 			hash function is used or not 
	 */
	public boolean isFast() {
		return fast;
	}

	/**
	 * @param 	if true: Catena uses a 
	 * 			round-reduced hash function
	 * 			for some computations
	 */
	public void setFast(boolean fast) {
		this.fast = fast;
	}
}
