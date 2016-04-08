package cologne.eck.dr.op.crypto.password_hashing;

/*
 * Helper Class for Catena v3.3 
 * 
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

import cologne.eck.dr.op.crypto.digest.Digest;
import cologne.eck.dr.op.crypto.digest.FastHash;



public class CatenaHelper {
	
	private Digest digest;
	private FastHash fastHash;
	boolean fast;
	
	private int hLen;
	//private int hLenFast;
	

	public CatenaHelper(Digest _digest, FastHash _fastHash, boolean _fast) {
		digest = _digest;
		fastHash = _fastHash;
		fast = _fast;		
		hLen = digest.getOutputSize();
	}
	
	
	/**
	 * This function uses a full version of a digest,
	 * (sets first node H(0|X) and second node H(1|X) ) 
	 * 
	 * @param input1	first input vector for hash function
	 * @param inIndex1	index of first input vector, the 
	 * 					length is always hLen (64 byte)
	 * @param input2	second input vector for hash function
	 * @param inIndex2	index of second input vector, the 
	 * 					length is always hLen (64 byte)
	 * @param hash		vector to store the resulting hash value
	 * @param outIndex	index, where hash value is stored
	 */
	protected void H_INIT(
			byte[] x, int xlen,  
			byte[] vm1, 
			byte[] vm2){

		byte l = 2;// * hLenFast / hLen;// 2 * k / n
		byte[] tmp = new byte[l * hLen];
		  
		for (int i = 0; i < l; i++) {
			  
			digest.update( (byte) i);
			digest.update(x, 0, xlen);
			digest.doFinal(tmp,  i * hLen);			  
			digest.reset();
		}  
		System.arraycopy(tmp, 0, vm1, 0, hLen);
		System.arraycopy(tmp, l/2*hLen, vm2, 0, hLen);
		Arrays.fill(tmp, (byte) 0);
	}
	
	/**
	 * Uses hashfull instead of hashfast for first node in current layer
	 * 
	 * @param input1	first input vector for hash function
	 * @param inIndex1	index of first input vector, the 
	 * 					length is always hLen (64 byte)
	 * @param input2	second input vector for hash function
	 * @param inIndex2	index of second input vector, the 
	 * 					length is always hLen (64 byte)
	 * @param hash		vector to store the resulting hash value
	 * @param outIndex	index, where hash value is stored
	 */
	protected void H_First( 
			byte[] input1, int inIndex1, 
			byte[] input2, int inIndex2, 
			byte[] hash, int outIndex){

		byte[] x = new byte[hLen];		
		
		digest.update(input1, inIndex1, hLen);
		digest.update(input2, inIndex2, hLen);
		digest.doFinal(x, 0);				
		digest.reset();
		
		digest.update( (byte) 0);
		digest.update(x,0, hLen);
		digest.doFinal(hash, outIndex);		
		digest.reset();
	}	

	/**
	 * If fast = true, this function uses a round-reduced 
	 * version of the digest. 
	 * 
	 * @param vIndex	vertex index, indicates the round 
	 * 					of the hash function to be used
	 * @param input1	first input vector for hash function
	 * @param inIndex1	index of first input vector, the 
	 * 					length is always hLen (64 byte)
	 * @param input2	second input vector for hash function
	 * @param inIndex2	index of second input vector, the 
	 * 					length is always hLen (64 byte)
	 * @param out		vector to store the resulting hash value
	 * @param outIndex	index, where hash value is stored
	 */
	protected void hashFast(int vIndex, 
			byte[] input1, int inIndex1, 
			byte[] input2, int inIndex2, 
			byte[] out, int outIndex) {
		
		if (fast == true) {			
			fastHash.hash(vIndex, 
					input1, inIndex1, 
					input2, inIndex2, 
					out, outIndex);
		} else { // FULL
			hash2(
					input1, inIndex1, 
					input2, inIndex2, 
					out, outIndex);
		}
	}	
	
	/**
	 * This function uses a digest with all rounds
	 * 
	 * @param vIndex	vertex index, indicates the round 
	 * 					of the hash function to be used
	 * @param input1	first input vector for hash function
	 * @param inIndex1	index of first input vector, the 
	 * 					length is always hLen (64 byte)
	 * @param input2	second input vector for hash function
	 * @param inIndex2	index of second input vector, the 
	 * 					length is always hLen (64 byte)
	 * @param hash		vector to store the resulting hash value
	 * @param outIndex	index, where hash value is stored
	 */
	protected void hash2(
			byte[] input1, int inIndex1, 
			byte[] input2, int inIndex2, 
			byte[] hash, int outIndex) {
		
		digest.update(input1, inIndex1, hLen);
		digest.update(input2, inIndex2, hLen);
		digest.doFinal(hash, outIndex);
		digest.reset();
	}
	
	/**
	 * Initializes the state vector
	 * @param triplesIndex		64 byte vector
	 * @param c		int value
	 * @param r		memory consuming state vector
	 */
	protected void initmem(byte[] x, long c, byte[] r) {

		byte[] vm1 = new byte[hLen];
		byte[] vm2 = new byte[hLen];
		
		H_INIT(x, hLen, vm1, vm2);
		
		  if(fastHash != null) {
			  fastHash.reset();
		  }		  
		  hashFast(0, vm1, 0, vm2, 0, r, 0);	
		  hashFast(1, r, 0, vm1, 0, r, hLen);
		    
		  for(int i = 2; i < c; i++){	
			  hashFast(i, r, (i-1) * hLen, r, (i-2) * hLen, r, i * hLen);
		  }
	}	

	// === RNG xorshift1024star ===
	private long[] s ;// state of the Xorshift RNG
	private int p; // position in state vector s
	
	/**
	 * Used for Xorshift generator
	 */
	void initXSState(byte[] a, byte[] b){ // seed the state with two hash values
		s = new long[16];

		p = 0;
		int sIndex = 0;
		for ( int i = 0; i < a.length; i+=8) {
			s[sIndex++] = bytes2long(a, i);
		}
		for ( int i = 0; i < b.length; i+=8) {
			s[sIndex++] = bytes2long(b, i);
		}		
	}

	/**
	 * Xorshift generator with 1024 bits of state
	 * 
	 * @return
	 */
	private long xorshift1024star(){	
		// computes random g-bit value j1 / j2
		// in each iteration of the for-loop of saltMix 
		long s0 = s[p];
		p = (p+1) & 15;
		long s1 = s[ p];
		s1 ^= s1 << 31; // a
		s1 ^= s1 >>> 11; // b
		s0 ^= s0 >>> 30; // c
		s[p] = s0 ^ s1;
		return s[p] * 1181783497276652981L;
	}	

	/**
	 * The gamma function for Butterfly and Dragonfly, 
	 * updates the state array in salt-dependent manner 
	 * 
	 * @param garlic
	 * @param publicInput
	 * @param r
	 */
	protected void saltMix(int garlic, byte[] publicInput, byte[] r) {

		long q = 1 << ((3*garlic+3)/4);
		int vertexIndex; 
		long j; // index of updated word and index for first input
		long j2; // index of second input
		byte[] tmp = new byte[hLen];
		byte[] tmp2 = new byte[hLen];

		// generate the seed		
		digest.update(publicInput);
		digest.doFinal(tmp, 0);
		digest.reset();
		//blake2b = new Blake2b();
		digest.update(tmp);
		digest.doFinal(tmp2, 0);
		digest.reset();

		initXSState(tmp, tmp2);

		if(fastHash != null)
		fastHash.reset();
		//fastDigest.reset();
		for(vertexIndex = 0; vertexIndex < q; vertexIndex++){ 
			j = xorshift1024star() >>> (64 - garlic); 
			j2 = xorshift1024star() >>> (64 - garlic);

	  		hashFast(vertexIndex, 
				r, (int) j * hLen, 
				r, (int) j2 * hLen, 
				r, (int) j * hLen);
		}	
	}	
	
	/**
	 * Convert an array of 8 bytes in a 64 bit long value
	 * in little endian order
	 * 
	 * @param byteArray		byte array
	 * @param offset		start index in byte array 
	 * 
	 * @return				the resulting 64 bit long value
	 */
	public final static long bytes2long(byte[] byteArray, int offset) {
	      
	      return (	    		  
				  ((long) byteArray[offset] & 0xFF ) |
				  (((long) byteArray[offset + 1] & 0xFF ) << 8) |
				  (((long) byteArray[offset + 2] & 0xFF ) << 16) |
				  (((long) byteArray[offset + 3] & 0xFF ) << 24) |
			      (((long) byteArray[offset + 4] & 0xFF ) << 32) |
			      (((long) byteArray[offset + 5] & 0xFF ) << 40) |
			      (((long) byteArray[offset + 6] & 0xFF ) << 48) |
			      (((long) byteArray[offset + 7] & 0xFF ) << 56) ) ;  	    			    		  
	}
}
