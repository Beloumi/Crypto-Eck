package blake2b;


/**
 * @author Axel von dem Bruch
 */

/*
 * Hash Function Blake2b
 * Copyright (C) 2015  Axel von dem Bruch
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
 * 
 * Note: A modified version of this class might be in future a part of 
 * Bouncy Castle Crypto API
 * and will probably available under MIT-like license 
 */


/*  The BLAKE2 cryptographic hash function was designed by Jean-
   Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian
   Winnerlein.
   With a built-in keying mechanism BLAKE2 can be used instead of a HMAC construction.
   BLAKE2b is optimized for 64-bit platforms and produces digests of any size 
   between 1 and 64 bytes.      
      Reference Implementation and Description can be found at: https://blake2.net/      
      Internet Draft: https://tools.ietf.org/html/draft-saarinen-blake2-02
      
   This implementation does not support the Tree Hashing Mode. 
          
      
   Example code using this class:
      
      Blake2b b = new Blake2b(); // no key, no salt, no personalization
      b.update( anyByteArray1 );
      b.update( anyByteArray2 );
      byte[] hash = new byte[64];// full length of hash value
      b.doFinal(hash, 0); // result now holds the hash value (64 byte)
      
      Blake2b b2b = new Blake2b(); // no key, no salt, no personalization
      b2b2.update( anyByteArray );
      // store hash value in any byte array with length > 64 + pos
      b2b.doFinal(result, pos); // result now holds the hash value (64 byte) at position pos
      
      Blake2b b2bK = new Blake2b( anyKeyAsByteArray );// key length 0 - 64 
      b2bK.update( anyByteArray );
      byte[] resultK = new byte[64];// full length of hash value
      b2bK.doFinal(resultK, 0); // resultK now holds the hash value
      
      Blake2b b2bX = new Blake2b(
      		anyKeyAsByteArray, // 0 - 64 Byte or null
      		outputLength, // 1 - 64
      		anySaltAsByteArray, // exactly 16 Byte or null
      		anyPersonalizationAsByteArray); // exactly 16 Byte or null
      b2bX.update( anyByteArray );
      byte[] resultX = new byte[outputLength];
      b2bX.doFinal(resultX, 0); // resultX now holds the hash value    
*/

import java.util.Arrays;

public class Blake2b {
	
	private final static long blake2b_IV[] = 
			// Blake2b Initialization Vector: 
			// Produced from the square root of primes 2, 3, 5, 7, 11, 13, 17, 19.
			// The same as SHA-512 IV.
		{
		  0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
		  0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
		  0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
		  0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L 
		};
	
	private final static byte[][] blake2b_sigma = // Message word permutations
		{
		  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
		  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
		  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
		  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
		  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
		  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
		  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
		  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
		  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
		  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
		  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
		  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
		};

	private final static int ROUNDS = 12;
	private final static int BLOCK_LENGTH_BYTES = 128;// bytes
	
	// General parameters:
	private int digestLength = 64; // 1- 64 bytes 
	private int keyLength = 0; // 0 - 64 bytes for keyed hashing for MAC
	private byte[] salt = null;//new byte[16];
	private byte[] personalization = null;//new byte[16];
	
	// Tree hashing parameters: 
	// Because this class does not implement the Tree Hashing Mode,
	// these parameters can be treated as constants (see init() function)
/*	private int fanout = 1; // 0-255
	private int depth = 1; // 1 - 255
	private int leafLength= 0; 
	private long nodeOffset = 0L;
	private int nodeDepth = 0; 
	private int innerHashLength = 0; 
*/	
	
	// whenever this buffer overflows, it will be processed 
	// in the compress() function. 
	// For performance issues, long messages will not use this buffer. 
	private byte[] buffer = null;//new byte[BLOCK_LENGTH_BYTES];
	// Position of last inserted byte:
	private int bufferPos = 0;// a value from 0 up to 128

	private long[] internalState = new long[16]; // In the Blake2b paper it is called: v
	private long[] chainValue = null; // state vector, in the Blake2b paper it is called: h
	
	private long t0 = 0L; // holds last significant bits, counter (counts bytes)
	private long t1 = 0L; // counter: Length up to 2^128 are supported
	private long f0 = 0L; // finalization flag, for last block: ~0L
	
	// For Tree Hashing Mode, not used here:
//	private long f1 = 0L; // finalization flag, for last node: ~0L 
	
	public Blake2b() {
		buffer = new byte[BLOCK_LENGTH_BYTES];
		keyLength = 0;
		digestLength = 64;
		init();
	}
	public Blake2b(byte[] key) {
		buffer = new byte[BLOCK_LENGTH_BYTES];
		if (key != null) {
			if (key.length > 64) {
				throw new IllegalArgumentException("Keys > 64 are not supported");
			}
			keyLength = key.length;
			System.arraycopy(key, 0, buffer, 0, key.length);
			bufferPos = BLOCK_LENGTH_BYTES; // zero padding
		} 
		digestLength = 64;
		init();
	}
	public Blake2b(
			byte[] key, 
			int _digestLength, 
			byte[] _salt, 
			byte[] _personalization) {

		buffer = new byte[BLOCK_LENGTH_BYTES];
		if (_digestLength < 1 || digestLength > 64) {
			throw new IllegalArgumentException("Invalid digest length (required: 1 - 64)");		
		}
		digestLength = _digestLength;		
		if (_salt != null) {
			if (_salt.length != 16) {
				throw new IllegalArgumentException("salt length must be exactly 16 bytes");
			}
			salt = new byte[16];
			System.arraycopy(_salt,  0,  salt,  0,  _salt.length);
		}
		if (_personalization != null) {
			if (_personalization.length != 16) {
				throw new IllegalArgumentException("personalization length must be exactly 16 bytes");
			}
			personalization = new byte[16];
			System.arraycopy(_personalization,  0,  personalization,  0,  _personalization.length);
		}		
		if (key != null) {
			if (key.length > 64) {
				throw new IllegalArgumentException("Keys > 64 are not supported");
			}
			keyLength = key.length;
			System.arraycopy(key, 0, buffer, 0, key.length);
			bufferPos = BLOCK_LENGTH_BYTES; // zero padding
		} 
		init();
	}
	
	// initialize chainValue
	private void init() {
		
		if (chainValue == null){
			chainValue = new long[8];

			chainValue[0] = blake2b_IV[0] ^ ( digestLength | (keyLength << 8) | 0x1010000);
				// 0x1010000 = ((fanout << 16) | (depth << 24) | (leafLength << 32)); 
				// with fanout = 1; depth = 0; leafLength = 0;
			chainValue[1] = blake2b_IV[1];// ^ nodeOffset; with nodeOffset = 0;
			chainValue[2] = blake2b_IV[2];// ^ ( nodeDepth | (innerHashLength << 8) );
			// with nodeDepth = 0; innerHashLength = 0;
			
			chainValue[3] = blake2b_IV[3];
			
			chainValue[4] = blake2b_IV[4];
			chainValue[5] = blake2b_IV[5];
			if (salt != null) {
				chainValue[4] ^= (bytes2long(salt, 0));
				chainValue[5] ^= (bytes2long(salt, 8));
			}
			
			chainValue[6] = blake2b_IV[6];
			chainValue[7] = blake2b_IV[7];
			if (personalization != null) {
				chainValue[6] ^= (bytes2long(personalization, 0));
				chainValue[7] ^= (bytes2long(personalization, 8));				
			}
		}
	}
	
	private void initializeInternalState(){
		
		// initialize v:
		System.arraycopy(chainValue, 0, internalState, 0, chainValue.length);
		System.arraycopy(blake2b_IV, 0, internalState, chainValue.length, 4);
		internalState[12] = t0 ^ blake2b_IV[4];
		internalState[13] = t1 ^ blake2b_IV[5];
		internalState[14] = f0 ^ blake2b_IV[6];
		internalState[15] = blake2b_IV[7];// ^ f1 with f1 = 0
	}
	
	/**
	 * Processes the given message
	 * 
	 * @param message
	 *            byte array containing the message to be processed
	 */
	public void update(byte[] message) {

		update(message, 0, message.length);
	}
	
	/**
	 * Processes a number of bytes of the given message 
	 * from a start position up to offset+len
	 * 
	 * @param message
	 *            byte array containing the message to be processed
	 * @param offset
	 *            position of message to start from
	 * @param len
	 *            number of bytes to be processed.
	 */
	public void update(byte[] message, int offset, int len) {
		
		if (message == null || len == 0) return;
		
		int remainingLength = 0; // left bytes of buffer
		
		if (bufferPos != 0) { // commenced, incomplete buffer

			// complete the buffer:	
			remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
			if (remainingLength < len) { // full buffer + at least 1 byte
				System.arraycopy(message, offset, buffer, bufferPos, 
						remainingLength);
				t0 += BLOCK_LENGTH_BYTES;
				if (t0 == 0) { // if message > 2^64
					t1++;	
				}
				compress(buffer, 0);
				bufferPos = 0;
				Arrays.fill(buffer,  (byte) 0);// clear buffer
			} else {
				System.arraycopy(message, offset, buffer, bufferPos, 
						len);
				bufferPos += len;
				return;
			}
		}
		
		// process blocks except last block (also if last block is full)
		int messagePos;
		int blockWiseLastPos = offset + len - BLOCK_LENGTH_BYTES;
		for ( messagePos = offset + remainingLength; messagePos < blockWiseLastPos; messagePos += BLOCK_LENGTH_BYTES) { // block wise 128 bytes
			// without buffer:
			t0 += BLOCK_LENGTH_BYTES;
			if (t0 == 0) {
				t1++;	
			}
			compress(message, messagePos);
		}

		//fill the buffer with left bytes, this might be a full block
		System.arraycopy(message, messagePos, buffer,  0, offset + len - messagePos);	
		bufferPos += offset + len - messagePos;
	}
	
	/**
	 * Calculates the final digest value and resets the digest
	 * 
	 * @param out
	 * 			the calculated digest will be copied in this array
	 * @param outOffset
	 * 			start position of the array out, where the digest is copied
	 */	
	public void doFinal(byte[] out, int outOffset) {

		f0 = 0xFFFFFFFFFFFFFFFFL;
		t0 += bufferPos;
		// bufferPos may be < 128, so (t0 == 0) does not work 
		// for  2^64 < message length > 2^64 - 127
		if ( (t0 < 0) && (bufferPos > -t0) ) {
			t1++;
		}
		compress(buffer, 0);
		Arrays.fill(buffer,  (byte) 0);// Holds eventually the key if input is null
		Arrays.fill(internalState, 0L);

		for (int i = outOffset; i < chainValue.length; i++) {
			System.arraycopy(long2bytes(chainValue[i]), 0, out, i * 8, 8);
		}
		Arrays.fill(chainValue, 0L);		
	}
	
	/**
	 * Reset the hash function 
	 */
	public void reset() {
		//  nothing to do	
	}
	
	private void compress(byte[] message, int messagePos) {

		initializeInternalState();
		
		long[] m = new long[16];
		for (int j = 0; j < 16; j++) {
			m[j] = bytes2long(message, messagePos + j*8);
		}

		for (int round = 0; round < ROUNDS; round++) {

			// G apply to columns of internalState:
		    G(m, 0, round, 0,4,8,12); 
		    G(m, 1, round, 1,5,9,13); 
		    G(m, 2, round, 2,6,10,14); 
		    G(m, 3, round, 3,7,11,15); 
		    // G apply to diagonals of internalState:
		    G(m, 4, round, 0,5,10,15); 
		    G(m, 5, round, 1,6,11,12); 
		    G(m, 6, round, 2,7,8,13); 
		    G(m, 7, round, 3,4,9,14); 
		}

		// update chain values: 
		for( int offset = 0; offset < chainValue.length; offset++ ) {
			chainValue[offset] = chainValue[offset] ^ internalState[offset] ^ internalState[offset + 8];	
		}
	}
	

	private void G(long[] m, int blockPos,  int round, int posA, int posB, int posC, int posD) {

		internalState[posA] = internalState[posA] + internalState[posB] + m[blake2b_sigma[round][2 * blockPos]]; 
	    internalState[posD] = rotr64(internalState[posD] ^ internalState[posA], 32); 
	    internalState[posC] = internalState[posC] + internalState[posD]; 
	    internalState[posB] = rotr64(internalState[posB] ^ internalState[posC], 24); // replaces 25 of BLAKE
	    internalState[posA] = internalState[posA] + internalState[posB] + m[blake2b_sigma[round][2*blockPos +1]]; 
	    internalState[posD] = rotr64(internalState[posD] ^ internalState[posA], 16); 
	    internalState[posC] = internalState[posC] + internalState[posD]; 
	    internalState[posB] = rotr64(internalState[posB] ^ internalState[posC], 63); // replaces 11 of BLAKE
	}
	
	private long rotr64(long x, int rot) {
		return x >>> rot | (x << (64 - rot));
	}
	
	// convert one long value in byte array
	// little-endian byte order!
	public final static byte[] long2bytes(long longValue) {
	    return new byte[] {	        
		    (byte) longValue,
	        (byte) (longValue >> 8),
	        (byte) (longValue >> 16),
	        (byte) (longValue >> 24),
	        (byte) (longValue >> 32),
	        (byte) (longValue >> 40),
	        (byte) (longValue >> 48),
	        (byte) (longValue >> 56)};
	}
	// little-endian byte order!
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
