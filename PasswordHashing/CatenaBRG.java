package cologne.eck.dr.op.crypto.password_hashing;

/**
 * This implementation refers to: 
 * Paper v3.3 and from reference implementation 2016
 */

/*
 * Password Hashing Scheme Catena: Instance Catena-Dragonfly (v3.3)
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

import cologne.eck.dr.op.crypto.digest.Blake2b;
import cologne.eck.dr.op.crypto.digest.Blake2b_1;


public class CatenaBRG extends Catena {
	
	private final static String VERSION_ID = "Dragonfly";
	private final static String VERSION_ID_FULL = "Dragonfly-Full";
	private final static int DEFAULT_LAMBDA = 2;//  λ (depth of F)
	private final static int DEFAULT_GARLIC = 21;// defines time and memory requirements
	private final static int DEFAULT_MIN_GARLIC = 21;// minimum garlic	

	private CatenaHelper helper;

	/**
	 * Default constructor. 
	 * Uses round-reduced hash function 
	 * and does not clear the password
	 */
	public CatenaBRG() {
		setFast(true);
		setDigest(new Blake2b());
		setFastHash(new Blake2b_1());
		setVersionID(VERSION_ID);
		helper = new CatenaHelper(getDigest(), getFastHash(), isFast());
	}
	
	/**
	 * Constructor for round-reduced hash function
	 * 
	 * @param fast	if true, use round-reduced 
	 * 				hash function for some computations
	 */
	public CatenaBRG(boolean _fast) {

		setDigest(new Blake2b());
		setFast(_fast);
		if (_fast == false) {
			setVersionID(VERSION_ID_FULL);
		} else {
			setVersionID(VERSION_ID);
			setFastHash(new Blake2b_1());
		}
		helper = new CatenaHelper(getDigest(), getFastHash(), isFast());
	}
	
	/**
	 * Constructor for round-reduced hash function 
	 * and clearing the password
	 * 
	 * 
	 * @param fast			if true, use round-reduced 
	 * 						hash function for some computations
	 * @param overwrite		if true, clear password as soon 
	 * 						as possible
	 */	
	public CatenaBRG(boolean _fast, boolean overwrite) {

		setDigest(new Blake2b());
		setFast(_fast);
		setOverwrite(overwrite);
		if (_fast == false) {
			setVersionID(VERSION_ID_FULL);
		} else {
			setFastHash(new Blake2b_1());
			setVersionID(VERSION_ID);
		}
		helper = new CatenaHelper(getDigest(), getFastHash(), isFast());
	}
	
	/**
	 * an optional randomization layer Γ,
	 * to harden the memory initialization;
	 * updates the state array, 
	 * depending on the public input (salt)
	 * 
	 * @param garlic	cost parameter
	 * @param salt		salt
	 * @param r			memory consuming state vector
	 */
	protected void gamma(int garlic, byte[] salt, byte[] r) {
		helper.saltMix(garlic, salt, r);		
	}
	
	/**
	 * Memory-hard function: Bit-Reversal Graph
	 * 
	 * @param r			the memory consuming state vector
	 * @param garlic	cost parameter
	 * @param lambda	depth of graph
	 * @param h			value, holds the result
	 */
	protected void F(byte[] r, int garlic, int lambda, byte[] h) {
		
		int c = 1 << garlic;
		  
		for (int k = 0; k < lambda; k++) {

			helper.H_First(
					r, (c - 1) * hLen, 
					r, 0, 
					r, 0);
			  
			if (fastHash != null){
				fastHash.reset();
			}

			byte[] previousR = new byte[hLen];
			System.arraycopy(r, 0, previousR, 0, hLen);
			    
			for (long i = 1; i < c; i++) {
		    	helper.hashFast(
		    			(int)i, previousR, 
		    			0, r, 
		    			Math.abs((int) reverse(i, garlic) * hLen), r, (int)reverse(i, garlic) * hLen);
		    	System.arraycopy( r, (int)reverse(i, garlic) * hLen,  previousR,  0,  hLen);
			}
		    k++;
		    if (k >= lambda) {
		      break;
		    }
		    
			helper.H_First(
					r, (c - 1) * hLen, 
					r, 0, 
					r, 0);
		    
			if (fastHash != null){
				fastHash.reset();
			}

		    int pIndex = 0;
		    for (int i = 1; i < c; i++, pIndex += hLen) {
		    	helper.hashFast( i, r, pIndex, r, pIndex + hLen, r, pIndex + hLen);
		    }
		}
		System.arraycopy(r, (c - 1) * hLen, h, 0, hLen);
		Arrays.fill(r,  (byte) 0);
	}
	
	private long byteSwap(long x) {
	    return  ((((x) & 0xff00000000000000L) >>> 56)				      
	    	      | (((x) & 0x00ff000000000000L) >>> 40)				      
	    	      | (((x) & 0x0000ff0000000000L) >>> 24)				      
	    	      | (((x) & 0x000000ff00000000L) >>> 8)				      
	    	      | (((x) & 0x00000000ff000000L) << 8)				      
	    	      | (((x) & 0x0000000000ff0000L) << 24)				      
	    	      | (((x) & 0x000000000000ff00L) << 40)				      
	    	      | (((x) & 0x00000000000000ffL) << 56));
	}
	
	/* Return the reverse bit order of triplesIndex where triplesIndex is interpreted as n-bit value */
	private long reverse(long x, int n) {

	  x = byteSwap(x);
	  x = ((x & (0x0f0f0f0f0f0f0f0fL)) <<  4) |
	      ((x & (0xf0f0f0f0f0f0f0f0L)) >>> 4);
	  x = ((x & (0x3333333333333333L)) <<  2) |
	      ((x & (0xccccccccccccccccL)) >>> 2);
	  x = ((x & (0x5555555555555555L)) <<  1) |
	      ((x & (0xaaaaaaaaaaaaaaaaL)) >>> 1);
	  return x >>> (64 - n);
	}
	
	@Override
	public int getDefaultGarlic() {
		return DEFAULT_GARLIC;
	}
	@Override
	public int getDefaultMinGarlic() {
		return DEFAULT_MIN_GARLIC;
	}
	@Override
	public int getDefaultLambda() {
		return DEFAULT_LAMBDA;
	}
	@Override
	public String getAlgorithmName() {
		return versionID;
	}

	@Override
	public byte[] hashPassword(int outlen, byte[] in, byte[] salt, int t_cost,
			int m_cost, Object... varArgs) throws Exception {
		byte[] hash = new byte[outlen];
		hashPassword(
				in, salt, null,  
			    t_cost, m_cost, m_cost,// lambda, minGarlic, garlic  
			    hash);
		return hash;
	}

	@Override
	public boolean isWipePassword() {
		return overwrite;
	}

	@Override
	public void setWipePassword(boolean _wipe) {
		overwrite = true;
	}

	@Override
	public void flap(byte[] x, int lambda, int garlic, byte[] salt, byte[] h) {
		byte[]  r   = new byte[ (int) (( (1 << garlic) + (1 << (garlic-1)) ) * hLen)];

		helper.initmem(x, (1 << garlic), r);
		gamma(garlic, salt, r);
		F(r, garlic, lambda, h);		
	}
}
