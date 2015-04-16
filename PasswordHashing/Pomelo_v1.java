package cologne.eck.dr.op.crypto.password_hashing;


/**
 * @author Axel von dem Bruch
 */

/*
 * Password Hashing Scheme Pomelo (old Version 1)
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
 */



/**
 * Pomelo was designed by Hongjun Wu.
 * It is one of the nine finalist of the Password Hashing Competition. 
 * Submission paper: "POMELO: A Password Hashing Algorithm".
 *  
 * All papers and C reference implementations can be found at:
 * http://www3.ntu.edu.sg/home/wuhj/research/pomelo/
 */

/*
 * it is recommended that: 8 <= t_cost + m_cost <= 20;
 * one may use the parameters: m_cost = 12; t_cost = 1;
 * 
 * for m_cost 12: 32 MiB 
 * for m_cost 13: 64 MiB
 * ...
 */

import java.util.Arrays;

import cologne.eck.dr.op.crypto.password_hashing.test.TestPomelo_v1;


public class Pomelo_v1 implements PasswordHashingScheme {

    int i1,i2,i3,i4;
    long [] S; // 2 ^ (13 + m_cost) (byte)
    int mask, index;
    int state_size;
    
	// if set true: password and salt are filled immediately: 
    private boolean wipe = false;
    
    public Pomelo_v1() {
    	this.wipe = false;
    }
    public Pomelo_v1 (boolean _wipe) {
    	this.wipe = _wipe;
    }

	@Override
	public byte[] hashPassword(int outlen, byte[] pwd, byte[] salt, int t_cost,
			int m_cost, Object... varArgs) throws Exception {

		// check parameters:
		if (m_cost > 18 || 
				t_cost > 20 || 
				salt.length < 16 || salt.length > 32 ||
				outlen < 32 || outlen > 128 ||
				pwd.length > 128) {
			throw new IllegalArgumentException("invalid parameters");
		}

	    //Step 1:  Initialize the state S
	    state_size = 8192 << m_cost;
	    S = new long[ state_size / 8 ];
	    mask = state_size/8 - 1; //mask is used for modulation: modulo size_size/8

	    //Step 2:  Load the password, salt, input/output sizes into the state S	    
	    int sIndex = pwd.length / 8 ;
		for (int i = 0; i < sIndex; i++) {
			S[i] = 
			  ((long)(pwd[i * 8 + 7] & 0xff) << 56) |
		      ((long)(pwd[i * 8 + 6] & 0xff) << 48) |
		      ((long)(pwd[i * 8 + 5] & 0xff) << 40) |
		      ((long)(pwd[i * 8 + 4] & 0xff) << 32) |
		      ((long)(pwd[i * 8 + 3] & 0xff) << 24) |
		      ((long)(pwd[i * 8 + 2] & 0xff) << 16) |
		      ((long)(pwd[i * 8 + 1] & 0xff) << 8) |
		      ((long)(pwd[i * 8 + 0] & 0xff));			
		}
		// incomplete long value if in.length % 8 != 0
		int shift = 0;
		for (int i = sIndex * 8; i < pwd.length; i++) {
			S[sIndex] |= ((long) (pwd[i] & 0xFF) << shift);
			shift += 8;
		}		
		if (wipe == true) {
			Arrays.fill(pwd,  (byte) 0);
		}

	    int saltlenLong = salt.length / 8 ;
		for (int i = 0; i < saltlenLong; i++) {
			S[16 + i] = 
			  ((long)(salt[i * 8 + 7] & 0xff) << 56) |
		      ((long)(salt[i * 8 + 6] & 0xff) << 48) |
		      ((long)(salt[i * 8 + 5] & 0xff) << 40) |
		      ((long)(salt[i * 8 + 4] & 0xff) << 32) |
		      ((long)(salt[i * 8 + 3] & 0xff) << 24) |
		      ((long)(salt[i * 8 + 2] & 0xff) << 16) |
		      ((long)(salt[i * 8 + 1] & 0xff) << 8) |
		      ((long)(salt[i * 8 + 0] & 0xff));
		}
		shift = 0;
		for (int i = 0; i < salt.length - saltlenLong * 8; i++) {
			S[16 + saltlenLong] |= ((long) (salt[saltlenLong * 8 + i] & 0xFF) << shift);
			shift += 8;
		}		
		if (wipe == true) {
			Arrays.fill(salt,  (byte) 0);
		}

		S[20] =   ((long)(outlen & 0xff) << 16) |
			      ((long)(salt.length & 0xff) << 8) |
			      ((long)(pwd.length & 0xff));

	    //Step 3: Expand the data into the whole state.
	    for (int i = 41; i < state_size/8; i++)
	    {
	        F(S,i);
	    }

	    //Step 4: update the state using F and G
	    // deterministic random memory accesses:
	    long temp = 1;
	    for (int j = 0; j < (1 << t_cost); j++)
	    {
	       for (int i = 0; i < state_size/8; i++)
	       {
	           F(S,i);
	           // function G(S, i, j)
	           if ( (i & 3) == 3 )
	           {
	               index     = (int) ((temp + (temp >>> 32)) & mask);
	               S[i]     ^= S[index] << 1;
	               S[index] ^= S[i] << 3;
	           }
	           temp = temp + (temp << 2);   // temp = temp*5;
	       }
	    }
	    
	    // Step 5: update the state using F: 
	    for (int i = 0; i < state_size/8; i++)
	    {
	        F(S,i);
	    }

	    // Step 6: update the state using F and H
	    // password-dependent random memory accesses
	    for (int j = 0; j < (1 << t_cost); j++)
	    {
	       for (int i = 0; i < state_size/8; i++)
	       {
	           F(S,i);

	           // function H(S, i)
	           if ( (i & 3) == 3 )
	           {
	               i1 = (i - 1)  & mask;
	               index = (int) (S[ i1] & mask);
	               S[(int) i]     ^= S[index] << 1;
	               S[(int) index] ^= S[ i] << 3;
	           }
	       }
	    }
	    
	    // Step 7: update the state using F
	    for (int i = 0; i < state_size/8; i++)
	    {
	        F(S,i);
	    }
    	temp = 0;
    	i1 = 0;
    	i2 = 0;
    	i3 = 0;
    	i4 = 0;

	    //Step 8: generate the output
		int outlenLong = outlen / 8 + 1; 		
		byte[] tmp = new byte[outlenLong * 8];

		for ( int i = S.length - outlenLong, j = 0; i < S.length; i++, j++) {
			tmp[j * 8 + 7] = (byte) (S[i] >>> 56);
			tmp[j * 8 + 6] = (byte) (S[i] >>> 48);
			tmp[j * 8 + 5] = (byte) (S[i] >>> 40);
			tmp[j * 8 + 4] = (byte) (S[i] >>> 32);
			tmp[j * 8 + 3] = (byte) (S[i] >>> 24);
			tmp[j * 8 + 2] = (byte) (S[i] >>> 16);
			tmp[j * 8 + 1] = (byte) (S[i] >>> 8);
			tmp[j * 8 + 0] = (byte) (S[i] >>> 0);
		}
		
		byte[] out = new byte[outlen];
		System.arraycopy(tmp, tmp.length - outlen, out,  0,  outlen);
		Arrays.fill(tmp,  (byte) 0);
    	Arrays.fill(S, 0L);
    	
		// prevent dead code eliminations (compiler optimizations):
		if ((S[ state_size / 8 -1] 
				| tmp[tmp.length-1]) != 0) {
			System.err.print("zeroization failed!");
		}
		if ((wipe == true) && 
				((pwd[pwd.length-1] // password
						| salt[salt.length-1]) != 0)) {
				System.err.print("zeroization failed!");				
		}

	    return out;
	}
	
	// state update function F: 
	private void F(long[] S, int i)  {         
	    i1 = (i - 1)  & mask; 
	    i2 = (i - 3)  & mask; 
	    i3 = (i - 17) & mask; 
	    i4 = (i - 41) & mask; 
	    S[i] += ((S[i1] ^ S[i2]) + S[i3]) ^ S[i4]; 
	    S[i] = (S[i] << 17) ^ (S[i] >>> 47); 
	}
	

	@Override
	public String getAlgorithmName() {
		return "Pomelo_v1";
	}
	
	@Override
	/**
	 * @return the wipe value
	 */
	public boolean isWipe() {
		return wipe;
	}

	@Override
	/**
	 * if true: password and salt are filled immediately with zero
	 * 
	 * @param _wipe 
	 * 					wipe the input parameters 
	 * 					password and salt or not
	 */
	public void setWipeInput(boolean _wipe) {
		this.wipe = _wipe;
	}
	
	//========================================================
	public static void main(String[] args) {
		TestPomelo_v1.main(args);
	}
}
