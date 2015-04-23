package cologne.eck.dr.op.crypto.password_hashing;


/**
 * @author Axel von dem Bruch
 */

/*
 * Password Hashing Scheme Battcrypt (without key derivation mode)
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
 * Battcrypt was designed by Steven Thomas.
 * It is one of the nine finalist of the Password Hashing Competition. 
 * Submission paper: "battcrypt (Blowfish All The Things)".
 *  
 * Paper and C++ reference implementation can be found at:
 * https://github.com/bsdphk/PHC/tree/master/Battcrypt
 * 
 * Note: This is an implementation without the key derivation mode. 
 * 
 * This implementation requires Bouncy Castles Crypto-API
 * for Blowfish and SHA512
 */

/*
 * Battcrypt intends to make Blowfish memory-hard. 
 * It allows server reliefs: clients calculate everything but instead of the 
 * last "SHA512(SHA512(data || key). This works only if the salt is public. 
 */

import java.util.Arrays;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import cologne.eck.dr.op.crypto.password_hashing.test.TestBattcrypt_v0;


public class Battcrypt_v0 implements PasswordHashingScheme {
	
	private final static int DATA_SIZE_INT = 512; // 2 KiB
	private final static int DATA_SIZE_BYTE = 512 * 4;

	private final static int HASH_LENGTH_BYTE = 64;//SHA512 byte
	private final static int HASH_LENGTH_INT = 64 / 4;// as int
	
	private final static int IV_LENGTH_BYTE = 8;// block size of Blowfish
	
	// if true: password is filled immediately
	private boolean wipePassword = false;

	public Battcrypt_v0() {
		this.wipePassword = false;
	}
	public Battcrypt_v0(boolean _wipe) {
		this.wipePassword = _wipe;
	}
	
	@Override
	public byte[] hashPassword(int outlen, byte[] in, byte[] salt, 
			int t_cost, int m_cost, Object... varArgs) 
					throws DataLengthException, 
					IllegalStateException, 
					InvalidCipherTextException {
		
		SHA512Digest sha = new SHA512Digest();
		int[] data = new int[DATA_SIZE_INT];
		BlowfishEngine blowfish;
		long upgradeLoops = 1;
		long loops;
		int memSize = 4 << m_cost;//= 4 * 2 ** m_cost
		int memMask = memSize - 1;
		int[] mem;
		
		byte[] hashBuffer = new byte[HASH_LENGTH_BYTE];// holds hash value as bytes
		byte[] dataBuffer = new byte[DATA_SIZE_BYTE];// holds encrypted bytes
		
		// These are the PHP max. values 
		if (	m_cost > 18 || // maximum: 2.147.483.648 bytes
				(t_cost & 0xffff) > 62 || 
				(t_cost >> 16) > 63 || 
				outlen > HASH_LENGTH_BYTE) {
			throw new IllegalArgumentException("invalid parameters");
		}
				
		int tmp = t_cost >> 16;

		if (tmp != 0) {
			// upgradeLoops = 1, 2, 3, 4, 6, 8, 12, 16, ...
			upgradeLoops = (long) (3 - (tmp & 1)) << ((tmp - 1) >> 1);
		}

		// loops = 2, 3, 4, 6, 8, 12, 16, ...
		tmp = t_cost & 0xffff;
		loops = (long) ((tmp & 1) + 2) << (tmp >> 1);
		
		// key = SHA512(SHA512(salt) || in)
		byte[] keyBytes = new byte[HASH_LENGTH_BYTE];
		sha.update(salt, 0, salt.length);
		sha.doFinal(keyBytes, 0);
		sha.reset();
		sha.update(keyBytes, 0, HASH_LENGTH_BYTE);
		sha.update(in, 0, in.length);//password
		sha.doFinal(keyBytes,  0);
		sha.reset();
		if (wipePassword == true) {
			Arrays.fill(in,  (byte) 0);	
		}
		
		// initialize cipher with 448 bit (56 byte) key: 
		// truncate keyBytes:
		byte[] blowfishKey = new byte[56];
		System.arraycopy(keyBytes, 0, blowfishKey, 0, 56);
		// use zeros as IV
		byte[] iv = new byte[IV_LENGTH_BYTE]; 
		KeyParameter params = new KeyParameter(blowfishKey);
		Arrays.fill(blowfishKey, (byte) 0);
		ParametersWithIV ivParams = new ParametersWithIV(params, iv);				
		blowfish = new BlowfishEngine(); 
		// CBC, no padding: all vectors are multiples of Blowfish block length
		BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(blowfish)); 			
		cipher.init(true, ivParams);		
		
		// initialize memory-hard vector:
		mem = new int[DATA_SIZE_INT * memSize];
		
		for (long u = 0; u < upgradeLoops; u++)	{

			// initialize data:
			// data = SHA512(BIG_ENDIAN_64( 0) || key) || ...
			// ... || SHA512(BIG_ENDIAN_64(31) || key)			
			byte[] counterBytesBE = new byte[8]; // holds counter as long to update
			for (int i = 0; i < DATA_SIZE_BYTE / HASH_LENGTH_BYTE; i++) {

				counterBytesBE[7] = (byte) i; // set first byte
				sha.update(counterBytesBE, 0, counterBytesBE.length); // BIG_ENDIAN_64(i)
				sha.update(keyBytes, 0, HASH_LENGTH_BYTE);
				sha.doFinal(hashBuffer, 0);
				sha.reset();
				// hash values allow weak garbage collector attack - 
				// so, avoid new allocations: 				
				for (int j = 0; j < HASH_LENGTH_BYTE / 4; j++) {
					data[HASH_LENGTH_INT * i + j] = ((hashBuffer[j*4+3 ] & 0xFF) << 24) 
							| ((hashBuffer[j*4+2] & 0xFF) << 16) 
							| ((hashBuffer[j*4+1] & 0xFF) << 8) 
							| (hashBuffer[j*4+0] & 0xFF); // little endian order
				}			
				Arrays.fill(hashBuffer, (byte) 0);
			}
			
			// Initialize memory:
			for (int i = 0; i < memSize; i++) {
				// data = blowfish_encrypt_cbc(data)
				// mem = mem || data				
				for (int j = 0; j < DATA_SIZE_INT; j++ ) {
					dataBuffer[j*4+0] = (byte) (data[j]);// little endian
					dataBuffer[j*4+1] = (byte)(data[j] >>>  8);
					dataBuffer[j*4+2] = (byte)(data[j] >>>  16);
					dataBuffer[j*4+3] = (byte)(data[j] >>>  24);
				}	
				int len = cipher.processBytes(dataBuffer, 0, DATA_SIZE_BYTE, dataBuffer, 0);
				cipher.doFinal(dataBuffer, len);
				cipher.reset();
				
				// get iv for next encryption step:
				// "running CBC": the last block of the
				//  previous call is the IV for the next call
				System.arraycopy(dataBuffer,  DATA_SIZE_BYTE - IV_LENGTH_BYTE,  
						iv,  0,  IV_LENGTH_BYTE);
				ivParams = new ParametersWithIV(params, iv);
				cipher.init(true, ivParams);
				
				for (int j = 0; j < DATA_SIZE_INT; j++) {
					data[j] = ((dataBuffer[j*4+3 ] & 0xFF) << 24) 
							| ((dataBuffer[j*4+2] & 0xFF) << 16) 
							| ((dataBuffer[j*4+1] & 0xFF) << 8) 
							| (dataBuffer[j*4+0] & 0xFF); // little endian order
				}
				System.arraycopy(data, 0, mem, DATA_SIZE_INT * i, DATA_SIZE_INT);
			}

			// encrypt data:
			for (int j = 0; j < DATA_SIZE_INT; j++ ) {
				dataBuffer[j*4+0] = (byte) (data[j]);// little endian
				dataBuffer[j*4+1] = (byte)(data[j] >>>  8);
				dataBuffer[j*4+2] = (byte)(data[j] >>>  16);
				dataBuffer[j*4+3] = (byte)(data[j] >>>  24);
			}	
			int len = cipher.processBytes(dataBuffer, 0, DATA_SIZE_BYTE, dataBuffer, 0);
			cipher.doFinal(dataBuffer, len);			
			cipher.reset();
			System.arraycopy(dataBuffer,  DATA_SIZE_BYTE - IV_LENGTH_BYTE,  
					iv,  0, IV_LENGTH_BYTE);
			ivParams = new ParametersWithIV(params, iv);
			cipher.init(true, ivParams);

			for (int j = 0; j < DATA_SIZE_INT; j++) {
				data[j] = ((dataBuffer[j*4+3 ] & 0xFF) << 24) 
						| ((dataBuffer[j*4+2] & 0xFF) << 16) 
						| ((dataBuffer[j*4+1] & 0xFF) << 8) 
						| (dataBuffer[j*4+0] & 0xFF); // little endian order
			}

			// work:
			for (long i = 0; i < loops; i++)
			{
				for (int j = 0; j < memSize; j++)
				{
					// in the C++ reference implementation and the paper 
					// this rValue a 64 bit integer, but this makes only a
					// difference for memSize > 0xFFFFFFFF +1, while the
					// recommended maximum for memSize is 2^32
					int rValue = 
							((((int)data[DATA_SIZE_INT - 1]) <<  24) & 0xff000000) | 
							((((int)data[DATA_SIZE_INT - 1]) <<   8) & 0x00ff0000) | 
							((((int)data[DATA_SIZE_INT - 1]) >>>  8) & 0x0000ff00) | 
							((((int)data[DATA_SIZE_INT - 1]) >>> 24) & 0x000000ff) ;
					int index = (int) (DATA_SIZE_INT *  (rValue & memMask));

					for (int k = 0; k < DATA_SIZE_INT; k++) {
						mem[j * DATA_SIZE_INT + k] ^= data[k] ^ mem[index + k];
					}
					
					// convert to byte: 
					for (int k = 0; k < DATA_SIZE_INT; k++ ) {
						dataBuffer[k*4+0] = (byte) (mem[j * DATA_SIZE_INT + k]);
						dataBuffer[k*4+1] = (byte)(mem[j * DATA_SIZE_INT + k] >>>  8);
						dataBuffer[k*4+2] = (byte)(mem[j * DATA_SIZE_INT + k] >>>  16);
						dataBuffer[k*4+3] = (byte)(mem[j * DATA_SIZE_INT + k] >>>  24);
					}	
					int len1 = cipher.processBytes(dataBuffer, 0, DATA_SIZE_BYTE, dataBuffer, 0);

					cipher.doFinal(dataBuffer, len1);
					cipher.reset();
					// get iv for next step:
					System.arraycopy(dataBuffer, DATA_SIZE_BYTE - IV_LENGTH_BYTE,  
							iv,  0, IV_LENGTH_BYTE);

					for (int k = 0; k < DATA_SIZE_INT; k++) {
						mem[j * DATA_SIZE_INT + k] = ((dataBuffer[k*4+3 ] & 0xFF) << 24) 
								| ((dataBuffer[k*4+2] & 0xFF) << 16) 
								| ((dataBuffer[k*4+1] & 0xFF) << 8) 
								| (dataBuffer[k*4+0] & 0xFF); // little endian order
					}
					
					ivParams = new ParametersWithIV(params, iv);
					cipher.init(true, ivParams);

					// data ^= mem[j]
					for (int k = 0; k < DATA_SIZE_INT; k++)
					{
						data[k] ^= mem[DATA_SIZE_INT * j + k];
					}
				}
			}
			// Finish
			// key = truncate(SHA512(SHA512(data || key)), outlen) || zeros(HASH_LENGTH - outlen)
			// convert to byte: 
			for (int k = 0; k < DATA_SIZE_INT; k++ ) {
				dataBuffer[k*4+0] = (byte) (data[k]);
				dataBuffer[k*4+1] = (byte)(data[k] >>>  8);
				dataBuffer[k*4+2] = (byte)(data[k] >>>  16);
				dataBuffer[k*4+3] = (byte)(data[k] >>>  24);
			}
			sha.update(dataBuffer, 0, DATA_SIZE_BYTE);
			sha.update(keyBytes, 0, HASH_LENGTH_BYTE);
			sha.doFinal(keyBytes,  0);
			sha.reset();
		}
		
		sha.update(keyBytes, 0, HASH_LENGTH_BYTE);
		sha.doFinal(keyBytes,  0);
		sha.reset();
		
		byte[] out = new byte[outlen];
		
		System.arraycopy(keyBytes,  0,  out,  0,  out.length);
		
		// Clean-up:
		Arrays.fill(keyBytes, (byte) 0);
		Arrays.fill(dataBuffer, (byte) 0);		
		Arrays.fill(iv,  (byte) 0);
		Arrays.fill(data, 0);
		Arrays.fill(mem, (byte) 0);
		
		// wipe the key from parameters
		Arrays.fill(params.getKey(), (byte) 0);
		
		// prevent dead code eliminations (compiler optimizations):
		if ((keyBytes[HASH_LENGTH_BYTE -1] 
				| blowfishKey[blowfishKey.length-1]
				| dataBuffer[DATA_SIZE_BYTE -1] 
				| hashBuffer[HASH_LENGTH_BYTE -1]
				| data[DATA_SIZE_INT -1] 
				| iv[IV_LENGTH_BYTE -1]
				| mem[mem.length-1] 
				| params.getKey()[params.getKey().length -1]) != 0) {
			System.err.print("zeroization failed!");
		}
		if ((wipePassword == true) && 
				(in[in.length-1] != 0)) {
				System.err.print("zeroization failed!");				
		}		
		return out;
	}

	@Override
	public String getAlgorithmName() {
		return "Battcrypt";
	}
	
	@Override
	/**
	 * indicates if zeroization of password is performed or not
	 * 
	 * @return the wipePassword value
	 */
	public boolean isWipePassword() {
		return wipePassword;
	}

	@Override
	/**
	 * zeroize the password or keep it
	 * 
	 * @param _wipe 
	 * 					true: wipe the password as soon as 
	 * 					possible 
	 * 					false: keep it for later use
	 */
	public void setWipePassword(boolean _wipe) {
		this.wipePassword = _wipe;
	}



//========================================================================
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		TestBattcrypt_v0.main(args);
	}
}
