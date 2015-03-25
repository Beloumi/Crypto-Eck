package blake2b;

/**
 * @author Axel von dem Bruch
 */

/*
 * Test class for Hash Function Blake2b
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

import java.io.UnsupportedEncodingException;

public class TestBlake2b {	
	
	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	
	private static final String[][] keyedTestVectors = { // input/message, key, hash
		
		// Vectors from BLAKE2 web site: https://blake2.net/blake2b-test.txt		
		{"",
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			"10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"},
		
		{"0001",
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			"da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965"},
		
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d",
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			"f1aa2b044f8f0c638a3f362e677b5d891d6fd2ab0765f6ee1e4987de057ead357883d9b405b9d609eea1b869d97fb16d9b51017c553f3b93c0a1e0f1296fedcd"},
				
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3",
				"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
				"c230f0802679cb33822ef8b3b21bf7a9a28942092901d7dac3760300831026cf354c9232df3e084d9903130c601f63c1f4a4a4b8106e468cd443bbe5a734f45f"},
					
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
				"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
				"142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e92484be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461"}			
	};
	
	private final static String[][] unkeyedTestVectors = { // from: http://fossies.org/linux/john/src/rawBLAKE2_512_fmt_plug.c
		// hash, input/message
		// digests without leading $BLAKE2$
		{"4245af08b46fbb290222ab8a68613621d92ce78577152d712467742417ebc1153668f1c9e1ec1e152a32a9c242dc686d175e087906377f0c483c5be2cb68953e", 
			"blake2"},
		{"021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0", 
			"hello world"},
		{"1f7d9b7c9a90f7bfc66e52b69f3b6c3befbd6aee11aac860e99347a495526f30c9e51f6b0db01c24825092a09dd1a15740f0ade8def87e60c15da487571bcef7", 
			"verystrongandlongpassword"},
		{"a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918", 
			"The quick brown fox jumps over the lazy dog"},
		{"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", 
			""},		
	};
	
	//=========================================================================
	// Helper functions:
	
	private final static byte[] hex2bytes(String hexString) {

		byte[] byteArray = new byte[hexString.length() / 2];// 2 Character = 1 Byte
		int len = hexString.length();
		if ( (len & 1) == 1){ 
			System.err.println("Illegal Argument (Function hexStringToBytes): HexString is not even");
			System.exit(1);
		}
		final char [] hexCharArray = hexString.toCharArray ();
		for (int i = 0; i < hexString.length(); i+=2) {
			// 1. char in hex <<4, 2. char in hex
			byteArray[i / 2] = (byte) ((Character.digit (hexCharArray[i], 16) << 4) 
							+ Character.digit (hexCharArray[i + 1], 16));
		}		
		return byteArray;
	}

	private final static String bytes2hex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}

	public static void main(String[] args) {		
		
		// test keyed test vectors:
		for (int tv = 0; tv < keyedTestVectors.length; tv++) {
		
			byte[] input = hex2bytes(keyedTestVectors[tv][0]);
			byte[] key = hex2bytes(keyedTestVectors[tv][1]);

			Blake2b blake2bkeyed = new Blake2b(key );
			
			blake2bkeyed.update(input);
			byte[] keyedHash = new byte[64];
			blake2bkeyed.doFinal(keyedHash, 0);
			
			if (bytes2hex(keyedHash).toUpperCase().equals(keyedTestVectors[tv][2].toUpperCase())){
				System.out.println(keyedTestVectors[tv][0] + " with key");
				System.out.println("ok");
			} else {
				System.out.println("Keyed test vector failed");
				System.out.println("result: \n" + bytes2hex(keyedHash));
				System.out.println("expected: \n" + keyedTestVectors[tv][2].toUpperCase());
			}
		}

		// test unkeyed test vectors:
		for (int i = 0; i < unkeyedTestVectors.length; i++) {
			
			Blake2b blake2bunkeyed = new Blake2b( );		
			try {
				blake2bunkeyed.update( unkeyedTestVectors[i][1].getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			byte[] unkeyedHash = new byte[64];
			blake2bunkeyed.doFinal(unkeyedHash, 0);
			
			if (bytes2hex(unkeyedHash).toUpperCase().equals(unkeyedTestVectors[i][0].toUpperCase())){
				System.out.println(unkeyedTestVectors[i][1]);
				System.out.println("ok");
			} else {
				System.out.println("Unkeyed test vector failed");
				System.out.println("result: \n" + bytes2hex(unkeyedHash));
				System.out.println("expected: \n" + unkeyedTestVectors[i][0].toUpperCase());
			}
		}
	}
}
