package cologne.eck.dr.op.crypto.password_hashing.test;


/**
 * @author Axel von dem Bruch
 */

/*
 * Test class for Pomelo
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

import cologne.eck.dr.op.crypto.password_hashing.Pomelo_v1;

public class TestPomelo_v1 {
	
	private final static String[][] TEST_VECTORS = {
		// first 7 vectors:
		{	"0", // password first byte
		"0", // salt first byte
		"0", // m_cost
		"0", // t_cost
		"be5442a20d7319fa20155f0ab10e86089f7d9ad1e0d168a08e15bce328de78d7"},
		{	"0", // password first byte
		"1", // salt first byte
		"0", // m_cost
		"0", // t_cost
		"577974036f0581f4b9927aa30a8c9f358dfd90e563d6e8c45e9e36e27196c426"},
		{	"0", // password first byte
		"2", // salt first byte
		"0", // m_cost
		"0", // t_cost
		"0ef43f9c7e3db0757ad871771391f5ac41b1daca056ea1c01413a23ed78a0380"},	
		{	"0", // password first byte
		"3", // salt first byte
		"0", // m_cost
		"0", // t_cost
		"ebea79f4946d4686165e77145047c31301a82d21a9741c44c21507964005dc84"},
		{	"0", // password first byte
		"4", // salt first byte
		"0", // m_cost
		"0", // t_cost
		"7d25f483e28052102a7be2a4da65264ae5af6681cdc2439d97e38a9f4e835a8f"},
		{	"0", // password first byte
		"5", // salt first byte
		"0", // m_cost
		"0", // t_cost
		"3ae390634b4867c1ee51a28eeb0dcdcac2cf6261c7d6423814dd3b3579ca67a1"},
		{	"0", // password first byte
		"6", // salt first byte
		"0", // m_cost
		"0", // t_cost
		"70d6695b5b2eab185378ea059abb74c7b27ec968798ea1b9561cd0d8ada6568b"},
		{	"0", // password first byte
		"7", // salt first byte
		"0", // m_cost
		"0", // t_cost
		"a41b0166cd340ec3816ebde59cfe4ed2dfb1cae98e4f24d9ab40763fa09965ec"},
		
		// last 7 vectors:
		{	"7", // password first byte
		"1", // salt first byte
		"7", // m_cost
		"7", // t_cost
		"704e14872866d7a3f678078f4884ec28f8a1df7ade6f5abbb81c74ad3cb4f26b"},
		{	"7", // password first byte
		"2", // salt first byte
		"7", // m_cost
		"7", // t_cost
		"55a31325d36e7b8bee2a14ff79a9f4311d1d89a1db1f655f982d0d601877d247"},
		{	"7", // password first byte
		"3", // salt first byte
		"7", // m_cost
		"7", // t_cost
		"d0648f574d24f30aead9dc6884ec604311cef7f9f12e57513d11ffefe8695d61"},
		{	"7", // password first byte
		"4", // salt first byte
		"7", // m_cost
		"7", // t_cost
		"25ed8ffcbbce86166466b4a66fbd977836edafcced51c484de1faf78eff37918"},
		{	"7", // password first byte
		"5", // salt first byte
		"7", // m_cost
		"7", // t_cost
		"14332619a26eb18ff06ea6fa68ee21efb3700ff13c602f9c0a306a51d539ece0"},
		{	"7", // password first byte
		"6", // salt first byte
		"7", // m_cost
		"7", // t_cost
		"d6cdf01812736a9a33ec2a2cbed344d3b126d517b2a4019d7d05bfb945205784"},
		{	"7", // password first byte
		"7", // salt first byte
		"7", // m_cost
		"7", // t_cost
		"6f5a69aa53dbbe899f0958dcc8460cb300f70ef16176fc600757b08b3a50ccac"}		
	};
	
	private final static String[][] EXTRA_VECTORS = {
		// some extra vectors, produced with the reference implementation of Pomelo
		{"password", 
		"saltsaltsaltsalt",
		"128",
		"1", 
		"12", 
		"2b0ac4da18640904966a9889e71eae5cafbc55a179742e5332d5e35bb8dbebc7d8bfbd0042456c6ea500bb68ef47dc24fd358397d2c832d2623c84436448ac65fdb0fa2ef7e328990f6908990cc4048ac33e6f767302a128e6fd595a334b322b296c29a10b340ceca76725eac01dd7479f4a6f66e9f6ca849a5f4e29f6f12ab8"},
	
		{"äöüßÄÖÜ", 
		"saltsaltsaltsaltsal",
		"67",
		"1", 
		"12", 
		"a587e11b357fc2f7aa95362eeaffaa5664d4aa1e52cfca0a9b3900eadc575549fe6738746bc644057dead2e8b81fb205971b75ae919f4d58e78cf45f69f9acaec5ee9d"},	
	};
	
	private final static char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	private static String bytes2hex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	private final static void testOfficialVectors(){
		// fixed for test vectors:
		int outlen = 32;
		byte[] out = new byte[outlen];
		byte[] in = new byte[128];
		int saltlen = 16;
		byte[] salt = new byte[saltlen];
		
		for (int i = 0; i < TEST_VECTORS.length; i++) {
			// variable:
			in[0] = (byte) Integer.parseInt(TEST_VECTORS[i][0]);
			salt[0] = (byte) Integer.parseInt(TEST_VECTORS[i][1]);

			int m_cost = Integer.parseInt(TEST_VECTORS[i][2]);
			int t_cost = Integer.parseInt(TEST_VECTORS[i][3]);				

			Pomelo_v1 pom = new Pomelo_v1();		
//			pom.PHS(out, outlen,  in, inlen, salt, saltlen, t_cost, m_cost);
			try {
				out = pom.hashPassword(outlen,  in, salt, t_cost, m_cost);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			
			if (bytes2hex(out).toUpperCase().equals(TEST_VECTORS[i][4].toUpperCase())){
				System.out.println("Vector " + i + " ok");
			} else {
				System.out.println("Vector " + i + " failed! \n result:");
				System.out.println(bytes2hex(out).toUpperCase() );
				System.out.println("Test vector: \n" +TEST_VECTORS[i][4].toUpperCase() );
			}
		}
	}
	
	private final static void testExtraVectors(){
		for (int i = 0; i < EXTRA_VECTORS.length; i++) {
			
			byte[] pwd = null;
			byte[] saltX = null;
			try {
				pwd = EXTRA_VECTORS[i][0].getBytes("UTF-8");
				saltX = EXTRA_VECTORS[i][1].getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}	
			int outlenX = Integer.parseInt(EXTRA_VECTORS[i][2]);
			int t_costX =  Integer.parseInt(EXTRA_VECTORS[i][3]);
			int m_costX  = Integer.parseInt(EXTRA_VECTORS[i][4]);
			
			Pomelo_v1 pom = new Pomelo_v1();		
/*			pom.PHS(outX, outlenX,  
				pwd, pwd.length, 
				saltX, saltX.length, 
				t_costX,  // t_cost
				m_costX);// m_cost*/
			byte[] out = null;
			try {
				out = pom.hashPassword(outlenX, pwd, saltX, t_costX, m_costX);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			if (EXTRA_VECTORS[i][5].toUpperCase().equals(bytes2hex(out).toUpperCase())){
				System.out.println(new String(pwd) + "  ok");
			} else {
				System.out.println("Vector " + i + " failed! \n result:");
				System.out.println(bytes2hex(out).toUpperCase() );
				System.out.println("Test vector: \n" +EXTRA_VECTORS[i][5].toUpperCase() );
			}
		}
	}
	private final static void testPerformance(){
		long start = System.currentTimeMillis(); // start
		
		byte[] pwd = null;
		byte[] salt = null;
		try {
			pwd = EXTRA_VECTORS[0][0].getBytes("UTF-8");
			salt = EXTRA_VECTORS[0][1].getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
/*		byte[] out = new byte[32];
		Pomelo pom = new Pomelo();		
		pom.PHS(out, out.length,  
			pwd, pwd.length, 
			salt, salt.length, 
			1,  // t_cost
			12);// m_cost */
		Pomelo_v1 pom = new Pomelo_v1();	
		byte[] out = null;
		try {
			out = pom.hashPassword(32, pwd, salt, 1, 12);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1)+ "\n");//Endpunkt
		// 1 - 12 : 611, 559, 557, 550, 563 (32 MiB)
		// 2 - 12 : 1077, 955, 936, 945, 952 
		// 3 - 12 : 1739, 1765, 1737, 1731, 1748
		// 1 - 13 : 1035, 1052, 1047, 1041, 1046 (64 MiB)
		// 1 - 14 : 2051, 2037, 2032, 2060, 2038 (128 MiB)
		// 1 - 15 : 4106 (256 MiB)
		// 1 - 16 : 8409 (512 MiB)
		// 1 - 17 : java.lang.OutOfMemoryError: Java heap space
	}

	public static void main(String[] args) {
		
		testOfficialVectors();
		testExtraVectors();
		testPerformance();		
	}
}
