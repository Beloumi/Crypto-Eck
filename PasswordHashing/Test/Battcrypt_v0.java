package cologne.eck.dr.op.crypto.password_hashing.test;


/**
 * @author Axel von dem Bruch
 */

/*
 * Test class for Battcrypt
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

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import cologne.eck.dr.op.crypto.password_hashing.Battcrypt_v0;


public class TestBattcrypt_v0 {	
	
	private final static String[][] testVectors = {
	// first three official vectors
	{
		//outlen: 
		"64",
		//password hex:
		"70617373776f7264",// ASCII: "password"
		//salt hex: 
		"73616c74",// ASCII: "salt"
		//t_cost: 0x00000
		"0",
		//m_cost: 
		"0",
		//hash: 
		"e22441865a5405c2bbe84a4d6e025133595042886125989fafcf409493638d660803f13cc0fff9e902b3a017cb5b7bceb52ac404be77828dac531f01a25d17da"
	},
	{
		"32",
		"70617373776f7264",
		"73616c74",
		"0",
		"0",
		"e22441865a5405c2bbe84a4d6e025133595042886125989fafcf409493638d66"
	},
	{
		"64",
		"70617373776f7264",
		"73616c74",
		"1",
		"0",
		"a6ddd44ec442a4efa2b040ecdfe55faba23a868b62f975bab4231ab6055e4012b6a067bab54da6473514d662f3323a22778570a0a7734ac151dd4d1f80c39bbb"
	},
	//last three official vectors:
	{
		"64",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
		"1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
		"2",
		"2",
		"d330d017844f3ba392d98331257d6c2596d16a98b7987b33793b2b5219217200d175aa54a1dd139e412a5b6b8fd73d9110ac125a6a0e94e6191ab71938c14aac"
	}, 
	{
		"64",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d",
		"1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
		"2",
		"2",
		"9fe96ed9fcf43505dd7a461ff465da18af8a8e0d7a23d7686c10ede19cbe7625765e63a99906ee4ff2d18a31cbc626a5ca96f7702b3aa084d149cbd8895e8819"
	},
	{
		"64",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		"1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
		"2",
		"2",
		"959135fbf1e1bd04b8b7a0285c2a295b1c126b395d89974a00d075f5451a2301644f2aaae5de67790b68d06ae4632626494a099dce1f429b457f86cf99ad9752"
	},
	// some vectors from benchmark function of ref. implementation with high memory
	{
		//outlen: 
		"64",
		//password hex:
		"70617373776f7264",// ASCII: "password"
		//salt hex: 
		"73616c74",// ASCII: "salt"
		//t_cost: 0x00000
		"1",
		//m_cost: 
		"8",
		//hash: 
		"83e8d4a20bfb9d3fd7ff1b0077bc48a925ddb7219f2961fcb97588b6cb62a43f4fa2fa0ba77be4a92e9501587a2a5f32de9e7435acfa40aee88475fb7590e87c"
	},
	{
		//outlen: 
		"64",
		//password hex:
		"70617373776f7264",// ASCII: "password"
		//salt hex: 
		"73616c74",// ASCII: "salt"
		//t_cost: 0x00000
		"1",
		//m_cost: 
		"10",
		//hash: 
		"06fded82a2a4feb98b42e2ec250901272b1c251a1272bae765bbdef94f7f0f4eb7845a846a6a0f1e397ea5ada87379df8e3e3913131b497797f966a0b906c758"
	}, 
	{
		//outlen: 
		"64",
		//password hex:
		"70617373776f7264",// ASCII: "password"
		//salt hex: 
		"73616c74",// ASCII: "salt"
		//t_cost: 0x00000
		"1",
		//m_cost: 
		"13",
		//hash: 
		"9bd3867962c3a241637ebb6a46b7af029a1c324badf09bb67d165801a4a80befad7f129e98d6345679800e3bd54649d8046811478fe6ad84960675a7844f8014"
	}
	};
	
	//==============================================
	// HEX STRINGS AND BYTE ARRAYS:
	public final static byte[] hex2bytes(String hexString) {

		byte[] byteArray = new byte[hexString.length() / 2];// 2 Character = 1 Byte
			int len = hexString.length();
			if ( (len & 1) == 1){ // ungerade
				System.err.println("Illegal Argument (Function hexStringToBytes): HexString is not even");
				return byteArray; // return null-Array
			}
			final char [] hexCharArray = hexString.toCharArray ();
			for (int i = 0; i < hexString.length(); i+=2) {
				// 1. char in hex <<4, 2. char in hex
				byteArray[i / 2] = (byte) ((Character.digit (hexCharArray[i], 16) << 4) 
								+ Character.digit (hexCharArray[i + 1], 16));
			}		
			return byteArray;
	}
	private static final String HEXES = "0123456789ABCDEF";
	public static String getHex( byte [] raw ) {
	    final StringBuilder hex = new StringBuilder( 2 * raw.length );
	    for ( final byte b : raw ) {
	        hex.append(HEXES.charAt((b & 0xF0) >> 4))
	            .append(HEXES.charAt((b & 0x0F)));
	    }
	    return hex.toString();
	}


	public static void main(String[] args) {
		
		long start = System.currentTimeMillis(); 

		for (int i = 0; i < testVectors.length -1; i++) {
			
			int outlen = Integer.parseInt(testVectors[i][0]);
			byte[] pwd = hex2bytes(testVectors[i][1]);
			byte[] salt = hex2bytes(testVectors[i][2]);
			int t_cost = Integer.parseInt(testVectors[i][3]);
			int m_cost = Integer.parseInt(testVectors[i][4]);
			
			byte[] out = null;
			Battcrypt_v0 batt = new Battcrypt_v0();
			try {
				out = batt.hashPassword(outlen, 
						pwd, //pwd.length, // password
						salt, //salt.length, 
						t_cost, m_cost);
			} catch (DataLengthException e) {
				e.printStackTrace();
			} catch (IllegalStateException e) {
				e.printStackTrace();
			} catch (InvalidCipherTextException e) {
				e.printStackTrace();
			}
			String result = getHex(out);
			
			if ((result.toUpperCase().equals( testVectors[i][5].toUpperCase()) )){
				System.out.println(i + ": " + m_cost + " m_cost - "+ testVectors[i][1] + "  ok");				
			} else {
				try {
					System.out.println("test vector failed for password " + new String(hex2bytes(testVectors[i][1]), "UTF-8"));
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				System.out.println("expected: \n" + testVectors[i][5].toUpperCase());
				System.out.println("result: \n" + result.toUpperCase() );
			}		

			System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1)+ "\n");//Endpunkt
			start = System.currentTimeMillis(); 
		}
		System.out.println("test end.");
	}
}
