package cologne.eck.dr.op.crypto.password_hashing.test;


/**
 * @author Axel von dem Bruch
 */

/*
 * Test class for Pomelo v2
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

import cologne.eck.dr.op.crypto.password_hashing.Pomelo_v2;

public class TestPomelo_v2 {
	
	private final static String[][] TEST_VECTORS = {
		// first 5 official vectors:
		{ 
		"0", //m_cost			
		"0", // t_cost
		"16", // inlen
		"16", // saltlen
		"256", // outlen 
		"000102030405060708090a0b0c0d0e0f", //password
		"01030507090b0d0f11131517191b1d1f", // salt
		"105f424523592c4f2d8b9a10a0edc102176c47a077c799cb469f2b1e6143e7778e46716e6ea61b618fe2f840dbc0c2a939a4b479208e0d43fe217126d9dc5df7c4b2dd8b8550d56936b9c5cfa3c28142f09e18b7a785d688f7aff54d478163ba0ba9f561055afe630a9b535edf92278e086e92adb36f915c3bddb5ebab045c5b11aae0200ae079f4023c3387fecd889e27ec5a6f3c0b24b5d3440a276c91c3a575692340b18d6e070ddea96e3f4f5638fb3f6a6d094b59a435a0778cce6b8bcdb63259ad38bfa0cbd07c72191823dfe398fbfcf65c61c1aa3d57d15dadd99e8eb71ff4107e02969cff5427185846d2c6f564d4c8efaf3b1bdefaa6241902da97" // output
		},
		
		{
		"0",
		"0",
		"16",
		"32",
		"256", 
		"000102030405060708090a0b0c0d0e0f",
		"01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f",
		"21fcfdfe3af69fd8d587e4fd4b9d5f020e41375e92fb9846716dc9b6ebaf0b7fa2748f987461d7ec445d11c7d87967e734bde72389b5162f807308a04f877115e8f84adb9d7497b2c670619138b49ab5e4e0f7f3a6a6627d557fcf7046eea95edff1dd55f2ae1d89865cb9fc7130335dfc9ec0b9c44d7e324d508a9bed9b7f2cda712301c34dcf5a75181d187b40049bfe7f88815bfe9fe8180de80beaef9f6a6b804a0bab928e3041a11d62f619384868b4b18ece5aedae28e65e463da6cd9fa22daa36c897cf5493f00ff969c57c9a1c4c350c31108d8bcf982fdd3e40cc63b039ab89e97979fab157a4dc8fbc59b68aa8723ba9046d87b03a8cf05c3a6882"
		},
		
		{
		"0",
		"0",
		"16",
		"48",
		"256", 
		"000102030405060708090a0b0c0d0e0f",
		"01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f41434547494b4d4f51535557595b5d5f",
		"f9bd5424cdd0de56249951c081a0c62c5444d040927826a700e3d4148f54153bab3e00b64fc54ca1bba6fd489642aee9b740e437779be3f61107a451e959a21266783f722a99f0b99e30a23cd9ca7958b2b22a1fcd9d62425c0a5487acd8902a8aa169f581630d0937eacd4ab7168eaa81581071e51c39d0a7158d80e96074e77fcd2969b19720f5d34ce5bd194bfc4b1b426190ec5f8b5f81fd8b587c20b9b33dc7f4fb24129a19a210cb53f693d4d2b99276fc788cd491d94b69782da9d4ac2c0f7f6eb40aca315c1daeb39ba3b943ed7c16644dccb5876557dbc3064351c54d51a7b83b0e8138e1fc8d8535e583d2a47474b6248348970c3257e21ffd081e"
		},

		{
		"0",
		"0",
		"16",
		"64",
		"256", 
		"000102030405060708090a0b0c0d0e0f",
		"01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f41434547494b4d4f51535557595b5d5f61636567696b6d6f71737577797b7d7f",
		"0c17a75e24c6cbeb67afc50c667e1ce4dc1578e97dbce4ceaa6e15307ac256900caaf75a06d49bf4093b3c32500910b64092f4890679dad7823f2f5e9e0a0d68cd74c051909dee0451f0c9c5c237e25a44f454fae758a1bdcacb765973c01c07ecab4fb3bc1c8f5077f14f894226ce77872cd2f166dd261183d478be4191af9ee294ae11a1267b3015840422c5960bfe3cd3cd9d2519936c2fa0b8bb075d5f87568db9db115f30569555d61c0dcdb25bfb26e00cae50de1053ba573ce8a3d5f9804e52746094c0469f9f5ad81d564751b34653d813ad4897a97fb39e5b38d436509e93fb52a23df32d4997f3496d7602dcaf15757e38589498e89a2691c0b862"
		},

		{
		"0",
		"0", 
		"32", 
		"16", 
		"256", 
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"01030507090b0d0f11131517191b1d1f",
		"62da075e8851e9403a065272c271111f9887acd28bc80aea3b0e2532b164a2c2639f4a5758a08035ee0bffab4771f672905acdca629850cde0fe9475b9165d9d96a9b192bd88d56e72d718c63d25d422cd0b045bcb1587f6ebb3537896e22bcc743c7639e24946759e3d32533554f84fde35d1655b6c602c36e24cb13ad0b541064d2ea9993e5f24294d31eba6f7a455b19578dfdd39f537bbde3e101bb9625a51979b190f87fb85a55b30dcc437e6559c8c38c4b1c4a7262219ca7ea4786c654ad6271e64b314332851acb8f58787adad12d3ecfa8e0bbb99d1fd6a7f726a0ddc95c10f968e56a4ff5dccca68bbd3ca86a861151e341ce631f9ac4e2c60de1b"
	},
		
	// last 5 official vectors:
	{
		"3", 
		"3", 
		"240", 
		"64",
		"256", 
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef",
		"01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f41434547494b4d4f51535557595b5d5f61636567696b6d6f71737577797b7d7f",
		"0c2775ca049c0a43930d1b10c76ffb1a6f91166c38927ee82d25ef130bfc6c59154ae5911b645d480262084348d54ef82a2c71bf91076f1c6c143bb0dce79042fba1a3ff3034490484be475c61b9b94aa0d73a2883ea5a10552e75b83bea087f7f4e481b593b2ce63eb0ff8bba69fc2b2de3197663076fb48193ad5b48417495254b37d98031afd50b81178a95108506cf806322bfdeed15169e8840905321f6c76ad49e33f633ba85b082d9826d4b337775a309023e4954670acbb03bcf34547b65aeb58c8e0c75d124f1ad03b7ae2155e192d6b715f8bb8b7283fc39217d2e98ae464808d91f0d68b1e0988e940d8faf24e952d114af4fcad4fae87c6605af"
	},
	{
		"3", 
		"3", 
		"256",  
		"16",
		"256",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"01030507090b0d0f11131517191b1d1f",
		"2adb0b395d1760b73a85600ebe1cff15230cfd2907de7d93d690e21d86a3833b49fe28f1953fdd9f3ec184f5c6e3cf0b74424929a86ff46365e022a3e0f1213df4f8aaadbc1df47fb832688310e3ed262ba1230be650a33a396048eb531b6851644848b87cd566220bbef800af803f4f39886d0c02df3006cbbf85293c76ce1d6d318f0a899134f697ba739727527c7a92807675ec126145c89d2841a8c8a39738170d3ed8a21fe7dfed07157b616b89040e59ceadd41bc7795a4bc44c24c45056874c18de173fbd117c59e8d95adb834206c0bf2df7a001d64aa8b7ec3df257ce95cb540db1ac21d0d834153707536f06396f329a364c058517f368b11c44fa"
	},
	{
		"3", 
		"3", 
		"256",  
		"32",
		"256",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f",
		"b34e60caca3b451efc5e9e403067ed3ae4ed97609930bf9d53e66739b353261be20a5f5979160b1ddbdce6303f18f12fc965c1d48442d77e2790ea1e81cf7e2ffcae79eb38d0ea29fe6e844ea5f535e53999057b785d20307df433502b6519027747591284698292e862e24d8ac6b2dc7df7f76ffc9573ffe0b38fe8d910631fbf90ed633ebfb0e048034b5ea9ab033fbba33163aab29c7196b8fa829cfdeec7470f7866c8eead44d4fdfc74e8c1054e89410ff83978d7953b918396a26ba51c8e41861f5cf9c754e39e31606345d65c058c13caedd8df3fdedd0d0f11827e0888d0d8c7783e1a2d1d22b42ae770c66743a61c0173334e3ea412d2acfa58debe"
	},
	{
		"3", 
		"3", 
		"256",  
		"48",
		"256",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f41434547494b4d4f51535557595b5d5f",
		"6576fd141abdefcca0fad30603c29d86b2b83451249b092eae68647ea72b61bee9e7b5be48e43122c46b91bd38dc9cb87e03047e79effa7523ff57f4e863c143a662505d1bd48b77c8220790c9918a0b9eca98fcd17a9039ea53edfb479a87a504d02646aa884a74ffcc91f1f9902548d864590ba102dd7cffbfe271e0178e8c9a12cc673389544c8717a15860cfd6b4fe2a6a9cf3d1f3288751fac7c0a4d0dbbef7c7994303650a3240d6fb664c915db5703cbd33762af5012c2d2c2fe0cb9a5534dc4a0ee4c5d9e56f6070452fe3aed6c3d855a693b782cf8a99eb6d60157e3e1ffe8fb1060246293cd85012a5f83092db0a4c4bc122d9bebf7cebce0932dc"
	},
	{
		"3", 
		"3", 
		"256",  
		"64",
		"256",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f41434547494b4d4f51535557595b5d5f61636567696b6d6f71737577797b7d7f",
		"1177bd9d6d7b278e0786b06734adf240f964bb2e98ccc8e1ff4746660adfeda8357ec571a1583bf8dc9356fdf33e9eb2a97058913c106dac4093a59572e21e35089e62af8c3373cf9a29475663fdccd330f550c16d30e24650ccc6a46a586c7d07abc2d313a8c740b3124961cffee901c26ca0d9c5f4cfe8a0eaf76ec9e006790d0a0c09f321c367a84d3be8941ec33b0f05a02056de14ac45ec0e171df404763123e6e91c63b90b3e1f1aee8b1a437f808d6ffdf4f95575d4df6e0848a1551823a0e27ae9121866b7a451e70e7a1e3f60edbf3cb807948557b7e682f4e08db3f7a7f6670383f56c1280aa4c9084ca0802d40f2d35eb874b8ce92a84111adb9f"
	}
	};
	
	private final static String[][] EXTRA_VECTORS = {
		// some extra vectors, produced with the reference implementation of Pomelo
		{"password", 
		"saltsaltsaltsalt",
		"128",
		"1", 
		"12", 
		"a9e744f2df27d0ef5abc43f43ed82283a187728d8c69a001e64f01d709990c1c9693b4a791b45d39e0a0bda3ea5c1fa6c58f3d87ac78db19948f754b7df3e48df6a7aeb06dd45245d0bf5f53858bafaefca9f9a54fad3f235af8248e3ff84e32974716593db4b6f1b2946d0f5c27a30ecd7448eb044c426ac32ff7fb59c62df5"
		},	
		{"äöüßÄÖÜ", 
		"saltsaltsaltsaltsal",
		"67",
		"1", 
		"12", 
		"87bb648cbcb6f045345a005b3e02002c9e82d076739bf9d1331ee392c1f99603a8fa45a1c6e2aa79320f42c034e2bddeb05924a052b582c14c9e369f2c660cb072b3da"
		}
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
	public final static byte[] hex2bytes(String hexString) {

		byte[] byteArray = new byte[hexString.length() / 2];// 2 Character = 1 Byte
			int len = hexString.length();
			if ( (len & 1) == 1){ 
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
	
	private final static void testOfficialVectors(){
		
		for (int i = 0; i < TEST_VECTORS.length; i++) {

			int m_cost = Integer.parseInt(TEST_VECTORS[i][0]);
			int t_cost = Integer.parseInt(TEST_VECTORS[i][1]);		
			int inlen = Integer.parseInt(TEST_VECTORS[i][2])  ;
			int saltlen = Integer.parseInt(TEST_VECTORS[i][3])   ;				
			int outlen = Integer.parseInt(TEST_VECTORS[i][4])    ;
			
			byte[] tmpIn = hex2bytes(TEST_VECTORS[i][5]);
			byte[] in = new byte[inlen];
			System.arraycopy(tmpIn,  0,  in,  0,  inlen);
			byte[] tmpSalt = hex2bytes(TEST_VECTORS[i][6]);
			byte[] salt = new byte[saltlen];
			System.arraycopy(tmpSalt,  0, salt,  0,  saltlen);

			Pomelo_v2 pom = new Pomelo_v2();		

			byte[] out = new byte[outlen];
			try {
				out = pom.hashPassword(outlen,  in, salt, t_cost, m_cost);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			
			if (bytes2hex(out).toUpperCase().equals(TEST_VECTORS[i][7].toUpperCase())){
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
			
			Pomelo_v2 pom = new Pomelo_v2();		
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
		
		// tested max. values for t_cost and m_cost
		// recommended max. values are both 25
		// modify t_max and m_max up to your patience limit
		int t_max = 16;
		int m_max = 16;
		
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
		
		byte[] out = null;
		Pomelo_v2 pom = new Pomelo_v2();		
		try {
			out = pom.hashPassword(
				32,  
				pwd, 
				salt, 
				0,  // t_cost
				0);
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}// m_cost 
		
		int t_cost = 0;
		int m_cost = 0;
		
		for (t_cost = 0; t_cost < t_max; t_cost++){
			
			int x_m_cost = m_cost;
			if (t_cost + m_cost < 5){
				x_m_cost = 5 - t_cost;
			}

			try {
				out = pom.hashPassword(32, pwd, salt, t_cost, x_m_cost);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}		
			System.out.println("t_cost: " + t_cost + "  m_cost: " + x_m_cost + "\ntime in ms: " + ((System.currentTimeMillis() - start)/1));//Endpunkt
			start = System.currentTimeMillis(); // start
//			System.out.println(bytes2hex(out).toUpperCase() );
		}
		t_cost = 0;
		for (m_cost = 0; m_cost < m_max; m_cost++){
			
			int x_t_cost = t_cost;
			if (t_cost + m_cost < 5){
				x_t_cost = 5 - m_cost;
			}
			try {
				out = pom.hashPassword(32, pwd, salt, x_t_cost, m_cost);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}		
			System.out.println("t_cost: " + x_t_cost + "  m_cost: " + m_cost + "\ntime in ms: " + ((System.currentTimeMillis() - start)/1));//Endpunkt
			start = System.currentTimeMillis(); // start
//			System.out.println(bytes2hex(out).toUpperCase() );
		}
		
		// time in general is about half of v1
	}

	public static void main(String[] args) {
		
		testOfficialVectors();
		testExtraVectors();
		testPerformance();
	}
}
