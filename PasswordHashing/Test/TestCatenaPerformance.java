package cologne.eck.dr.op.crypto.password_hashing.test;

import cologne.eck.dr.op.crypto.digest.Blake2b;
import cologne.eck.dr.op.crypto.digest.Catena_Blake2b_1;
import cologne.eck.dr.op.crypto.digest.SHA512Digest;
import cologne.eck.dr.op.crypto.password_hashing.Catena;
import cologne.eck.dr.op.crypto.password_hashing.CatenaBRG;
import cologne.eck.dr.op.crypto.password_hashing.CatenaDBG;

import tools.Converter;


public class TestCatenaPerformance {
	
	//=== Catena parameters and variables ===
	private static final byte[] PSW = "password".getBytes();
	private static final byte[] SALT = "salt".getBytes();
	private static final byte[] DATA = "data".getBytes();


	
	// recommended parameters
	private static final int DRAGONFLY_GARLIC = 21;
	private static final int DRAGONFLY_FULL_GARLIC = 18;
	private static final int DRAGONFLY_LAMBDA = 2;
	
	private static final int BUTTERFLY_GARLIC = 16;
	private static final int BUTTERFLY_FULL_GARLIC = 14;
	private static final int BUTTERFLY_LAMBDA = 4;

	private static final int DRAGONFLY_FULL_KDF_GARLIC = 22;
	private static final int DRAGONFLY_FULL_KDF_LAMBDA = 2;
	
	private static final int BUTTERFLY_FULL_KDF_GARLIC = 17;
	private static final int BUTTERFLY_FULL_KDF_LAMBDA = 4;


	public TestCatenaPerformance() {
	}


	public static void main(String[] args) {
		
		System.out.println(
				"Java version: " + System.getProperty("java.version") + "\n" +
				"Java VM: " + System.getProperty("java.vm.name") + "\n" +
				"Java VM version: " + System.getProperty("java.vm.version") + "\n" + 
				 "Operating system architecture: "  + System.getProperty("os.arch") + "\n" +
				"Operating system name: "  + System.getProperty("os.name") + "\n" +
				"Operating system version: " + System.getProperty("os.version") + "\n" + 
				"Number of cores: " + Runtime.getRuntime().availableProcessors() + "\n"
				);


		
		long start = System.currentTimeMillis(); // start timer
		
		System.out.println("\n===== Blake2b =====");
		
		byte[] hash = new byte[64];
		Catena cat = new CatenaBRG(true);
		cat.hashPassword( PSW, SALT, DATA, 
				DRAGONFLY_LAMBDA,
				DRAGONFLY_GARLIC,
				DRAGONFLY_GARLIC,
				 hash);
		System.out.println("\nDragonfly, garlic " + DRAGONFLY_GARLIC);
		System.out.println(Converter.getHex(hash));
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		start = System.currentTimeMillis(); // start timer

		
		cat = new CatenaBRG(true);
		cat.hashPassword( PSW, SALT, DATA, 
				DRAGONFLY_LAMBDA,
				DRAGONFLY_FULL_GARLIC,
				DRAGONFLY_FULL_GARLIC,
				 hash);
		System.out.println("\nDragonfly, garlic " + DRAGONFLY_FULL_GARLIC);
		System.out.println(Converter.getHex(hash));
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		start = System.currentTimeMillis(); // start timer
		
		cat = new CatenaBRG(false);
		cat.hashPassword( PSW, SALT, DATA, 
				DRAGONFLY_LAMBDA,
				DRAGONFLY_FULL_GARLIC,
				DRAGONFLY_FULL_GARLIC,
				 hash);
		System.out.println("\nDragonfly FULL, garlic " + DRAGONFLY_FULL_GARLIC);
		System.out.println(Converter.getHex(hash));
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		start = System.currentTimeMillis(); // start timer
		
		cat = new CatenaBRG(false);
		cat.hashPassword( PSW, SALT, DATA, 
				DRAGONFLY_LAMBDA,
				21,
				21,
				 hash);
		System.out.println("\nDragonfly FULL, garlic 21");
		System.out.println(Converter.getHex(hash));
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		start = System.currentTimeMillis(); // start timer
		
		cat = new CatenaDBG(true);
		cat.hashPassword( PSW, SALT, DATA, 
				BUTTERFLY_LAMBDA,
				BUTTERFLY_GARLIC,
				BUTTERFLY_GARLIC,
				 hash);
		System.out.println("\nBUTTERFLY, garlic " + BUTTERFLY_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		start = System.currentTimeMillis(); // start timer
		
		cat = new CatenaDBG(true);
		cat.hashPassword( PSW, SALT, DATA, 
				BUTTERFLY_LAMBDA,
				BUTTERFLY_FULL_GARLIC,
				BUTTERFLY_FULL_GARLIC,
				 hash);
		System.out.println("\nBUTTERFLY, garlic " + BUTTERFLY_FULL_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		start = System.currentTimeMillis(); // start timer		
		
		cat = new CatenaDBG(false);
		cat.hashPassword( PSW, SALT, DATA, 
				BUTTERFLY_LAMBDA,
				BUTTERFLY_FULL_GARLIC,
				BUTTERFLY_FULL_GARLIC,
				 hash);
		System.out.println("\nBUTTERFLY FULL, garlic " + BUTTERFLY_FULL_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		start = System.currentTimeMillis(); // start timer

		
		System.out.println("\n===== SHA512 =====");
		
		
		cat = new CatenaBRG(false);
		cat.setDigest( new SHA512Digest());
		cat.setReducedDigest( null);
		cat.hashPassword( PSW, SALT, DATA, 
				DRAGONFLY_LAMBDA,
				DRAGONFLY_FULL_GARLIC,
				DRAGONFLY_FULL_GARLIC,
				 hash);
		System.out.println("\nSHA512, Dragonfly FULL, garlic " + DRAGONFLY_FULL_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		start = System.currentTimeMillis(); // start timer
		
		cat = new CatenaDBG(false);
		cat.setDigest( new SHA512Digest());
		cat.setReducedDigest( null);
		cat.hashPassword( PSW, SALT, DATA, 
				BUTTERFLY_LAMBDA,
				BUTTERFLY_FULL_GARLIC,
				BUTTERFLY_FULL_GARLIC,
				 hash);
		System.out.println("\nSHA512, BUTTERFLY FULL, garlic " + BUTTERFLY_FULL_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		start = System.currentTimeMillis(); // start timer

		
		System.out.println("\n===== key derivation =====");
		
		byte[] key = new byte[64];
		cat = new CatenaBRG(false);
		cat.setDigest( new Blake2b());
		cat.setReducedDigest(null);
		cat.deriveKey(PSW,   
			       SALT,  
			       DATA,  
			       DRAGONFLY_FULL_KDF_LAMBDA, DRAGONFLY_FULL_KDF_GARLIC,
			       DRAGONFLY_FULL_KDF_GARLIC,
			       0, key);
		System.out.println("\nDragonfly KDF with Blake2b, garlic " + DRAGONFLY_FULL_KDF_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		
		start = System.currentTimeMillis(); // start timer
		cat = new CatenaBRG(false);
		cat.setDigest( new Blake2b());
		cat.setReducedDigest(new Catena_Blake2b_1());
		cat.deriveKey(PSW,   
			       SALT,  
			       DATA,  
			       DRAGONFLY_FULL_KDF_LAMBDA, DRAGONFLY_FULL_KDF_GARLIC,
			       DRAGONFLY_FULL_KDF_GARLIC,
			       0, key);
		System.out.println("\nDragonfly KDF with Blake2b and H', garlic " + DRAGONFLY_FULL_KDF_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		
		start = System.currentTimeMillis(); // start timer
		cat = new CatenaBRG(false);
		cat.setDigest(new SHA512Digest());
		cat.setReducedDigest(null);
		cat.deriveKey(PSW,   
			       SALT,  
			       DATA,  
			       DRAGONFLY_FULL_KDF_LAMBDA, DRAGONFLY_FULL_KDF_GARLIC,
			       DRAGONFLY_FULL_KDF_GARLIC,
			       0, key);
		System.out.println("\nDragonfly KDF with SHA512, garlic "+ DRAGONFLY_FULL_KDF_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		
		
		cat = new CatenaDBG(false);
		cat.setDigest( new Blake2b());
		cat.setReducedDigest(null);
		cat.deriveKey(PSW,   
			       SALT,  
			       DATA,  
			       BUTTERFLY_FULL_KDF_LAMBDA, BUTTERFLY_FULL_KDF_GARLIC,
			       BUTTERFLY_FULL_KDF_GARLIC,
			       0, key);
		System.out.println("\nBUTTERFLY KDF with Blake2b, garlic " + BUTTERFLY_FULL_KDF_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		
		start = System.currentTimeMillis(); // start timer
		cat = new CatenaDBG(false);
		cat.setDigest( new Blake2b());
		cat.setReducedDigest(new Catena_Blake2b_1());
		cat.deriveKey(PSW,   
			       SALT,  
			       DATA,  
			       BUTTERFLY_FULL_KDF_LAMBDA, BUTTERFLY_FULL_KDF_GARLIC,
			       BUTTERFLY_FULL_KDF_GARLIC,
			       0, key);
		System.out.println("\nButterfly KDF with Blake2b and H', garlic " + BUTTERFLY_FULL_KDF_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));
		
		start = System.currentTimeMillis(); // start timer
		cat = new CatenaDBG(false);
		cat.setDigest(new SHA512Digest());
		cat.setReducedDigest(null);
		cat.deriveKey(PSW,   
			       SALT,  
			       DATA,  
			       BUTTERFLY_FULL_KDF_LAMBDA, BUTTERFLY_FULL_KDF_GARLIC,
			       BUTTERFLY_FULL_KDF_GARLIC,
			       0, key);
		System.out.println("\nDragonfly KDF with SHA512, garlic " + BUTTERFLY_FULL_KDF_GARLIC);
		System.out.println("time in ms: " + ((System.currentTimeMillis() - start)/1));		
	}
}
