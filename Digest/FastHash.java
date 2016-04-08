package cologne.eck.dr.op.crypto.digest;

/*
 * This interface is used for hash functions which are 
 * probably not cryptographically secure, 
 * for example round-reduced hash functions.
 */

public interface FastHash {

	public void hash(int vIndex, 
			byte[] input1, int inIndex1, 
			byte[] input2, int inIndex2, 
			byte[] hash, int outIndex);
	
	public void reset();
	
	public String getName();
	
	public int getOutputSize();
}
