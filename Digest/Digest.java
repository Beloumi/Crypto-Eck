package cologne.eck.dr.op.crypto.digest;

/*
 * This interface can be used for round-reduced version
 * of hash function. 
 */

public interface Digest {
	
	public void update(byte[] message);
	
	public void update(byte b);
	
	public void update(byte[] message, int offset, int len);
	
	public void doFinal(byte[] out, int outOffset);
	
	public void reset();
	
	public int getRounds();
	
	public String getName();

	public void setVertexIndex(int vIndex);

}
