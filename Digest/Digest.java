package cologne.eck.dr.op.crypto.digest;


public interface Digest {
	
	public void update(byte[] message);
	
	public void update(byte b);
	
	public void update(byte[] message, int offset, int len);
	
	public void doFinal(byte[] out, int outOffset);
	
	public void reset();
	
	public String getName();
}
