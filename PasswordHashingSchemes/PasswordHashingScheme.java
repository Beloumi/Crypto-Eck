package cologne.eck.dr.op.crypto.password_hashing;

/**
 * Interface for Password Hashing Schemes. 
 * This is based on the standard function of the Password Hashing Competition,
 * but does not completely corresponds to the (C-style) prototype.
 */
public interface PasswordHashingScheme {

    /**
     * Return the name of the password hashing scheme
     *
     * @return 
	 * 			the name of the password hashing scheme
     */
    public String getAlgorithmName();

    /**
     * Calculate the password hash. This can be used for key derivation,
     * authentication or any other purpose. If these modes differ, this 
     * must be determined by the varArgs parameter. 
     * 
     * @param 	outlen
     * 					required length in byte for the password hash
     * @param 	in 
	 *					the password to be hashed
     * @param 	salt
     * 					a salt value
     * @param 	t_cost 
	 *					the time cost parameter
     * @param 	m_cost
     * 					the memory cost parameter
     * @param 	varArgs
     * 					additional parameters, not used by all schemes
     * 
     * @return the password hash
     * 
     * @throws Exception 
     * 					
     */
    public byte[] hashPassword(int outlen, byte[] in, byte[] salt, int t_cost, int m_cost, Object ... varArgs) throws Exception; 

}
