using PrivateBinSharp.Crypto.util;

namespace PrivateBinSharp.Crypto.crypto;

/**
     * super class for all Password Based Encyrption (Pbe) parameter generator classes.
     */
internal abstract class PbeParametersGenerator
{
	protected byte[]? mPassword;
	protected byte[]? mSalt;
	protected int mIterationCount;

	/**
         * base constructor.
         */
	protected PbeParametersGenerator()
	{
	}

	/**
         * initialise the Pbe generator.
         *
         * @param password the password converted into bytes (see below).
         * @param salt the salt to be mixed with the password.
         * @param iterationCount the number of iterations the "mixing" function
         * is to be applied for.
         */
	public virtual void Init(
		byte[] password,
		byte[] salt,
		int iterationCount)
	{
		if (password == null)
			throw new ArgumentNullException("password");
		if (salt == null)
			throw new ArgumentNullException("salt");

		mPassword = Arrays.Clone(password);
		mSalt = Arrays.Clone(salt);
		mIterationCount = iterationCount;
	}

	public virtual void Init(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterationCount)
	{
		mPassword = password.ToArray();
		mSalt = salt.ToArray();
		mIterationCount = iterationCount;
	}

	public virtual byte[] Password
	{
		get { return Arrays.Clone(mPassword!)!; }
	}

	public virtual byte[] Salt
	{
		get { return Arrays.Clone(mSalt!)!; }
	}

	/**
         * return the iteration count.
         *
         * @return the iteration count.
         */
	public virtual int IterationCount
	{
		get { return mIterationCount; }
	}

	public abstract ICipherParameters GenerateDerivedParameters(string algorithm, int keySize);
	public abstract ICipherParameters GenerateDerivedParameters(string algorithm, int keySize, int ivSize);

	/**
         * Generate derived parameters for a key of length keySize, specifically
         * for use with a MAC.
         *
         * @param keySize the length, in bits, of the key required.
         * @return a parameters object representing a key.
         */
	public abstract ICipherParameters GenerateDerivedMacParameters(int keySize);

}
