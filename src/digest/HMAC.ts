/**
 * <p>This class implements the HMAC message authentication algorithm,
 * under the {@link Digest} API, using the {@link DigestEngine} class.
 * HMAC is defined in RFC 2104 (also FIPS 198a). This implementation
 * uses an underlying digest algorithm, provided as parameter to the
 * constructor.</p>
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 * </pre>
 *
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

class HMAC extends DigestEngine {

    private dig!: Digest;
	private kipad!:Uint8Array
    private kopad!:Uint8Array;
	private outputLength!:number;
	private tmpOut!:Uint8Array;
    private onlyThis = 0;
	private static zeroPad = new Uint8Array(64);

	/**
	 * Build the object. The provided digest algorithm will be used
	 * internally; it MUST NOT be directly accessed afterwards. The
	 * {@code key} array holds the MAC key; the key is copied
	 * internally, which means that the caller may modify the {@code
	 * key} array afterwards.
	 *
	 * @param dig   the underlying hash function
	 * @param key   the MAC key
     * @param outputLength   the HMAC output length (in bytes)
	 */
	constructor(dig:Digest, key:Uint8Array, outputLength?:number)
	{
        super();
		dig.reset();
		this.dig = dig;
		var B = dig.getBlockLength();
		if (B < 0) {
			/*
			 * Virtual block length: inferred from the key
			 * length, with rounding (used for Fugue-xxx).
			 */
			let n = -B;
			B = n * ((key.length + (n - 1)) / n);
		}
		const keyB = new Uint8Array(B);
		var len = key.length;
		if (len > B) {
			key = dig.digest(key);
			len = key.length;
			if (len > B){
				len = B;
            }
		}
		arraycopy(key, 0, keyB, 0, len);
		/*
		 * Newly created arrays are guaranteed filled with zeroes,
		 * hence the key padding is already done.
		 */
		this.processKey(keyB);

		this.outputLength = -1;
		this.tmpOut = new Uint8Array(dig.getDigestLength());
		this.reset();
        if (outputLength && outputLength < dig.getDigestLength()){
			this.outputLength = outputLength;
        }
	}

	/**
	 * Internal constructor, used for cloning. The key is referenced,
	 * not copied.
	 *
	 * @param dig            the digest
	 * @param kipad          the (internal) ipad key
	 * @param kopad          the (internal) opad key
	 * @param outputLength   the output length, or -1
	 */
	private _HMAC(dig:Digest, kipad:Uint8Array, kopad:Uint8Array, outputLength:number)
	{
		this.dig = dig;
		this.kipad = kipad;
		this.kopad = kopad;
		this.outputLength = outputLength;
		this.tmpOut = new Uint8Array(dig.getDigestLength());
        return this;
	}

	private processKey(keyB:Uint8Array)
	{
		var B = keyB.length;
		this.kipad = new Uint8Array(B);
		this.kopad = new Uint8Array(B);
		for (let i = 0; i < B; i ++) {
			var x = keyB[i];
			this.kipad[i] = (x ^ 0x36);
			this.kopad[i] = (x ^ 0x5C);
		}
	}

	/** @see Digest */
	public copy(): Digest
	{
		const h = this._HMAC(this.dig.copy(), this.kipad, this.kopad, this.outputLength);
		return this.copyState(h);
	}

	/** @see Digest */
	public getDigestLength(): number
	{
		/*
		 * At construction time, outputLength is first set to 0,
		 * which means that this method will return 0, which is
		 * appropriate since at that time "dig" has not yet been
		 * set.
		 */
		return this.outputLength < 0 ? this.dig.getDigestLength() : this.outputLength;
	}

	/** @see Digest */
	public getBlockLength(): number
	{
		/*
		 * Internal block length is not defined for HMAC, which
		 * is not, stricto-sensu, an iterated hash function.
		 * The value 64 should provide correct buffering. Do NOT
		 * change this value without checking doPadding().
		 */
		return 64;
	}

	/** @see DigestEngine */
	protected engineReset()
	{
		this.dig.reset();
		this.dig.update(this.kipad);
	}

	/** @see DigestEngine */
	protected processBlock(data:Uint8Array)
	{
		if (this.onlyThis > 0) {
			this.dig.update(data, 0, this.onlyThis);
			this.onlyThis = 0;
		} else {
			this.dig.update(data);
		}
	}

	/** @see DigestEngine */
	protected doPadding(output:Uint8Array, outputOffset:number)
	{
		/*
		 * This is slightly ugly... we need to get the still
		 * buffered data, but the only way to get it from
		 * DigestEngine is to input some more bytes and wait
		 * for the processBlock() call. We set a variable
		 * with the count of actual data bytes, so that
		 * processBlock() knows what to do.
		 */
		this.onlyThis = this.flush();
		if (this.onlyThis > 0){
			this.update(HMAC.zeroPad, 0, 64 - this.onlyThis);
        }
		var olen = this.tmpOut.length;
		this.dig.digest(this.tmpOut, 0, olen);
		this.dig.update(this.kopad);
		this.dig.update(this.tmpOut);
		this.dig.digest(this.tmpOut, 0, olen);
		if (this.outputLength >= 0){
			olen = this.outputLength;
        }
		arraycopy(this.tmpOut, 0, output, outputOffset, olen);
	}

	/** @see DigestEngine */
	protected doInit()
	{
		/*
		 * Empty: we do not want to do anything here because
		 * it would prevent correct cloning. The initialization
		 * job is done in the constructor.
		 */
	}

	/** @see Digest */
	public toString(): string
	{
		return "HMAC/" + this.dig.toString();
	}
}