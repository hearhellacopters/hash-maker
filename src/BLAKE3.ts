const BLAKE3_VERSION_STRING = "1.8.2";
const BLAKE3_KEY_LEN = 32;
const BLAKE3_OUT_LEN = 32;
const BLAKE3_BLOCK_LEN = 64;
const BLAKE3_CHUNK_LEN = 1024;
const BLAKE3_MAX_DEPTH = 54;
const MAX_SIMD_DEGREE = 1;
const MAX_SIMD_DEGREE_OR_2 = (MAX_SIMD_DEGREE > 2 ? MAX_SIMD_DEGREE : 2);

const CHUNK_START = 1 << 0;
const CHUNK_END = 1 << 1;
const PARENT = 1 << 2;
const ROOT = 1 << 3;
const KEYED_HASH = 1 << 4;
const DERIVE_KEY_CONTEXT = 1 << 5;
const DERIVE_KEY_MATERIAL = 1 << 6;

var IV:Uint32Array;

var MSG_SCHEDULE:Uint8Array[];

function blake3_simd_degree() { return 1; };

interface blake3_chunk_state {
    /**
     * uint32_t[8]
     */
    cv: Uint32Array;
    chunk_counter: bigint;
    /**
     * uint8_t[BLAKE3_BLOCK_LEN]
     */
    buf: Uint8Array;
    buf_len: number;
    blocks_compressed: number;
    flags: number;
};

interface blake3_hasher {
    /**
     * uint32_t[8]
     */
    key: Uint32Array;
    chunk: blake3_chunk_state;
    cv_stack_len: number;
    /** 
     * uint8_t[(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN]
     *
     * The stack size is MAX_DEPTH + 1 because we do lazy merging. For example,
     * with 7 chunks, we have 3 entries in the stack. Adding an 8th chunk
     * requires a 4th entry, rather than merging everything down to 1, because we
     * don't know whether more input is coming. This is different from how the
     * reference implementation does things.
     */
    cv_stack: Uint8Array;
};

function highest_one(x: bigint) {
    return __builtin_popcountll(x);;
};

function __builtin_popcountll(value: bigint) {
    const mask = (BigInt(1) << BigInt(64)) - BigInt(1);
    let v = value & mask;
    let count = 0;

    while (v !== BigInt(0)) {
        v &= v - BigInt(1); // Clear the rightmost set bit
        count++;
    }

    return count;
};

function round_down_to_power_of_2(x: number) {
    return 1 << highest_one(BigInt(x | 1));
};

function counter_low(counter: bigint) {
    return Number(counter) >>> 0;
};

function counter_high(counter: bigint) {
    return Number(counter >> BigInt(32));
};

function load32(src: Uint8Array) {
    const p = src;
    return (((p[0]) << 0) | ((p[1]) << 8) |
        ((p[2]) << 16) | ((p[3]) << 24)) >>> 0;
};

function rotr32(w: number, c: number) {
    return (w >>> c) ^ (w << (32 - c));
};

function popcnt(x: bigint) {
    return __builtin_popcountll(x);
};

function g(
    state: Uint32Array, a: number, b: number, c: number, d: number,
    x: number /*uint32_t*/, y: number /*uint32_t*/
) {
    state[a] = state[a] + state[b] + x;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + y;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
};

function round_fn(
    state: Uint32Array, msg: Uint32Array, round: number
) {
    // Select the message schedule based on the round.
    const schedule = MSG_SCHEDULE[round];

    // Mix the columns.
    g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
    g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
    g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
    g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

    // Mix the rows.
    g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
    g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
    g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
    g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
};

function compress_pre(
    state: Uint32Array /*uint32_t[16]*/, cv: Uint32Array /*uint32_t[8]*/, block: Uint8Array /*uint8_t[BLAKE3_BLOCK_LEN] 64*/,
    block_len: number, counter: bigint, flags: number, block_offset: number = 0
) {
    const block_words = new Uint32Array(16);

    block_words[0] = load32(block.subarray(4 * 0));
    block_words[1] = load32(block.subarray(4 * 1));
    block_words[2] = load32(block.subarray(4 * 2));
    block_words[3] = load32(block.subarray(4 * 3));
    block_words[4] = load32(block.subarray(4 * 4));
    block_words[5] = load32(block.subarray(4 * 5));
    block_words[6] = load32(block.subarray(4 * 6));
    block_words[7] = load32(block.subarray(4 * 7));
    block_words[8] = load32(block.subarray(4 * 8));
    block_words[9] = load32(block.subarray(4 * 9));
    block_words[10] = load32(block.subarray(4 * 10));
    block_words[11] = load32(block.subarray(4 * 11));
    block_words[12] = load32(block.subarray(4 * 12));
    block_words[13] = load32(block.subarray(4 * 13));
    block_words[14] = load32(block.subarray(4 * 14));
    block_words[15] = load32(block.subarray(4 * 15));

    state[0] = cv[0];
    state[1] = cv[1];
    state[2] = cv[2];
    state[3] = cv[3];
    state[4] = cv[4];
    state[5] = cv[5];
    state[6] = cv[6];
    state[7] = cv[7];
    state[8] = IV[0];
    state[9] = IV[1];
    state[10] = IV[2];
    state[11] = IV[3];
    state[12] = counter_low(counter);
    state[13] = counter_high(counter);
    state[14] = block_len;
    state[15] = flags;

    round_fn(state, block_words, 0);
    round_fn(state, block_words, 1);
    round_fn(state, block_words, 2);
    round_fn(state, block_words, 3);
    round_fn(state, block_words, 4);
    round_fn(state, block_words, 5);
    round_fn(state, block_words, 6);
};

function memcpy(dst: Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
    src: Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
    dstOffset: number = 0,
    srcOffset: number = 0,
    size: number) {
    // Validate inputs
    const srcbyteLength = src.byteLength;
    if (srcOffset + size > src.byteLength) {
        throw new Error(`memcpy${size}: Source buffer too small, ${srcbyteLength} of ${srcOffset + size}`);
    }
    const dstbyteLength = dst.byteLength;
    if (dstOffset + size > dstbyteLength) {
        throw new Error(`memcpy${size}: Destination buffer too small, ${dstbyteLength} of ${dstOffset + size}`);
    }

    // Method 1: Use Uint8Array views for byte-level copying (most portable)
    const dstView = new Uint8Array(dst.buffer, dst.byteOffset + dstOffset, size);
    const srcView = new Uint8Array(src.buffer, src.byteOffset + srcOffset, size);

    dstView.set(srcView);
};

function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

function store32(
    dst: Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
    w: number,
    dstOffset: number = 0) {
    const dstbyteLength = dst.byteLength;
    if (dstOffset + 4 > dstbyteLength) {
        throw new Error(`store32: Destination buffer too small, ${dstbyteLength} of ${dstOffset + 4}`);
    }
    const dstView = new Uint32Array(dst.buffer, dst.byteOffset + dstOffset * dst.BYTES_PER_ELEMENT, 1);

    dstView[dstOffset / 4] = w;
};

function memset(
    dst: Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
    value: number,
    length = 0,
) {
    for (let i = 0; i < length; i++) {
        dst[i] = value;
    }
};

function blake3_compress_xof(cv: Uint32Array /*uint32_t[8]*/,
    block: Uint8Array /*uint8_t[BLAKE3_BLOCK_LEN]*/,
    block_len: number, counter: bigint, flags: number,
    out: Uint8Array /*uint8_t[64]*/) {

    blake3_compress_xof_portable(cv, block, block_len, counter, flags, out);
};

function blake3_compress_in_place(cv: Uint32Array /*uint32_t[8]*/,
    block: Uint8Array /*uint8_t[BLAKE3_BLOCK_LEN]*/,
    block_len: number, counter: bigint,
    flags: number, block_offset: number) {
    blake3_compress_in_place_portable(cv, block, block_len, counter, flags, block_offset);
};

function blake3_xof_many(cv: Uint32Array /*uint32_t[8]*/,
    block: Uint8Array /*uint8_t[BLAKE3_BLOCK_LEN]*/,
    block_len: number, counter: bigint, flags: number,
    out: Uint8Array /*uint8_t[64]*/, outblocks: number) {
    if (outblocks == 0) {
        // The current assembly implementation always outputs at least 1 block.
        return;
    }
    for (let i = 0; i < outblocks; ++i) {
        blake3_compress_xof(cv, block, block_len, counter + BigInt(i), flags, out.subarray(64 * i));
    }
};

function blake3_hash_many(inputs: Uint8Array, num_inputs: number,
    blocks: number, key: Uint32Array, counter: bigint,
    increment_counter: boolean, flags: number,
    flags_start: number, flags_end: number, out: Uint8Array) {
    blake3_hash_many_portable(inputs, num_inputs, blocks, key, counter,
        increment_counter, flags, flags_start, flags_end,
        out);
};


// blake3.c

function blake3_version() {
    return BLAKE3_VERSION_STRING;
};

function chunk_state_init(self: blake3_chunk_state, key: Uint32Array /*uint32_t[8]*/, flags: number) {
    memcpy(self.cv, key, 0, 0, BLAKE3_KEY_LEN);
    self.chunk_counter = BigInt(0);
    memset(self.buf, 0, BLAKE3_KEY_LEN);
    self.buf_len = 0;
    self.blocks_compressed = 0;
    self.flags = flags;
};

function chunk_state_reset(
    self: blake3_chunk_state, key: Uint32Array /*uint32_t[8]*/, chunk_counter: bigint
) {
    memcpy(self.cv, key, 0, 0, BLAKE3_KEY_LEN);
    self.chunk_counter = chunk_counter;
    self.blocks_compressed = 0;
    memset(self.buf, 0, BLAKE3_KEY_LEN);
    self.buf_len = 0;
};

function chunk_state_len(self: blake3_chunk_state) {
    return (BLAKE3_BLOCK_LEN * self.blocks_compressed) + (self.buf_len);
};

function chunk_state_fill_buf(
    self: blake3_chunk_state, input: Uint8Array, input_len: number, input_offset: number
) {
    var take = BLAKE3_BLOCK_LEN - (self.buf_len);
    if (take > input_len) {
        take = input_len;
    }

    //uint8_t *dest = self->buf + ((size_t)self->buf_len);
    //memcpy(dest, input, take);
    const dest = self.buf.subarray(self.buf_len);
    memcpy(dest, input, self.buf_len, input_offset, take);
    self.buf_len += take;
    return take;
};

function chunk_state_maybe_start_flag(self: blake3_chunk_state) {
    if (self.blocks_compressed == 0) {
        return CHUNK_START;
    } else {
        return 0;
    }
};

interface output_t {
    /**
     * uint32_t[8];
     **/
    input_cv: Uint32Array;
    counter: bigint;
    /**
     *uint8_t[BLAKE3_BLOCK_LEN];
     */
    block: Uint8Array;
    block_len: number;
    flags: number;
};

function make_output(
    input_cv: Uint32Array /*uint32_t[8]*/, block: Uint8Array /*uint8_t[BLAKE3_BLOCK_LEN]*/,
    block_len: number, counter: bigint, flags: number
) {
    const ret: output_t = {
        input_cv: new Uint32Array(8),
        block: new Uint8Array(BLAKE3_BLOCK_LEN),
        block_len: 0,
        counter: BigInt(0),
        flags: 0,
    };
    memcpy(ret.input_cv, input_cv, 0, 0, 32);
    memcpy(ret.block, block, 0, 0, BLAKE3_BLOCK_LEN);
    ret.block_len = block_len;
    ret.counter = counter;
    ret.flags = flags;
    return ret;
};

function output_chaining_value(self: output_t, cv: Uint8Array /*uint8_t[32]*/, cv_offset = 0) {
    const cv_words = new Uint32Array(8);
    memcpy(cv_words, self.input_cv, 0, 0, cv_offset);
    blake3_compress_in_place_portable(
        cv_words, self.block, self.block_len, self.counter, self.flags, 0
    );
    store_cv_words(cv, cv_words);
};

function output_root_bytes(
    self: output_t, seek: bigint, out: Uint8Array, out_len: number
) {
    if (out_len == 0) {
        return;
    }
    var output_block_counter = BigInt(seek / BigInt(64));
    var offset_within_block = Number(seek % BigInt(64));
    const wide_buf = new Uint8Array(64);
    var out_loc = 0;
    if (offset_within_block) {
        blake3_compress_xof(self.input_cv, self.block, self.block_len, output_block_counter, self.flags | ROOT, wide_buf);
        const available_bytes = 64 - offset_within_block;
        const bytes = out_len > available_bytes ? available_bytes : out_len;
        memcpy(out, wide_buf, out_loc, offset_within_block, bytes);
        //out += bytes;
        out_loc += bytes;
        out_len -= bytes;
        output_block_counter += BigInt(1);
    }
    const check = new Uint32Array(1);
    check[0] = out_len / 64;
    if (check[0]) {
        blake3_xof_many(self.input_cv, self.block, self.block_len, output_block_counter, self.flags | ROOT, out, check[0]);
    }
    output_block_counter += BigInt(out_len) / BigInt(64);
    //out += out_len & -64;
    out_loc += out_len & -64;
    out_len -= out_len & -64;
    if (out_len) {
        blake3_compress_xof(self.input_cv, self.block, self.block_len, output_block_counter, self.flags | ROOT, wide_buf);
        memcpy(out, wide_buf, out_loc, 0, out_len);
    }
};

function chunk_state_update(
    self: blake3_chunk_state, input: Uint8Array, input_len: number, input_offset = 0
) {
    var inOff = input_offset;
    if (self.buf_len > 0) {
        var take = chunk_state_fill_buf(self, input, input_len, inOff);
        inOff += take;
        //input += take;
        input_len -= take;
        if (input_len > 0) {
            blake3_compress_in_place(
                self.cv, self.buf, BLAKE3_BLOCK_LEN, self.chunk_counter,
                self.flags | chunk_state_maybe_start_flag(self), 0
            );
            self.blocks_compressed += 1;
            self.buf_len = 0;
            memset(self.buf, 0, BLAKE3_BLOCK_LEN);
        }
    }

    while (input_len > BLAKE3_BLOCK_LEN) {
        blake3_compress_in_place(
            self.cv, input, BLAKE3_BLOCK_LEN, self.chunk_counter,
            self.flags | chunk_state_maybe_start_flag(self), inOff
        );
        self.blocks_compressed += 1;
        inOff += BLAKE3_BLOCK_LEN;
        //input += BLAKE3_BLOCK_LEN;
        input_len -= BLAKE3_BLOCK_LEN;
    }

    chunk_state_fill_buf(self, input, input_len, inOff);
};

function chunk_state_output(self: blake3_chunk_state) {
    var block_flags = self.flags | chunk_state_maybe_start_flag(self) | CHUNK_END;

    return make_output(self.cv, self.buf, self.buf_len, self.chunk_counter, block_flags);
};

function parent_output(
    block: Uint8Array /*uint8_t[BLAKE3_BLOCK_LEN]*/, key: Uint32Array /*uint32_t[8]*/, flags: number
) {
    return make_output(key, block, BLAKE3_BLOCK_LEN, BigInt(0), flags | PARENT);
};

function left_subtree_len(input_len: number) {
    // Subtract 1 to reserve at least one byte for the right side. input_len
    // should always be greater than BLAKE3_CHUNK_LEN.
    var full_chunks = (input_len - 1) / BLAKE3_CHUNK_LEN;
    return round_down_to_power_of_2(full_chunks) * BLAKE3_CHUNK_LEN;
};

function compress_chunks_parallel(
    input: Uint8Array, input_len: number, key: Uint32Array /*uint32_t[8]*/,
    chunk_counter: bigint, flags: number, out: Uint8Array, input_offset = 0
) {
    const chunks_array = new Uint8Array(MAX_SIMD_DEGREE);
    var input_position = 0;
    var chunks_array_len = 0;
    while (input_len - input_position >= BLAKE3_CHUNK_LEN) {
        chunks_array[chunks_array_len] = input[input_position + input_offset];
        input_position += BLAKE3_CHUNK_LEN;
        chunks_array_len += 1;
    }

    blake3_hash_many_portable(
        chunks_array, chunks_array_len, BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, key,
        chunk_counter, true, flags, CHUNK_START, CHUNK_END, out
    );

    // Hash the remaining partial chunk, if there is one. Note that the empty
    // chunk (meaning the empty message) is a different codepath.
    if (input_len > input_position) {
        var counter = chunk_counter + BigInt(chunks_array_len);
        var chunk_state: blake3_chunk_state = {
            cv: new Uint32Array(8),
            chunk_counter: BigInt(0),
            buf: new Uint8Array(BLAKE3_BLOCK_LEN),
            buf_len: 0,
            blocks_compressed: 0,
            flags: 0,
        };
        chunk_state_init(chunk_state, key, flags);
        chunk_state.chunk_counter = counter;
        chunk_state_update(
            chunk_state, input, input_len - input_position, input_position + input_offset,
        );
        var output = chunk_state_output(chunk_state);
        output_chaining_value(output, out, chunks_array_len * BLAKE3_OUT_LEN);
        return chunks_array_len + 1;
    } else {
        return chunks_array_len;
    }
};

function compress_parents_parallel(
    child_chaining_values: Uint8Array, num_chaining_values: number,
    key: Uint32Array /*uint32_t[8]*/, flags: number, out: Uint8Array
) {
    const parents_array = new Uint8Array(MAX_SIMD_DEGREE_OR_2);
    var parents_array_len = 0;

    while (num_chaining_values - (2 * parents_array_len) >= 2) {
        parents_array[parents_array_len] =
            child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN];
        parents_array_len += 1;
    }

    blake3_hash_many_portable(parents_array, parents_array_len, 1, key,
        BigInt(0),  // Parents always use counter 0.
        false, flags | PARENT,
        0,  // Parents have no start flags.
        0,  // Parents have no end flags.
        out);

    // If there's an odd child left over, it becomes an output.
    if (num_chaining_values > 2 * parents_array_len) {
        memcpy(
            out,
            child_chaining_values,
            parents_array_len * BLAKE3_OUT_LEN,
            2 * parents_array_len * BLAKE3_OUT_LEN,
            BLAKE3_OUT_LEN
        );
        return parents_array_len + 1;
    } else {
        return parents_array_len;
    }
};

function blake3_compress_subtree_wide(
    input: Uint8Array, input_len: number, key: Uint32Array /*uint32_t[8]*/,
    chunk_counter: bigint, flags: number, out: Uint8Array, input_offset = 0
): number {
    // Note that the single chunk case does *not* bump the SIMD degree up to 2
    // when it is 1. If this implementation adds multi-threading in the future,
    // this gives us the option of multi-threading even the 2-chunk case, which
    // can help performance on smaller platforms.
    if (input_len <= blake3_simd_degree() * BLAKE3_CHUNK_LEN) {
        return compress_chunks_parallel(input, input_len, key, chunk_counter, flags, out);
    }

    // With more than simd_degree chunks, we need to recurse. Start by dividing
    // the input into left and right subtrees. (Note that this is only optimal
    // as long as the SIMD degree is a power of 2. If we ever get a SIMD degree
    // of 3 or something, we'll need a more complicated strategy.)
    var left_input_len = left_subtree_len(input_len);
    var right_input_len = input_len - left_input_len;
    const right_input = input.subarray(input_offset + left_input_len);
    const right_chunk_counter = chunk_counter + BigInt(left_input_len / BLAKE3_CHUNK_LEN);

    // Make space for the child outputs. Here we use MAX_SIMD_DEGREE_OR_2 to
    // account for the special case of returning 2 outputs when the SIMD degree
    // is 1.
    const cv_array = new Uint8Array(2 * MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN);
    var degree = blake3_simd_degree();
    if (left_input_len > BLAKE3_CHUNK_LEN && degree == 1) {
        // The special case: We always use a degree of at least two, to make
        // sure there are two outputs. Except, as noted above, at the chunk
        // level, where we allow degree=1. (Note that the 1-chunk-input case is
        // a different codepath.)
        degree = 2;
    }

    const right_cvs = cv_array.subarray(degree * BLAKE3_OUT_LEN);

    // Recurse!
    var left_n = -1;
    var right_n = -1;

    var left_n = blake3_compress_subtree_wide(input, left_input_len, key, chunk_counter, flags, cv_array);
    var right_n = blake3_compress_subtree_wide(right_input, right_input_len, key, right_chunk_counter, flags, right_cvs);

    // The special case again. If simd_degree=1, then we'll have left_n=1 and
    // right_n=1. Rather than compressing them into a single output, return
    // them directly, to make sure we always have at least two outputs.
    if (left_n == 1) {
        memcpy(out, cv_array, 0, 0, 2 * BLAKE3_OUT_LEN);
        return 2;
    }

    // Otherwise, do one layer of parent node compression.
    var num_chaining_values = left_n + right_n;
    return compress_parents_parallel(cv_array, num_chaining_values, key, flags, out);
};

function compress_subtree_to_parent_node(
    input: Uint8Array, input_len: number, key: Uint32Array /*uint32_t[8]*/,
    chunk_counter: bigint, flags: number, out: Uint8Array, input_offset: number = 0 /*uint8_t[2 * BLAKE3_OUT_LEN]*/
) {
    const cv_array = new Uint8Array(MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN);
    var num_cvs = blake3_compress_subtree_wide(input, input_len, key, chunk_counter, flags, cv_array, input_offset);

    // If MAX_SIMD_DEGREE is greater than 2 and there's enough input,
    // compress_subtree_wide() returns more than 2 chaining values. Condense
    // them into 2 by forming parent nodes repeatedly.
    const out_array = new Uint8Array(MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN / 2);

    while (num_cvs > 2) {
        num_cvs = compress_parents_parallel(cv_array, num_cvs, key, flags, out_array);
        memcpy(cv_array, out_array, 0, 0, 32);
    }

    memcpy(out, cv_array, 0, 0, 2 * BLAKE3_OUT_LEN);
};

function hasher_init_base(self: blake3_hasher, key: Uint32Array /*uint32_t[8]*/, flags: number) {
    memcpy(self.key, key, 0, 0, BLAKE3_KEY_LEN);
    chunk_state_init(self.chunk, key, flags);
    self.cv_stack_len = 0;
    return self;
};

function blake3_hasher_init(self: blake3_hasher) {
    return hasher_init_base(self, IV, 0);
};

function blake3_hasher_init_keyed(self: blake3_hasher, key: Uint8Array /*uint8_t[BLAKE3_KEY_LEN]*/) {
    const key_words = new Uint32Array(8);
    load_key_words(key, key_words);
    return hasher_init_base(self, key_words, KEYED_HASH);
};

function blake3_hasher_init_derive_key_raw(
    self: blake3_hasher, context: Uint8Array,
    context_len: number) {
    const context_hasher: blake3_hasher = {
        key: new Uint32Array(8),
        chunk: {
            cv: new Uint32Array(8),
            chunk_counter: BigInt(0),
            buf: new Uint8Array(BLAKE3_BLOCK_LEN),
            buf_len: BLAKE3_BLOCK_LEN,
            blocks_compressed: 0,
            flags: 0,
        },
        cv_stack_len: 0,
        cv_stack: new Uint8Array((BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN)
    };
    hasher_init_base(context_hasher, IV, DERIVE_KEY_CONTEXT);
    blake3_hasher_update(context_hasher, context, context_len);
    const context_key = new Uint8Array(BLAKE3_KEY_LEN);
    blake3_hasher_finalize(context_hasher, context_key, BLAKE3_KEY_LEN);
    const context_key_words = new Uint32Array(8);
    load_key_words(context_key, context_key_words);
    return hasher_init_base(self, context_key_words, DERIVE_KEY_MATERIAL);
};

function blake3_hasher_init_derive_key(self: blake3_hasher, context?: InputData) {
    context = context == undefined ? new Uint8Array() : formatMessage(context);
    blake3_hasher_init_derive_key_raw(self, context, context.length);
};

function hasher_merge_cv_stack(self: blake3_hasher, total_len: bigint) {
    var post_merge_stack_len = popcnt(total_len);
    while (self.cv_stack_len > post_merge_stack_len) {
        const parent_node = self.cv_stack.subarray((self.cv_stack_len - 2) * BLAKE3_OUT_LEN);
        const output = parent_output(parent_node, self.key, self.chunk.flags);
        output_chaining_value(output, parent_node);
        self.cv_stack_len -= 1;
    }
};

function hasher_push_cv(
    self: blake3_hasher, new_cv: Uint8Array /*uint8_t[BLAKE3_OUT_LEN]*/, chunk_counter: bigint
) {
    hasher_merge_cv_stack(self, chunk_counter);
    memcpy(
        self.cv_stack,
        new_cv,
        self.cv_stack_len * BLAKE3_OUT_LEN,
        0,
        BLAKE3_OUT_LEN
    );
    self.cv_stack_len += 1;
};

function blake3_hasher_update_base(self: blake3_hasher, input: Uint8Array,
    input_len: number) {
    // Explicitly checking for zero avoids causing UB by passing a null pointer
    // to memcpy. This comes up in practice with things like:
    //   std::vector<uint8_t> v;
    //   blake3_hasher_update(&hasher, v.data(), v.size());
    if (input_len == 0) {
        return;
    }

    var input_bytes = input;
    var inOff = 0;
    // If we have some partial chunk bytes in the internal chunk_state, we need
    // to finish that chunk first.
    if (chunk_state_len(self.chunk) > 0) {
        var take = BLAKE3_CHUNK_LEN - chunk_state_len(self.chunk);
        if (take > input_len) {
            take = input_len;
        }
        chunk_state_update(self.chunk, input_bytes, take, inOff);
        //input_bytes += take;
        inOff += take;
        input_len -= take;
        // If we've filled the current chunk and there's more coming, finalize this
        // chunk and proceed. In this case we know it's not the root.
        if (input_len > 0) {
            const output = chunk_state_output(self.chunk);
            const chunk_cv = new Uint8Array(32);
            output_chaining_value(output, chunk_cv);
            hasher_push_cv(self, chunk_cv, self.chunk.chunk_counter);
            chunk_state_reset(self.chunk, self.key, self.chunk.chunk_counter + BigInt(1));
        } else {
            return;
        }
    }

    // Now the chunk_state is clear, and we have more input. If there's more than
    // a single chunk (so, definitely not the root chunk), hash the largest whole
    // subtree we can, with the full benefits of SIMD (and maybe in the future,
    // multi-threading) parallelism. Two restrictions:
    // - The subtree has to be a power-of-2 number of chunks. Only subtrees along
    //   the right edge can be incomplete, and we don't know where the right edge
    //   is going to be until we get to finalize().
    // - The subtree must evenly divide the total number of chunks up until this
    //   point (if total is not 0). If the current incomplete subtree is only
    //   waiting for 1 more chunk, we can't hash a subtree of 4 chunks. We have
    //   to complete the current subtree first.
    // Because we might need to break up the input to form powers of 2, or to
    // evenly divide what we already have, this part runs in a loop.
    while (input_len > BLAKE3_CHUNK_LEN) {
        var subtree_len = round_down_to_power_of_2(input_len);
        var count_so_far = self.chunk.chunk_counter * BigInt(BLAKE3_CHUNK_LEN);
        // Shrink the subtree_len until it evenly divides the count so far. We know
        // that subtree_len itself is a power of 2, so we can use a bitmasking
        // trick instead of an actual remainder operation. (Note that if the caller
        // consistently passes power-of-2 inputs of the same size, as is hopefully
        // typical, this loop condition will always fail, and subtree_len will
        // always be the full length of the input.)
        //
        // An aside: We don't have to shrink subtree_len quite this much. For
        // example, if count_so_far is 1, we could pass 2 chunks to
        // compress_subtree_to_parent_node. Since we'll get 2 CVs back, we'll still
        // get the right answer in the end, and we might get to use 2-way SIMD
        // parallelism. The problem with this optimization, is that it gets us
        // stuck always hashing 2 chunks. The total number of chunks will remain
        // odd, and we'll never graduate to higher degrees of parallelism. See
        // https://github.com/BLAKE3-team/BLAKE3/issues/69.
        while ((BigInt((subtree_len - 1)) & count_so_far) != BigInt(0)) {
            subtree_len /= 2;
        }
        // The shrunken subtree_len might now be 1 chunk long. If so, hash that one
        // chunk by itself. Otherwise, compress the subtree into a pair of CVs.
        var subtree_chunks = BigInt(subtree_len / BLAKE3_CHUNK_LEN);
        if (subtree_len <= BLAKE3_CHUNK_LEN) {
            const chunk_state: blake3_chunk_state = {
                cv: new Uint32Array(8),
                chunk_counter: BigInt(0),
                buf: new Uint8Array(BLAKE3_BLOCK_LEN),
                buf_len: BLAKE3_BLOCK_LEN,
                blocks_compressed: 0,
                flags: 0,
            };
            chunk_state_init(chunk_state, self.key, self.chunk.flags);
            chunk_state.chunk_counter = self.chunk.chunk_counter;
            chunk_state_update(chunk_state, input_bytes, subtree_len, inOff);
            const output = chunk_state_output(chunk_state);
            const cv = new Uint8Array(BLAKE3_OUT_LEN);
            output_chaining_value(output, cv);
            hasher_push_cv(self, cv, chunk_state.chunk_counter);
        } else {
            // This is the high-performance happy path, though getting here depends
            // on the caller giving us a long enough input.
            const cv_pair = new Uint8Array(2 * BLAKE3_OUT_LEN);
            compress_subtree_to_parent_node(input_bytes, subtree_len, self.key,
                self.chunk.chunk_counter,
                self.chunk.flags, cv_pair, inOff);
            hasher_push_cv(self, cv_pair, self.chunk.chunk_counter);
            hasher_push_cv(self, cv_pair.subarray(BLAKE3_OUT_LEN),
                self.chunk.chunk_counter + (subtree_chunks / BigInt(2)));
        }
        self.chunk.chunk_counter += subtree_chunks;
        //input_bytes += subtree_len;
        inOff += subtree_len;
        input_len -= subtree_len;
    }

    // If there's any remaining input less than a full chunk, add it to the chunk
    // state. In that case, also do a final merge loop to make sure the subtree
    // stack doesn't contain any unmerged pairs. The remaining input means we
    // know these merges are non-root. This merge loop isn't strictly necessary
    // here, because hasher_push_chunk_cv already does its own merge loop, but it
    // simplifies blake3_hasher_finalize below.
    if (input_len > 0) {
        chunk_state_update(self.chunk, input_bytes, input_len, inOff);
        hasher_merge_cv_stack(self, self.chunk.chunk_counter);
    }
};

function blake3_hasher_update(self: blake3_hasher, input: Uint8Array, input_len: number) {
    blake3_hasher_update_base(self, input, input_len);
};

function blake3_hasher_finalize(self: blake3_hasher, out: Uint8Array, out_len: number) {
    blake3_hasher_finalize_seek(self, BigInt(0), out, out_len);
};

function blake3_hasher_finalize_seek(
    self: blake3_hasher, seek: bigint, out: Uint8Array, out_len: number
) {
    // Explicitly checking for zero avoids causing UB by passing a null pointer
    // to memcpy. This comes up in practice with things like:
    //   std::vector<uint8_t> v;
    //   blake3_hasher_finalize(&hasher, v.data(), v.size());
    if (out_len == 0) {
        return;
    }

    // If the subtree stack is empty, then the current chunk is the root.
    if (self.cv_stack_len == 0) {
        const output = chunk_state_output(self.chunk);
        output_root_bytes(output, seek, out, out_len);
        return;
    }
    // If there are any bytes in the chunk state, finalize that chunk and do a
    // roll-up merge between that chunk hash and every subtree in the stack. In
    // this case, the extra merge loop at the end of blake3_hasher_update
    // guarantees that none of the subtrees in the stack need to be merged with
    // each other first. Otherwise, if there are no bytes in the chunk state,
    // then the top of the stack is a chunk hash, and we start the merge from
    // that.
    var output: output_t = {
        input_cv: new Uint32Array(8),
        counter: BigInt(0),
        block: new Uint8Array(BLAKE3_BLOCK_LEN),
        block_len: 0,
        flags: 0,
    };
    var cvs_remaining;
    if (chunk_state_len(self.chunk) > 0) {
        cvs_remaining = self.cv_stack_len;
        output = chunk_state_output(self.chunk);
    } else {
        // There are always at least 2 CVs in the stack in this case.
        cvs_remaining = self.cv_stack_len - 2;
        output = parent_output(self.cv_stack.subarray(cvs_remaining * 32), self.key, self.chunk.flags);
    }

    while (cvs_remaining > 0) {
        cvs_remaining -= 1;
        const parent_block = new Uint8Array(BLAKE3_BLOCK_LEN);
        memcpy(parent_block, self.cv_stack.subarray(cvs_remaining * 32), 0, 0, 32);
        output_chaining_value(output, parent_block, 32);
        output = parent_output(parent_block, self.key, self.chunk.flags);
    }
    output_root_bytes(output, seek, out, out_len);
};

function blake3_hasher_reset(self: blake3_hasher) {
    chunk_state_reset(self.chunk, self.key, BigInt(0));
    self.cv_stack_len = 0;
};



function load_key_words(
  /*uint8_t[BLAKE3_KEY_LEN] 32*/ key: Uint8Array, key_words: Uint32Array // uint32_t[8]
) {
    key_words[0] = load32(key.subarray(0 * 4));
    key_words[1] = load32(key.subarray(1 * 4));
    key_words[2] = load32(key.subarray(2 * 4));
    key_words[3] = load32(key.subarray(3 * 4));
    key_words[4] = load32(key.subarray(4 * 4));
    key_words[5] = load32(key.subarray(5 * 4));
    key_words[6] = load32(key.subarray(6 * 4));
    key_words[7] = load32(key.subarray(7 * 4));
};

function store_cv_words(bytes_out: Uint8Array /*uint8_t[32]*/, cv_words: Uint32Array /*uint32_t[8]*/, dstOffset = 0, srcOffset = 0) {
    memcpy(bytes_out, cv_words, dstOffset, srcOffset, 32);
};

function blake3_compress_xof_portable(
    cv: Uint32Array /*uint32_t[8]*/, block: Uint8Array /*uint8_t[BLAKE3_BLOCK_LEN]*/, block_len: number,
    counter: bigint, flags: number, out: Uint8Array /*uint8_t[64]*/
) {
    const state = new Uint32Array(16);
    compress_pre(state, cv, block, block_len, counter, flags);

    store32(out.subarray(0 * 4), state[0] ^ state[8]);
    store32(out.subarray(1 * 4), state[1] ^ state[9]);
    store32(out.subarray(2 * 4), state[2] ^ state[10]);
    store32(out.subarray(3 * 4), state[3] ^ state[11]);
    store32(out.subarray(4 * 4), state[4] ^ state[12]);
    store32(out.subarray(5 * 4), state[5] ^ state[13]);
    store32(out.subarray(6 * 4), state[6] ^ state[14]);
    store32(out.subarray(7 * 4), state[7] ^ state[15]);
    store32(out.subarray(8 * 4), state[8] ^ cv[0]);
    store32(out.subarray(9 * 4), state[9] ^ cv[1]);
    store32(out.subarray(10 * 4), state[10] ^ cv[2]);
    store32(out.subarray(11 * 4), state[11] ^ cv[3]);
    store32(out.subarray(12 * 4), state[12] ^ cv[4]);
    store32(out.subarray(13 * 4), state[13] ^ cv[5]);
    store32(out.subarray(14 * 4), state[14] ^ cv[6]);
    store32(out.subarray(15 * 4), state[15] ^ cv[7]);
};

function blake3_compress_in_place_portable(
    cv: Uint32Array /*uint32_t[8]*/, block: Uint8Array /*uint8_t[BLAKE3_BLOCK_LEN]*/, block_len: number,
    counter: bigint, flags: number, block_offset: number
) {
    const state = new Uint32Array(16);
    compress_pre(state, cv, block, block_len, counter, flags, block_offset);

    //const state64 = uint64_t(state);
    //const cv64 = uint64_t(cv);
    cv[0] = state[0] ^ state[8];
    cv[1] = state[1] ^ state[9];
    cv[2] = state[2] ^ state[10];
    cv[3] = state[3] ^ state[11];
    cv[4] = state[4] ^ state[12];
    cv[5] = state[5] ^ state[13];
    cv[6] = state[6] ^ state[14];
    cv[7] = state[7] ^ state[15];
};

function left_len(content_len: number) {
    // Subtract 1 to reserve at least one byte for the right side. content_len
    // should always be greater than BLAKE3_CHUNK_LEN.
    var full_chunks = (content_len - 1) / BLAKE3_CHUNK_LEN;
    return round_down_to_power_of_2(full_chunks) * BLAKE3_CHUNK_LEN;
};

function hash_one_portable(
    input: Uint8Array, blocks: number, key: Uint32Array /*uint32_t[8]*/, counter: bigint,
    flags: number, flags_start: number, flags_end: number, out: Uint8Array, /*uint8_t[BLAKE3_OUT_LEN]*/
    input_offset = 0, output_offset = 0
) {
    const cv = new Uint32Array(8);
    memcpy(cv, key, 0, 0, BLAKE3_KEY_LEN);
    var block_flags = flags | flags_start;
    var inOff = input_offset;
    while (blocks > 0) {
        if (blocks == 1) {
            block_flags |= flags_end;
        }
        blake3_compress_in_place_portable(cv, input, BLAKE3_BLOCK_LEN, counter, block_flags, inOff);
        //input = &input[BLAKE3_BLOCK_LEN];
        inOff = input_offset + BLAKE3_BLOCK_LEN;
        blocks -= 1;
        block_flags = flags;
    }
    store_cv_words(out, cv, output_offset);
};

function blake3_hash_many_portable(
    inputs: Uint8Array, num_inputs: number, blocks: number, key: Uint32Array /*uint32_t[8]*/,
    counter: bigint, increment_counter: boolean, flags: number, flags_start: number,
    flags_end: number, out: Uint8Array
) {
    var outOff = 0;
    var inOff = 0;
    while (num_inputs > 0) {
        hash_one_portable(inputs, blocks, key, counter, flags, flags_start, flags_end, out, inOff, outOff);
        if (increment_counter) {
            counter += BigInt(1);
        }
        inOff += 1;
        //inputs += 1;
        num_inputs -= 1;
        outOff = BLAKE3_OUT_LEN;
        //out = &out[BLAKE3_OUT_LEN];
    }
};

function strToUint8Array(str: string): Uint8Array {
    // Check if the browser supports TextDecoder API
    try {
        const encoder = new TextEncoder();

        // Encode the string and return as a Uint8Array
        return encoder.encode(str);
    } catch (e) { }

    // Fallback for older systems without TextDecoder support
    let result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        const codePoint = str.charCodeAt(i);
        if (codePoint <= 255) {
            result[i] = codePoint;
        } else {
            result.set([codePoint >> 8, codePoint & 0xFF], i * 2);
        }
    }
    return result;
}

function formatMessage(message?: InputData): Uint8Array {
    if (message === undefined) {
        return new Uint8Array(0);
    }

    if (typeof message === 'string') {
        return strToUint8Array(message);
    }

    if (Buffer.isBuffer(message)) {
        return new Uint8Array(message);
    }

    if (message instanceof Uint8Array) {
        return message as Uint8Array;
    }

    throw new Error('input is invalid type');
}

var inited = false;

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

/**
 * Static class of all Blake3 functions
 */
export class Blake3 {
    key: InputData | undefined;
    hasher: blake3_hasher;
    constructor(key?: InputData, flags: number = 0) {
        if (!inited) {
            IV = new Uint32Array([
                0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
            ]);

            MSG_SCHEDULE = [
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
                new Uint8Array([2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]),
                new Uint8Array([3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1]),
                new Uint8Array([10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6]),
                new Uint8Array([12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4]),
                new Uint8Array([9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7]),
                new Uint8Array([11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13]),
            ];
            inited = true;
        }
        this.key = key;
        this.hasher = {
            key: new Uint32Array(8),
            chunk: {
                cv: new Uint32Array(8), //uint32_t[8]
                chunk_counter: BigInt(0),
                buf: new Uint8Array(BLAKE3_BLOCK_LEN), //uint8_t[BLAKE3_BLOCK_LEN]
                buf_len: BLAKE3_BLOCK_LEN,
                blocks_compressed: 0,
                flags: flags,
            },
            cv_stack_len: (BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN,
            // The stack size is MAX_DEPTH + 1 because we do lazy merging. For example,
            // with 7 chunks, we have 3 entries in the stack. Adding an 8th chunk
            // requires a 4th entry, rather than merging everything down to 1, because we
            // don't know whether more input is coming. This is different from how the
            // reference implementation does things.
            cv_stack: new Uint8Array((BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN), // uint8_t[(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN]
        };
    };

    init() {
        if (this.key) {
            this.key = formatMessage(this.key);
            if (this.key.length == 32) {
                blake3_hasher_init_keyed(this.hasher, this.key);
            } else {
                blake3_hasher_init(this.hasher);
            }
        } else {
            blake3_hasher_init(this.hasher);
        }
    };

    init_derive_key() {
        if (this.key) {
            this.key = formatMessage(this.key);
            blake3_hasher_init_derive_key(this.hasher, this.key);
        }
    }

    update(message?: InputData) {
        message = formatMessage(message);
        blake3_hasher_update(this.hasher, message, message.length);
    };

    final(digestBytes: number) {
        const out = new Uint8Array(digestBytes);
        blake3_hasher_finalize(this.hasher, out, digestBytes);
        return out;
    };
};

function bytesToHex(bytes: Uint8Array): string {
    for (var hex: string[] = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
};

/**
 * Creates a vary length BLAKE3 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} outLen - length of hash (default 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function BLAKE3(message: InputData, format: OutputFormat = arrayType(), outLen: number = BLAKE3_KEY_LEN) {
    message = formatMessage(message);
    const hash = new Blake3();
    hash.init();
    hash.update(message);
    const digestbytes = hash.final(outLen);
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

/**
 * Creates a vary length keyed BLAKE3 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} outLen - length of hash (default 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function BLAKE3_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType(), outLen: number = BLAKE3_KEY_LEN) {
    const hash = new Blake3(key);
    hash.init();
    hash.update(message);
    const digestbytes = hash.final(outLen);
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

/**
 * Creates a 32 byte BLAKE3 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData?} message - context salt
 * @param {InputData?} key - starting key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} outLen - length of hash (default 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function BLAKE3_DeriveKey(message?: InputData, key?: InputData, format: OutputFormat = arrayType(), outLen: number = BLAKE3_KEY_LEN) {
    const hash = new Blake3(key);
    hash.init_derive_key();
    hash.update(message);
    const digestbytes = hash.final(outLen);
    // Format output
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};